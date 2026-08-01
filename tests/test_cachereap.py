"""Tests for cachereap. Run: python3 -m unittest discover -s tests -v"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cachereap as cr  # noqa: E402


def cand(path, rule="r", tier="low", size=0, **kw):
    return cr.Candidate(path=Path(path), rule_id=rule, tier=tier, label="", regen="",
                        size=size, **kw)


def write(path: Path, mb: int = 1):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(b"\0" * (mb * 1024 * 1024))


class TestFormatting(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(cr.parse_size("0"), 0)
        self.assertEqual(cr.parse_size("512"), 512)
        self.assertEqual(cr.parse_size("10M"), 10 * 1024 ** 2)
        self.assertEqual(cr.parse_size("1.5G"), int(1.5 * 1024 ** 3))

    def test_human_roundtrip(self):
        self.assertEqual(cr.human(0), "0B")
        self.assertTrue(cr.human(1536).endswith("K"))
        self.assertTrue(cr.human(5 * 1024 ** 3).endswith("G"))


VECTORS = Path(__file__).resolve().parent / "guard_vectors.json"


def load_vectors():
    import json
    doc = json.loads(VECTORS.read_text())
    for case in doc["cases"]:
        yield case, case["path"].replace("$HOME", str(cr.HOME))


class TestPathGuards(unittest.TestCase):
    """Asserts against tests/guard_vectors.json, the same file the Rust GUI uses.

    A guard changed in one language and not the other fails here or in `cargo test`.
    """

    def test_shared_vectors(self):
        checked = 0
        for case, path in load_vectors():
            with self.subTest(path=case["path"], why=case["why"]):
                self.assertEqual(cr.path_is_protected(Path(path)), case["reason"])
            checked += 1
        self.assertGreaterEqual(checked, 35, "vector file looks truncated")

    def test_vectors_cover_both_outcomes(self):
        reasons = [case["reason"] for case, _ in load_vectors()]
        self.assertGreaterEqual(sum(1 for r in reasons if r), 20, "need blocked cases")
        self.assertGreaterEqual(sum(1 for r in reasons if not r), 10, "need allowed cases")

    def test_cloud_hint_matches_only_at_a_name_boundary(self):
        self.assertTrue(cr._looks_like_cloud_dir("OneDrive"))
        self.assertTrue(cr._looks_like_cloud_dir("OneDrive - Acme Corp"))
        self.assertTrue(cr._looks_like_cloud_dir("Google Drive"))
        self.assertFalse(cr._looks_like_cloud_dir("megaproject"))
        self.assertFalse(cr._looks_like_cloud_dir("boxes"))
        self.assertFalse(cr._looks_like_cloud_dir("dropboxer"))


class TestDeleteValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rejects_path_outside_allowed_roots(self):
        target = self.tmp / "a" / "node_modules"
        target.mkdir(parents=True)
        c = cand(target, rule="node-modules", tier="medium")
        self.assertEqual(cr.validate_for_delete(c, [cr.HOME]), "outside allowed roots")

    def test_accepts_path_inside_allowed_roots(self):
        target = self.tmp / "a" / "node_modules"
        target.mkdir(parents=True)
        c = cand(target, rule="node-modules", tier="medium")
        self.assertEqual(cr.validate_for_delete(c, [self.tmp]), "")

    def test_rejects_when_name_changed_since_scan(self):
        target = self.tmp / "a" / "src"
        target.mkdir(parents=True)
        c = cand(target, rule="node-modules", tier="medium", expect_name="node_modules")
        self.assertEqual(cr.validate_for_delete(c, [self.tmp]), "name changed since scan")

    def test_rejects_symlink(self):
        real = self.tmp / "real"
        real.mkdir()
        link = self.tmp / "a" / "node_modules"
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        c = cand(link, rule="node-modules", tier="medium")
        self.assertEqual(cr.validate_for_delete(c, [self.tmp]), "symlink")
        cr.delete([c], dry_run=False, allowed=[self.tmp])
        self.assertTrue(real.exists(), "symlink target must survive")

    def test_rejects_vanished_path(self):
        c = cand(self.tmp / "a" / "node_modules", rule="node-modules", tier="medium")
        self.assertEqual(cr.validate_for_delete(c, [self.tmp]), "already gone")


class TestOnDiskSize(unittest.TestCase):
    """Sizes must reflect blocks occupied, never logical length."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sparse_file_counts_as_the_space_it_occupies(self):
        # A sparse file behaves like an iCloud/Google Drive dataless placeholder:
        # huge st_size, ~zero st_blocks. Counting st_size inflated a real
        # ~/Library measurement from 29.9G to 704G.
        placeholder = self.tmp / "placeholder.bin"
        with placeholder.open("wb") as fh:
            fh.truncate(4 * 1024 ** 3)
        write(self.tmp / "real.bin", 1)

        size, _, files = cr.dir_stats(self.tmp)
        self.assertEqual(files, 2)
        # real.bin alone is 1 MiB; if the 4 GiB placeholder were counted this
        # would be over 4_000_000_000 rather than a little over 1 MiB.
        self.assertLess(size, 4 * 1024 ** 2, "sparse file counted at its logical size")

    def test_empty_file_is_zero_not_fallback(self):
        (self.tmp / "empty").touch()
        size, _, files = cr.dir_stats(self.tmp)
        self.assertEqual(files, 1)
        self.assertEqual(size, 0)

    def test_real_bytes_are_still_counted(self):
        write(self.tmp / "solid.bin", 4)
        size, _, _ = cr.dir_stats(self.tmp)
        self.assertGreaterEqual(size, 4 * 1024 ** 2)
        self.assertLess(size, 8 * 1024 ** 2)


class TestDedupe(unittest.TestCase):
    def test_drops_nested_candidates(self):
        kept = cr.dedupe_nested([cand("/a"), cand("/a/c"), cand("/a/c/d"), cand("/b/x")])
        self.assertEqual([str(k.path) for k in kept], ["/a", "/b/x"])

    def test_sibling_prefix_is_not_treated_as_child(self):
        # "/a-b" sorts between "/a" and "/a/c" as a plain string; it must survive
        kept = cr.dedupe_nested([cand("/a"), cand("/a-b"), cand("/a/c"), cand("/b/x")])
        self.assertEqual([str(k.path) for k in kept], ["/a", "/a-b", "/b/x"])


class TestSelection(unittest.TestCase):
    def setUp(self):
        self.groups = cr.group_by_rule([
            cand("/h/a", rule="low1", tier="low", size=10),
            cand("/h/b", rule="low1", tier="low", size=20),
            cand("/h/c", rule="med1", tier="medium", size=30),
            cand("/h/d", rule="high1", tier="high", size=40),
        ])

    def test_preselects_low_tier_only(self):
        self.assertEqual(cr._preselect(self.groups), {"/h/a", "/h/b"})

    def test_group_state_transitions(self):
        sel = cr._preselect(self.groups)
        low = next(g for g in self.groups if g["id"] == "low1")
        self.assertEqual(cr._group_state(low, sel), "all")
        cr._toggle_group(low, sel)
        self.assertEqual(cr._group_state(low, sel), "none")
        sel.add("/h/a")
        self.assertEqual(cr._group_state(low, sel), "some")

    def test_rows_expand_and_filter(self):
        rows = cr._build_rows(self.groups, {"low1"}, "")
        self.assertEqual([k for k, _, _ in rows], ["group", "item", "item", "group", "group"])
        rows = cr._build_rows(self.groups, set(), "med")
        self.assertEqual([g["id"] for _, g, _ in rows], ["med1"])


class TestArtifactDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.proj = self.tmp / "demo"
        self.proj.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self):
        return {c.rule_id: c for c in cr.discover_projects([self.tmp], 10, None)}

    def test_target_requires_cargo_or_pom(self):
        write(self.proj / "target" / "blob")
        self.assertNotIn("rust-target", self.scan())
        (self.proj / "Cargo.toml").touch()
        self.assertIn("rust-target", self.scan())

    def test_venv_requires_pyvenv_cfg(self):
        write(self.proj / ".venv" / "blob")
        self.assertNotIn("venv", self.scan())
        (self.proj / ".venv" / "pyvenv.cfg").touch()
        self.assertIn("venv", self.scan())

    def test_node_modules_claimed_and_not_descended(self):
        write(self.proj / "node_modules" / "pkg" / "node_modules" / "inner" / "blob")
        found = [c for c in cr.discover_projects([self.tmp], 10, None)
                 if c.rule_id == "node-modules"]
        self.assertEqual(len(found), 1, "must not descend into a claimed artifact")

    def test_source_dirs_are_never_claimed(self):
        write(self.proj / "src" / "main.rs")
        write(self.proj / "lib" / "thing.py")
        self.assertEqual(self.scan(), {})


@unittest.skipUnless(shutil.which("git"), "git not installed")
class TestGitignoreGating(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.proj = self.tmp / "demo"
        self.proj.mkdir()
        subprocess.run(["git", "init", "-q", str(self.proj)], check=True)
        (self.proj / ".gitignore").write_text("dist/\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ignored_dist_is_claimed_but_tracked_build_is_not(self):
        write(self.proj / "dist" / "blob")
        write(self.proj / "build" / "blob")
        ids = {c.rule_id for c in cr.discover_projects([self.tmp], 10, None)}
        self.assertIn("dist-dir", ids)
        self.assertNotIn("build-dir", ids, "a non-ignored build/ may be source")

    def test_build_outside_any_repo_is_not_claimed(self):
        loose = self.tmp / "loose"
        write(loose / "dist" / "blob")
        ids = {c.rule_id for c in cr.discover_projects([loose], 10, None)}
        self.assertNotIn("dist-dir", ids)


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.proj = self.tmp / "demo"
        (self.proj / "src").mkdir(parents=True)
        (self.proj / "Cargo.toml").touch()
        (self.proj / "package.json").touch()
        (self.proj / "src" / "main.rs").touch()
        write(self.proj / "target" / "debug" / "blob", 4)
        write(self.proj / "node_modules" / "pkg" / "blob", 2)
        write(self.proj / ".venv" / "blob", 1)
        (self.proj / ".venv" / "pyvenv.cfg").touch()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_measure_and_delete(self):
        cands = cr.dedupe_nested(cr.discover_projects([self.tmp], 10, None))
        cr.measure(cands, None)
        by_rule = {c.rule_id: c for c in cands}
        self.assertEqual(set(by_rule), {"rust-target", "node-modules", "venv"})
        self.assertGreater(by_rule["rust-target"].size, 3 * 1024 ** 2)
        self.assertEqual(by_rule["rust-target"].tier, "low")
        self.assertEqual(by_rule["venv"].tier, "medium")

        selected = [by_rule["rust-target"], by_rule["node-modules"]]
        freed, removed, errors = cr.delete(selected, dry_run=False, allowed=[self.tmp])

        self.assertEqual(removed, 2)
        self.assertEqual(errors, [])
        self.assertGreater(freed, 5 * 1024 ** 2)
        self.assertFalse((self.proj / "target").exists())
        self.assertFalse((self.proj / "node_modules").exists())
        self.assertTrue((self.proj / ".venv").exists(), "unselected item must survive")
        self.assertTrue((self.proj / "src" / "main.rs").exists(), "source must survive")
        self.assertTrue((self.proj / "Cargo.toml").exists())

    def test_dry_run_deletes_nothing(self):
        cands = cr.dedupe_nested(cr.discover_projects([self.tmp], 10, None))
        cr.measure(cands, None)
        freed, removed, _ = cr.delete(cands, dry_run=True, allowed=[self.tmp])
        self.assertEqual(removed, len(cands))
        self.assertGreater(freed, 0)
        self.assertTrue((self.proj / "target").exists())
        self.assertTrue((self.proj / "node_modules").exists())

    def test_delete_writes_a_log(self):
        import json
        cands = cr.dedupe_nested(cr.discover_projects([self.tmp], 10, None))
        cr.measure(cands, None)
        victim = cands[0]
        cr.delete([victim], dry_run=False, allowed=[self.tmp])

        logs = sorted(cr.LOG_DIR.glob("reap-*.jsonl"))
        self.assertTrue(logs, "a deletion must leave an audit log")
        entries = [json.loads(line) for line in logs[-1].read_text().splitlines() if line]
        match = [e for e in entries if e["path"] == str(victim.path)]
        self.assertEqual(len(match), 1, "the deleted path must appear exactly once")
        self.assertEqual(match[0]["rule"], victim.rule_id)
        self.assertIn("regen", match[0])


class TestStaticRuleSanity(unittest.TestCase):
    def test_every_rule_has_tier_label_and_regen(self):
        for rule in cr.STATIC_RULES:
            self.assertIn(rule.tier, cr.TIER_ORDER, rule.id)
            self.assertTrue(rule.label, rule.id)
            self.assertTrue(rule.regen, rule.id)
        for name, rules in cr.ARTIFACT_RULES.items():
            for rule in rules:
                self.assertIn(rule.tier, cr.TIER_ORDER, name)
                self.assertTrue(rule.label, name)
                self.assertTrue(rule.regen, name)

    def test_ambiguous_names_are_gated(self):
        for name in ("build", "dist", "out", "obj"):
            for rule in cr.ARTIFACT_RULES[name]:
                self.assertTrue(rule.need_gitignored, f"{name}/ must be gitignore-gated")

    def test_no_rule_targets_a_protected_path(self):
        for rule in cr.STATIC_RULES:
            base = Path("/") if rule.glob.startswith("/") else cr.HOME
            probe = base / rule.glob.lstrip("/")
            self.assertEqual(cr.path_is_protected(probe), "", rule.id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
