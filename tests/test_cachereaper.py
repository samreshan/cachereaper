"""Tests for cachereaper. Run: python3 -m unittest discover -s tests -v"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cachereaper as cr  # noqa: E402


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

    def test_rejects_reference_descendants_and_ancestor_deletion(self):
        reference = self.tmp / "archive"
        target = reference / "project" / "node_modules"
        target.mkdir(parents=True)
        child = cand(target, rule="node-modules", tier="medium")
        self.assertIn(
            "reference root is immutable",
            cr.validate_for_delete(child, [self.tmp], [reference]),
        )
        parent = cand(self.tmp, rule="node-modules", tier="medium", expect_name=self.tmp.name)
        self.assertIn(
            "reference root is immutable",
            cr.validate_for_delete(parent, [self.tmp], [reference]),
        )

    @unittest.skipIf(os.name == "nt", "creating symlinks may require Windows developer mode")
    def test_reference_matching_resolves_a_missing_leaf_through_symlink_parent(self):
        reference = self.tmp / "masters"
        reference.mkdir()
        alias = self.tmp / "ordinary"
        alias.symlink_to(reference, target_is_directory=True)
        self.assertEqual(
            cr.matching_reference_root(alias / "future.raw", [reference]),
            reference,
        )


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
        self.old_log_dir = cr.LOG_DIR
        cr.LOG_DIR = self.tmp / ".cachereaper"
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
        cr.LOG_DIR = self.old_log_dir
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
        self.assertFalse(list(cr.LOG_DIR.glob("*.jsonl")), "dry runs must not create history")

    def test_delete_writes_a_log(self):
        import json
        cands = cr.dedupe_nested(cr.discover_projects([self.tmp], 10, None))
        cr.measure(cands, None)
        victim = cands[0]
        cr.delete([victim], dry_run=False, allowed=[self.tmp])

        logs = sorted(cr.LOG_DIR.glob("receipt-*.jsonl"))
        self.assertTrue(logs, "a deletion must leave an audit log")
        entries = [json.loads(line) for line in logs[-1].read_text().splitlines() if line]
        match = [e for e in entries if e.get("kind") == "item" and e["path"] == str(victim.path)]
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


class TestNewStaticRules(unittest.TestCase):
    def rule(self, rule_id):
        return next(r for r in cr.STATIC_RULES if r.id == rule_id)

    def test_system_simulator_dyld_cache(self):
        rule = self.rule("simulator-dyld")
        self.assertEqual(rule.glob, "/Library/Developer/CoreSimulator/Caches/dyld")
        self.assertEqual((rule.tier, rule.system, rule.os), ("low", True, "macos"))

    def test_google_updater_crx_cache(self):
        rule = self.rule("google-updater-crx")
        self.assertEqual((rule.tier, rule.system, rule.os), ("low", False, "macos"))
        self.assertTrue(rule.glob.endswith("GoogleUpdater/crx_cache"))

    def test_static_globs_only_use_whole_component_wildcards(self):
        # The GUI's glob expander only understands `*` as an entire component;
        # `claude-*` would be looked up literally there and silently find nothing.
        for rule in cr.STATIC_RULES:
            for part in rule.glob.split("/"):
                if "*" in part or "?" in part or "[" in part:
                    self.assertEqual(part, "*", rule.id)

    def test_simulator_runtime_is_a_vendor_command_not_a_rule(self):
        commands = " ".join(cmd for _, cmd, _ in cr.TOOL_COMMANDS)
        self.assertIn("xcrun simctl runtime delete", commands)
        for rule in cr.STATIC_RULES:
            self.assertNotIn("AssetsV2", rule.glob, "SIP-protected; rm cannot remove it")

    def test_onedrive_cache_stays_behind_the_cloud_guard(self):
        cdn = cr.HOME / "Library/Application Support/OneDrive/settings/ListSync/cdn"
        self.assertIn("cloud-sync", cr.path_is_protected(cdn))
        for rule in cr.STATIC_RULES:
            self.assertNotIn("OneDrive", rule.glob, rule.id)


class ProvenRuleCase(unittest.TestCase):
    """A temporary HOME and log dir, so nothing here sees the real machine."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.saved = {name: getattr(cr, name) for name in
                      ("HOME", "LOG_DIR", "CLAUDE_TMP_BASE", "APPLICATIONS", "ADOBE_SUPPORT")}
        cr.HOME = self.home
        cr.LOG_DIR = self.tmp / ".cachereaper"
        # every finder runs on each discover_proven call; none may see the real machine
        cr.CLAUDE_TMP_BASE = self.tmp / "private-tmp"
        cr.APPLICATIONS = self.tmp / "Applications"
        cr.ADOBE_SUPPORT = self.tmp / "Library" / "Application Support" / "Adobe"

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(cr, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def found(self, rule_id, include_system=False):
        return {c.path for c in cr.discover_proven(include_system) if c.rule_id == rule_id}

    def validate(self, path, rule_id):
        rule = cr.PROVEN_BY_ID[rule_id]
        c = cr.Candidate(path=path, rule_id=rule.id, tier=rule.tier, label=rule.label,
                         regen=rule.regen, source="proven")
        return cr.validate_for_delete(c, [self.tmp]), c


class TestObsoleteEditorExtensions(ProvenRuleCase):
    def setUp(self):
        super().setUp()
        self.ext = self.home / ".vscode" / "extensions"
        for name in ("pub.a-1.0.0", "pub.a-1.1.0", "pub.b-2.0.0-darwin-arm64", "pub.c-0.9.0"):
            write(self.ext / name / "package.json", 0)
        (self.ext / ".obsolete").write_text(json.dumps({
            "pub.a-1.0.0": True,
            "pub.b-2.0.0-darwin-arm64": True,   # reinstalled since: extensions.json has it
            "pub.gone-0.1.0": True,             # already deleted by VS Code
            "../escape": True,
        }))
        self.write_installed("pub.a-1.1.0", "pub.b-2.0.0-darwin-arm64", "pub.c-0.9.0")

    def write_installed(self, *names):
        (self.ext / "extensions.json").write_text(json.dumps(
            [{"identifier": {"id": n.rsplit("-", 1)[0]}, "relativeLocation": n} for n in names]))

    def test_claims_only_entries_named_in_obsolete_and_not_installed(self):
        self.assertEqual(self.found("vscode-obsolete-ext"), {self.ext / "pub.a-1.0.0"})

    def test_older_looking_versions_are_not_inferred(self):
        # pub.c-0.9.0 is older than everything here and still is not claimed
        self.assertNotIn(self.ext / "pub.c-0.9.0", self.found("vscode-obsolete-ext"))

    def test_without_extensions_json_nothing_is_claimed(self):
        (self.ext / "extensions.json").unlink()
        self.assertEqual(self.found("vscode-obsolete-ext"), set())

    def test_malformed_obsolete_claims_nothing(self):
        (self.ext / ".obsolete").write_text("{not json")
        self.assertEqual(self.found("vscode-obsolete-ext"), set())

    def test_reinstall_after_scan_blocks_delete(self):
        target = self.ext / "pub.a-1.0.0"
        self.assertEqual(self.validate(target, "vscode-obsolete-ext")[0], "")
        self.write_installed("pub.a-1.0.0", "pub.a-1.1.0")
        why, c = self.validate(target, "vscode-obsolete-ext")
        self.assertIn("no longer proven", why)
        cr.delete([c], dry_run=False, allowed=[self.tmp])
        self.assertTrue(target.exists())

    def test_delete_keeps_the_current_version(self):
        cands = cr.discover_proven(False)
        _, removed, errors = cr.delete(cands, dry_run=False, allowed=[self.tmp])
        self.assertEqual((removed, errors), (1, []))
        self.assertFalse((self.ext / "pub.a-1.0.0").exists())
        self.assertTrue((self.ext / "pub.a-1.1.0" / "package.json").exists())


@unittest.skipUnless(cr.PLATFORM == "macos", "the rule is only verified against macOS")
class TestClaudeSessionTemp(ProvenRuleCase):
    SESSION = "6b217802-85e8-4bac-9408-2790915c0050"

    def setUp(self):
        super().setUp()
        self.root = cr.CLAUDE_TMP_BASE / f"claude-{os.getuid()}"
        self.project = self.root / "-Users-someone-Programming-demo"
        self.stale = self.project / self.SESSION
        self.live = self.project / "26cdb326-4424-4cf3-ba0d-cd41bc0bc564"
        self.other = self.root / "bash-edit-diff" / "1234-5678-abcd"
        write(self.stale / "tasks" / "b1.output")
        write(self.stale / "scratchpad" / "notes.txt", 0)
        write(self.live / "tasks" / "b2.output")
        write(self.other / "blob")
        write(self.root / f"cache-break-state-{self.SESSION}.json", 0)
        for path in (self.stale, self.other, self.root / f"cache-break-state-{self.SESSION}.json"):
            self.age(path, days=cr.CLAUDE_TMP_STALE_DAYS + 1)

    @staticmethod
    def age(path, days):
        old = time.time() - days * 86400
        if path.is_file():
            os.utime(path, (old, old))
            return
        for dirpath, dirnames, filenames in os.walk(path, topdown=False):
            for name in filenames + dirnames:
                os.utime(os.path.join(dirpath, name), (old, old))
            os.utime(dirpath, (old, old))

    def test_claims_only_stale_session_folders(self):
        self.assertEqual(self.found("claude-code-tmp"), {self.stale})

    def test_a_recent_write_anywhere_inside_protects_the_session(self):
        (self.stale / "tasks" / "b1.output").write_text("still running")
        self.assertEqual(self.found("claude-code-tmp"), set())

    def test_a_symlinked_root_is_not_followed(self):
        # /tmp is shared: a claude-<uid> planted by someone else, pointing into
        # your files, must not turn them into candidates
        shutil.rmtree(self.root)
        self.root.symlink_to(self.home, target_is_directory=True)
        victim = self.home / "proj" / self.SESSION
        write(victim / "thesis.tex")
        self.age(victim, days=30)
        self.assertEqual(self.found("claude-code-tmp"), set())

    def test_temp_root_is_an_allowed_delete_root(self):
        args = cr.build_parser().parse_args(["clean", "--tier", "medium"])
        self.assertIn(self.root, cr.allowed_roots_for(args))
        c = next(c for c in cr.discover_proven(False) if c.rule_id == "claude-code-tmp")
        self.assertEqual(cr.validate_for_delete(c, cr.allowed_roots_for(args)), "")

    def test_session_woken_after_scan_is_skipped_at_delete(self):
        c = next(c for c in cr.discover_proven(False) if c.rule_id == "claude-code-tmp")
        (self.stale / "tasks" / "b3.output").write_text("resumed")
        _, removed, errors = cr.delete([c], dry_run=False, allowed=[self.tmp])
        self.assertEqual(removed, 0)
        self.assertIn("no longer proven", errors[0])
        self.assertTrue(self.stale.exists())


@unittest.skipUnless(shutil.which("git"), "git not installed")
class TestCodexWorktrees(ProvenRuleCase):
    def git(self, cwd, *args):
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
             "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
             "-c", "init.defaultBranch=main", "-C", str(cwd), *args],
            check=True, capture_output=True,
        )

    def setUp(self):
        super().setUp()
        self.origin = self.tmp / "origin.git"
        self.main = self.tmp / "repo"
        self.git(self.tmp, "init", "-q", "--bare", str(self.origin))
        self.git(self.tmp, "init", "-q", str(self.main))
        (self.main / "app.py").write_text("print('hi')\n")
        (self.main / ".gitignore").write_text("node_modules/\n")
        self.git(self.main, "add", ".")
        self.git(self.main, "commit", "-q", "-m", "init")
        self.git(self.main, "remote", "add", "origin", str(self.origin))
        self.git(self.main, "push", "-q", "origin", "HEAD:refs/heads/main")
        self.git(self.main, "fetch", "-q", "origin")
        self.wt = self.home / ".codex" / "worktrees" / "02fc" / "repo"
        self.git(self.main, "worktree", "add", "-q", "--detach", str(self.wt))
        write(self.wt / "node_modules" / "pkg" / "blob")

    def test_clean_pushed_worktree_is_claimed(self):
        self.assertEqual(self.found("codex-worktree"), {self.wt})
        self.assertEqual(cr.PROVEN_BY_ID["codex-worktree"].tier, "high")

    def test_untracked_file_blocks_the_claim(self):
        (self.wt / "draft.md").write_text("not committed")
        self.assertEqual(self.found("codex-worktree"), set())

    def test_modified_tracked_file_blocks_the_claim(self):
        (self.wt / "app.py").write_text("print('changed')\n")
        self.assertEqual(self.found("codex-worktree"), set())

    def test_unpushed_commit_blocks_the_claim(self):
        (self.wt / "new.py").write_text("x = 1\n")
        self.git(self.wt, "add", "new.py")
        self.git(self.wt, "commit", "-q", "-m", "local only")
        self.assertEqual(self.found("codex-worktree"), set())

    def test_repo_without_a_remote_never_qualifies(self):
        self.git(self.main, "remote", "remove", "origin")
        self.assertEqual(self.found("codex-worktree"), set())

    def test_a_full_clone_is_not_a_worktree(self):
        clone = self.home / ".codex" / "worktrees" / "9308" / "clone"
        clone.parent.mkdir(parents=True)
        self.git(self.tmp, "clone", "-q", str(self.origin), str(clone))
        self.assertNotIn(clone, self.found("codex-worktree"))

    def test_removal_goes_through_git_worktree_remove(self):
        cands = [c for c in cr.discover_proven(False) if c.rule_id == "codex-worktree"]
        _, removed, errors = cr.delete(cands, dry_run=False, allowed=[self.tmp])
        self.assertEqual((removed, errors), (1, []))
        self.assertFalse(self.wt.exists())
        listed = subprocess.run(["git", "-C", str(self.main), "worktree", "list", "--porcelain"],
                                capture_output=True, text=True, check=True).stdout
        self.assertNotIn("02fc", listed, "rm would leave the main repo listing a missing worktree")
        self.assertTrue((self.main / "app.py").exists())

    def test_edit_after_scan_is_refused_at_delete(self):
        cands = [c for c in cr.discover_proven(False) if c.rule_id == "codex-worktree"]
        (self.wt / "app.py").write_text("print('late edit')\n")
        _, removed, errors = cr.delete(cands, dry_run=False, allowed=[self.tmp])
        self.assertEqual(removed, 0)
        self.assertIn("no longer proven", errors[0])
        self.assertEqual((self.wt / "app.py").read_text(), "print('late edit')\n")


@unittest.skipUnless(cr.PLATFORM == "macos", "Adobe leftovers are a macOS rule")
class TestOrphanedAdobeFolders(ProvenRuleCase):
    def setUp(self):
        super().setUp()
        self.app("Adobe Illustrator 2025", "Adobe Illustrator.app", "29.0.1")
        self.app("Adobe Photoshop 2023", "Adobe Photoshop 2023.app", "24.0.0")
        for name in ("Adobe Illustrator 28", "Adobe Illustrator 29", "Adobe Photoshop 2023",
                     "Adobe Photoshop 2024", "Adobe InDesign 2020", "CEP", "SLStore",
                     "backup20240808T183841", "Adobe Desktop Common"):
            write(cr.ADOBE_SUPPORT / name / "blob", 0)

    def app(self, folder, bundle, version):
        import plistlib
        plist = cr.APPLICATIONS / folder / bundle / "Contents" / "Info.plist"
        plist.parent.mkdir(parents=True)
        with plist.open("wb") as fh:
            plistlib.dump({"CFBundleShortVersionString": version}, fh)

    def test_claims_versions_whose_app_is_gone_under_either_naming(self):
        self.assertEqual(self.found("adobe-orphaned", include_system=True), {
            cr.ADOBE_SUPPORT / "Adobe Illustrator 28",   # by major version: 29 is installed
            cr.ADOBE_SUPPORT / "Adobe Photoshop 2024",   # by year: 2023 is installed
        })

    def test_only_with_system_scope(self):
        self.assertEqual(self.found("adobe-orphaned", include_system=False), set())

    def test_naming_is_not_assumed_without_a_matching_sibling(self):
        # With no folder for the installed Illustrator 29, nothing proves that
        # Illustrator names its folders by major version.
        shutil.rmtree(cr.ADOBE_SUPPORT / "Adobe Illustrator 29")
        self.assertNotIn(cr.ADOBE_SUPPORT / "Adobe Illustrator 28",
                         self.found("adobe-orphaned", include_system=True))

    def test_product_not_installed_at_all_is_left_alone(self):
        self.assertNotIn(cr.ADOBE_SUPPORT / "Adobe InDesign 2020",
                         self.found("adobe-orphaned", include_system=True))

    def test_reinstalling_the_version_blocks_delete(self):
        target = cr.ADOBE_SUPPORT / "Adobe Illustrator 28"
        self.assertEqual(self.validate(target, "adobe-orphaned")[0], "")
        self.app("Adobe Illustrator 2024", "Adobe Illustrator.app", "28.7.1")
        self.assertIn("no longer proven", self.validate(target, "adobe-orphaned")[0])


class TestBragIntermediates(ProvenRuleCase):
    def setUp(self):
        super().setUp()
        self.out = self.home / "proj" / "brag-output-2026-09-26-221544"
        write(self.out / "brag-plan.md", 0)
        write(self.out / "share-copy.txt", 0)
        write(self.out / "launch.mp4")
        write(self.out / "work" / "frames" / "0001.png")
        write(self.out / "work" / "master_crf17.mp4")

    def scan(self):
        return {c.path: c for c in cr.discover_projects([self.home], 10, None)
                if c.rule_id == "brag-work"}

    def test_claims_work_and_never_the_finished_video(self):
        self.assertEqual(set(self.scan()), {self.out / "work"})
        _, removed, errors = cr.delete(list(self.scan().values()), dry_run=False,
                                       allowed=[self.tmp])
        self.assertEqual((removed, errors), (1, []))
        self.assertFalse((self.out / "work").exists())
        for kept in ("launch.mp4", "brag-plan.md", "share-copy.txt"):
            self.assertTrue((self.out / kept).exists(), kept)

    def test_unfinished_render_is_not_claimed(self):
        (self.out / "launch.mp4").unlink()
        self.assertEqual(self.scan(), {})

    def test_work_needs_a_brag_output_parent_and_plan(self):
        other = self.home / "proj" / "notes"
        write(other / "brag-plan.md", 0)
        write(other / "talk.mp4")
        write(other / "work" / "draft.txt")
        (self.out / "brag-plan.md").unlink()
        self.assertEqual(self.scan(), {})


class TestProvenRulesStayOutOfTheGui(unittest.TestCase):
    def test_proven_rules_are_listed_apart_from_globs_and_markers(self):
        doc = cr.rules_document()
        self.assertEqual(doc["schema"], 2, "the GUI asserts the schema number")
        proven = {r["id"] for r in doc["proven"]}
        self.assertEqual(proven, set(cr.PROVEN_BY_ID))
        # the GUI applies these lists with nothing but a glob or a marker
        self.assertFalse(proven & {r["id"] for r in doc["static"]})
        self.assertFalse(proven & {r["id"] for r in doc["artifacts"]})
        for rule in doc["proven"]:
            self.assertTrue(rule["proof"], rule["id"])

    def test_every_proven_rule_can_prove_and_be_found(self):
        for rule in cr.PROVEN_RULES:
            self.assertIn(rule.tier, cr.TIER_ORDER, rule.id)
            self.assertTrue(rule.label and rule.regen and rule.proof, rule.id)
            self.assertTrue(callable(rule.prove), rule.id)
            self.assertTrue(callable(rule.find) or rule.dir_name, rule.id)

    def test_generated_copy_is_current(self):
        committed = Path(__file__).resolve().parent.parent / "gui" / "rules.generated.json"
        self.assertEqual(json.loads(committed.read_text(encoding="utf-8")), cr.rules_document(),
                         "run: python3 cachereaper.py dump-rules > gui/rules.generated.json")


class TestSavedExclusions(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.old_log_dir = cr.LOG_DIR
        cr.LOG_DIR = self.tmp / ".cachereaper"
        cr.LOG_DIR.mkdir()
        self.root = self.tmp / "work"
        write(self.root / "keep" / "node_modules" / "blob")
        write(self.root / "skip" / "node_modules" / "blob")

    def tearDown(self):
        cr.LOG_DIR = self.old_log_dir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def args(self, *extra):
        return cr.build_parser().parse_args([
            "scan", "--no-static", "--tier", "high", "--roots", str(self.root), *extra
        ])

    def test_global_and_session_path_exclusions_are_combined(self):
        (cr.LOG_DIR / "config.json").write_text(json.dumps({
            "global_excluded_paths": [str(self.root / "skip")],
        }))
        args = self.args("--exclude-path", str(self.root / "keep"))
        cr.apply_saved_scan_settings(args)
        self.assertEqual(cr.collect(args), [])

    def test_profile_resolves_root_and_rule_exclusions(self):
        (cr.LOG_DIR / "config.json").write_text(json.dumps({
            "global_excluded_rules": [],
            "profiles": [{"id": "p1", "name": "Work", "root": str(self.root),
                          "excluded_paths": [], "excluded_rules": ["node-modules"]}],
        }))
        args = cr.build_parser().parse_args(["scan", "--no-static", "--tier", "high", "--profile", "work"])
        cr.apply_saved_scan_settings(args)
        self.assertEqual(args.roots, [str(self.root)])
        self.assertEqual(cr.collect(args), [])

    def test_ignore_saved_exclusions_keeps_profile_root(self):
        (cr.LOG_DIR / "config.json").write_text(json.dumps({
            "reference_roots": [str(self.root / "keep")],
            "profiles": [{"id": "p1", "name": "Work", "root": str(self.root),
                          "excluded_paths": [str(self.root)], "excluded_rules": ["node-modules"]}],
        }))
        args = cr.build_parser().parse_args([
            "scan", "--no-static", "--tier", "high", "--profile", "p1", "--ignore-saved-exclusions"
        ])
        cr.apply_saved_scan_settings(args)
        self.assertEqual(len(cr.collect(args)), 2)
        self.assertEqual(args.reference_roots, [self.root / "keep"],
                         "ignore exclusions must never disable safety boundaries")

    def test_profile_and_roots_conflict(self):
        with self.assertRaises(SystemExit):
            cr.build_parser().parse_args(["scan", "--profile", "p1", "--roots", str(self.root)])

    def test_malformed_config_warns_and_falls_back(self):
        import contextlib
        import io
        (cr.LOG_DIR / "config.json").write_text("{broken")
        error = io.StringIO()
        args = self.args()
        with contextlib.redirect_stderr(error):
            cr.apply_saved_scan_settings(args)
        self.assertIn("ignoring malformed config", error.getvalue())
        self.assertEqual(len(cr.collect(args)), 2)

class TestUpdate(unittest.TestCase):
    """The update path, minus the network. Nothing here reaches GitHub: the two
    functions that do are the thin ends, and everything that decides whether a
    download is allowed to overwrite a working program is tested here."""

    def test_versions_compare_as_numbers_not_strings(self):
        self.assertGreater(cr.version_tuple("1.10.0"), cr.version_tuple("1.9.0"))
        self.assertGreater(cr.version_tuple("2.0.0"), cr.version_tuple("1.99.99"))
        self.assertEqual(cr.version_tuple("v1.4.0"), cr.version_tuple("1.4.0"))

    def test_a_prerelease_is_not_behind_the_release_it_precedes(self):
        # Otherwise an rc offers to "update" itself to the version it already is.
        self.assertEqual(cr.version_tuple("1.5.0-rc1"), cr.version_tuple("1.5.0"))

    def test_odd_versions_do_not_raise(self):
        self.assertEqual(cr.version_tuple("1.4"), (1, 4))
        self.assertEqual(cr.version_tuple("what"), (0,))

    def test_the_shipped_file_passes_its_own_download_check(self):
        source = Path(cr.__file__).read_text(encoding="utf-8")
        cr.check_downloaded(source, f"v{cr.VERSION}")

    def test_a_download_that_is_not_the_program_is_refused(self):
        real = Path(cr.__file__).read_text(encoding="utf-8")
        tag = f"v{cr.VERSION}"
        cases = {
            "an error page": "<html><body>404</body></html>",
            "a truncated file": real[:5000],
            "the wrong version": real.replace(f'VERSION = "{cr.VERSION}"', 'VERSION = "0.0.1"'),
            "mangled syntax": real.replace("def main(", "def main("[:-1] + "(("),
        }
        for why, payload in cases.items():
            with self.subTest(why):
                with self.assertRaises(Exception):
                    cr.check_downloaded(payload, tag)

    def test_replacing_keeps_the_mode_and_leaves_no_scratch_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "cachereaper"
            target.write_text("#!/usr/bin/env python3\nold\n", encoding="utf-8")
            target.chmod(0o755)

            cr.replace_self("#!/usr/bin/env python3\nnew\n", target)

            self.assertEqual(target.read_text(encoding="utf-8").strip().splitlines()[-1], "new")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            self.assertFalse((Path(tmp) / "cachereaper.new").exists())
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["cachereaper"])

    def test_update_is_the_only_command_that_can_reach_the_network(self):
        # A disk tool that phoned home on every scan would be a different tool.
        source = Path(cr.__file__).read_text(encoding="utf-8")
        before, _, after = source.partition("# updates")
        self.assertNotIn("urllib", before, "nothing before the update section may import urllib")
        self.assertNotIn("urllib", after.split("def build_parser")[1],
                         "nothing after the update section may import urllib")


if __name__ == "__main__":
    unittest.main(verbosity=2)
