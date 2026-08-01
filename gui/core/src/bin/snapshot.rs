//! Dump a scan as JSON.
//!
//!   snapshot findings ~          # findings only, shaped like `cachereaper scan --json`
//!   snapshot tree ~ out.json     # the treemap payload
//!
//! `findings` exists so the Rust rule engine can be diffed directly against the
//! Python CLI, which is the cross-check the plan asks for. `tree` feeds the
//! frontend during development without needing the Tauri shell built.

use cachereaper_core::rules::{all_findings, marker_vocabulary};
use cachereaper_core::{default_threads, human, scan_with_markers};
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "findings".into());
    let root: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(cachereaper_core::guard::home);
    let out = args.next();

    let tree = match scan_with_markers(&root, default_threads(), marker_vocabulary(), |_, _| {}) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("scan failed: {err}");
            std::process::exit(1);
        }
    };
    let findings = all_findings(&tree, false);

    match mode.as_str() {
        "findings" => {
            let rows: Vec<_> = findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "path": f.path.to_string_lossy(),
                        "rule": f.rule_id,
                        "tier": f.tier,
                        "bytes": f.size,
                        "source": f.source,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        "tree" => {
            // Compact keys: this payload is large and mostly repeated field names.
            let rule_of: std::collections::HashMap<u32, &cachereaper_core::Finding> =
                findings.iter().map(|f| (f.node, f)).collect();
            let nodes: Vec<_> = tree
                .nodes
                .iter()
                .enumerate()
                .map(|(idx, n)| {
                    let hit = rule_of.get(&(idx as u32));
                    serde_json::json!({
                        "n": n.name,
                        "p": if n.parent == cachereaper_core::NONE { -1i64 } else { n.parent as i64 },
                        "c": n.children,
                        "s": n.total_size,
                        "o": n.own_size,
                        "f": n.total_files,
                        "m": n.newest_mtime,
                        "u": n.unreadable,
                        "t": hit.map(|h| h.tier.clone()),
                        "r": hit.map(|h| h.rule_id.clone()),
                        "g": hit.map(|h| h.regen.clone()),
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "root_path": tree.root_path.to_string_lossy(),
                "stats": {
                    "dirs": tree.stats.dirs,
                    "files": tree.stats.files,
                    "bytes": tree.stats.bytes,
                    "unreadable": tree.stats.unreadable,
                    "elapsed_ms": tree.stats.elapsed_ms,
                },
                "findings": findings.len(),
                "nodes": nodes,
            });
            let text = serde_json::to_string(&doc).unwrap();
            match out {
                Some(path) => {
                    std::fs::write(&path, &text).expect("write snapshot");
                    eprintln!(
                        "wrote {} ({}) — {} nodes, {} findings, total {}",
                        path,
                        human(text.len() as u64),
                        tree.nodes.len(),
                        findings.len(),
                        human(tree.stats.bytes)
                    );
                }
                None => println!("{text}"),
            }
        }
        other => {
            eprintln!("unknown mode {other:?}; expected 'findings' or 'tree'");
            std::process::exit(2);
        }
    }
}
