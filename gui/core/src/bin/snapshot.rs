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

    // Nothing extra to skip: a dev snapshot has no permission record to consult,
    // and `scan_with_markers` refuses the dialog-raising locations on its own.
    let tree = match scan_with_markers(
        &root,
        default_threads(),
        marker_vocabulary(),
        Vec::new(),
        |_, _| {},
    ) {
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
                        "x": n.state,
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "root_path": tree.root_path.to_string_lossy(),
                "home_path": cachereaper_core::guard::home().to_string_lossy(),
                "stats": {
                    "dirs": tree.stats.dirs,
                    "files": tree.stats.files,
                    "bytes": tree.stats.bytes,
                    "unreadable": tree.stats.unreadable,
                    "elapsed_ms": tree.stats.elapsed_ms,
                    "reclaimable_bytes": tree.stats.reclaimable_bytes,
                    "allocated_reference_bytes": tree.stats.allocated_reference_bytes,
                    "logical_bytes": tree.stats.logical_bytes,
                    "shared_or_snapshot_bytes": tree.stats.shared_or_snapshot_bytes,
                    "excluded": tree.stats.excluded,
                    "unreadable_paths": tree.stats.unreadable_paths,
                    "excluded_paths": tree.stats.excluded_paths,
                    "volume_capacity": null,
                    "volume_free": null,
                },
                "findings": findings.iter().map(|finding| serde_json::json!({
                    "node_id": finding.node,
                    "rule_id": finding.rule_id,
                    "tier": finding.tier,
                    "label": finding.label,
                    "regen": finding.regen,
                    "warning": finding.warn,
                    "source": finding.source,
                    "reclaimable_size": finding.size,
                    "path": finding.path.to_string_lossy(),
                })).collect::<Vec<_>>(),
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
