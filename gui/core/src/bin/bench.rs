//! Benchmark the scanner. This exists to enforce the Phase 2 gate: a cold scan
//! of $HOME must finish in under 20s, otherwise the Tauri frontend is not worth
//! building on top of this walker.
//!
//!   cargo run --release --bin bench -- ~            # default thread sweep
//!   cargo run --release --bin bench -- ~ 6          # a single thread count

use cachereaper_core::{human, scan_with_progress};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let root: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(cachereaper_core::guard::home);
    let thread_counts: Vec<usize> = match args.next() {
        Some(n) => vec![n.parse().expect("thread count must be a number")],
        None => vec![1, 2, 4, 6, 8],
    };

    println!("scanning {}", root.display());
    println!(
        "{:>8}  {:>10}  {:>12}  {:>10}  {:>12}",
        "threads", "seconds", "files", "dirs", "files/s"
    );

    for threads in thread_counts {
        let counter = AtomicU64::new(0);
        let started = Instant::now();
        let tree = match scan_with_progress(&root, threads, |files, _| {
            // cheap heartbeat so a long scan does not look hung
            if files % 250_000 == 0 && files > 0 {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }) {
            Ok(t) => t,
            Err(err) => {
                eprintln!("scan failed: {err}");
                std::process::exit(1);
            }
        };
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "{:>8}  {:>10.2}  {:>12}  {:>10}  {:>12.0}",
            threads,
            elapsed,
            tree.stats.files,
            tree.stats.dirs,
            tree.stats.files as f64 / elapsed
        );
        if threads == 1 || elapsed < 1.0 {
            println!(
                "          total {}  unreadable dirs {}",
                human(tree.stats.bytes),
                tree.stats.unreadable
            );
        }
    }
}
