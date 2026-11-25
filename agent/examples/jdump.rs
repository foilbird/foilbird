// SPDX-License-Identifier: Apache-2.0
//! Cross-check of the journal reader against journalctl on a build host:
//!   jdump kernel|unit <name>|all [limit]   (current boot; run as root)
use foil_agent::journal::{self, Query};
use std::path::PathBuf;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim().replace('-', "");
    let mut q = Query { boot_id: Some(boot), limit: 1_000_000, ..Default::default() };
    match a.first().map(String::as_str) {
        Some("kernel") => q.kernel_only = true,
        Some("unit") => q.unit = Some(a[1].clone()),
        _ => {}
    }
    let t = std::time::Instant::now();
    let r = journal::query(&[PathBuf::from("/var/log/journal"), PathBuf::from("/run/log/journal")], &q);
    println!("entries={} boots={} elapsed_ms={}", r.entries.len(), r.boots.len(), t.elapsed().as_millis());
    for e in r.entries.iter().rev().take(3).rev() {
        println!("  {} {}", e.realtime_usec, e.get("MESSAGE").unwrap_or("").chars().take(100).collect::<String>());
    }
}
