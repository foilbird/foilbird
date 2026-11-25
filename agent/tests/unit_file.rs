// SPDX-License-Identifier: Apache-2.0
//! Static check of systemd/foil-agent.service: the agent is restarted for good (a panic aborts it, panic = "abort"),
//! each restart field in the section systemd reads it from ([Unit] vs [Service]; in the wrong one it is ignored with a
//! warning).

use std::collections::HashMap;

/// (section, key) -> values, in file order.
fn unit() -> HashMap<(String, String), Vec<String>> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd/foil-agent.service");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let mut out: HashMap<(String, String), Vec<String>> = HashMap::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or_else(|| panic!("not key=value: {line}"));
        out.entry((section.clone(), k.trim().to_string())).or_default().push(v.trim().to_string());
    }
    out
}

fn one<'a>(u: &'a HashMap<(String, String), Vec<String>>, section: &str, key: &str) -> &'a str {
    match u.get(&(section.to_string(), key.to_string())).map(Vec::as_slice) {
        Some([v]) => v,
        other => panic!("[{section}] {key}: expected exactly one value, got {other:?}"),
    }
}

fn absent(u: &HashMap<(String, String), Vec<String>>, section: &str, key: &str) {
    assert!(!u.contains_key(&(section.to_string(), key.to_string())), "{key} must not be in [{section}] (systemd ignores it there)");
}

#[test]
fn agent_unit_restarts_for_good() {
    let u = unit();
    // [Unit]: no start rate limit, so a crash loop never leaves the unit failed and the node without its API
    assert_eq!(one(&u, "Unit", "StartLimitIntervalSec"), "0");
    for k in ["StartLimitIntervalSec", "StartLimitBurst"] {
        absent(&u, "Service", k);
    }
    // [Service]: restart always, 2 s growing to 60 s
    assert_eq!(one(&u, "Service", "Restart"), "always");
    assert_eq!(one(&u, "Service", "RestartSec"), "2");
    assert_eq!(one(&u, "Service", "RestartMaxDelaySec"), "60");
    let steps: u32 = one(&u, "Service", "RestartSteps").parse().expect("RestartSteps: a number");
    assert!(steps > 0, "RestartSteps must be > 0 for the delay to grow");
    for k in ["Restart", "RestartSec", "RestartSteps", "RestartMaxDelaySec"] {
        absent(&u, "Unit", k);
    }
}
