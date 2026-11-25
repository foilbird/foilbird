// SPDX-License-Identifier: Apache-2.0
//! Read-only journald reader without exec and without libsystemd: parses the
//! journal file format (systemd docs/JOURNAL_FILE_FORMAT.md) directly.
//! Supported: regular and compact files, zstd-compressed fields (the default
//! of current systemd); xz/lz4 fields are reported as not decoded.
//! Files are scanned linearly; online files may be truncated at the tail,
//! which only ends the scan of that file.

use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const SIGNATURE: &[u8; 8] = b"LPKSHHRH";
const INCOMPAT_COMPACT: u32 = 1 << 4;
const OBJ_DATA: u8 = 1;
const OBJ_ENTRY: u8 = 3;
const COMPRESSED_XZ: u8 = 1;
const COMPRESSED_LZ4: u8 = 2;
const COMPRESSED_ZSTD: u8 = 4;
/// Files above this size are skipped (journald rotates far below it).
const MAX_FILE: u64 = 512 << 20;
const MAX_MESSAGE: usize = 4096;

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub realtime_usec: u64,
    pub boot_id: String,
    pub fields: HashMap<String, String>,
}

impl Entry {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.fields.get(k).map(String::as_str)
    }
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Fields worth decoding; others are skipped (saves decompression).
const WANTED: &[&str] = &[
    "MESSAGE", "PRIORITY", "_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT", "_PID", "SYSLOG_IDENTIFIER",
    "_TRANSPORT", "_COMM",
];

fn data_payload(d: &[u8], off: usize, compact: bool) -> Option<Vec<u8>> {
    if d.get(off) != Some(&OBJ_DATA) {
        return None;
    }
    let flags = *d.get(off + 1)?;
    let size = u64_at(d, off + 8)? as usize;
    let start = off + if compact { 72 } else { 64 };
    let end = off.checked_add(size)?;
    let raw = d.get(start..end)?;
    match flags & (COMPRESSED_XZ | COMPRESSED_LZ4 | COMPRESSED_ZSTD) {
        0 => Some(raw.to_vec()),
        COMPRESSED_ZSTD => {
            use std::io::Read;
            let mut dec = ruzstd::decoding::StreamingDecoder::new(raw).ok()?;
            let mut out = Vec::new();
            dec.read_to_end(&mut out).ok()?;
            Some(out)
        }
        _ => {
            // field name is not recoverable without decompression
            None
        }
    }
}

/// Parse one journal file into entries passing `keep` (called with the
/// header fields only; full fields are decoded for kept entries).
pub fn read_file(path: &Path, mut keep: impl FnMut(&Entry) -> bool) -> Result<Vec<Entry>, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_FILE {
        return Err(format!("{} larger than {MAX_FILE}", path.display()));
    }
    let d = std::fs::read(path).map_err(|e| e.to_string())?;
    if d.len() < 240 || &d[0..8] != SIGNATURE {
        return Err("not a journal file".into());
    }
    let incompat = u32_at(&d, 12).unwrap();
    let compact = incompat & INCOMPAT_COMPACT != 0;
    let header_size = u64_at(&d, 88).unwrap() as usize;
    let tail = u64_at(&d, 136).unwrap() as usize;
    let item = if compact { 4 } else { 16 };
    let mut out = Vec::new();
    let mut cache: HashMap<usize, Option<(String, String)>> = HashMap::new();
    let mut o = header_size;
    while o <= tail && o + 16 <= d.len() {
        let t = d[o];
        let Some(size) = u64_at(&d, o + 8).map(|s| s as usize) else { break };
        if size < 16 || o + size > d.len() {
            break;
        }
        if t == OBJ_ENTRY && size >= 64 {
            let realtime = u64_at(&d, o + 24).unwrap_or(0);
            let boot_id = hex::encode(&d[o + 40..o + 56]);
            let mut e = Entry { realtime_usec: realtime, boot_id, fields: HashMap::new() };
            let n = (size - 64) / item;
            for i in 0..n {
                let p = o + 64 + i * item;
                let off = if compact { u32_at(&d, p).map(|x| x as usize) } else { u64_at(&d, p).map(|x| x as usize) };
                let Some(off) = off else { break };
                let kv = cache.entry(off).or_insert_with(|| {
                    let pl = data_payload(&d, off, compact)?;
                    let eq = pl.iter().position(|&b| b == b'=')?;
                    let k = std::str::from_utf8(&pl[..eq]).ok()?;
                    if !WANTED.contains(&k) {
                        return Some((k.to_string(), String::new()));
                    }
                    Some((k.to_string(), String::from_utf8_lossy(&pl[eq + 1..]).into_owned()))
                });
                if let Some((k, v)) = kv {
                    if WANTED.contains(&k.as_str()) {
                        e.fields.insert(k.clone(), v.clone());
                    }
                }
            }
            if keep(&e) {
                out.push(e);
            }
        }
        o += (size + 7) & !7;
    }
    Ok(out)
}

/// Journal files of this machine: persistent and runtime, archived and online.
pub fn files(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for r in roots {
        let Ok(dirs) = std::fs::read_dir(r) else { continue };
        for d in dirs.flatten() {
            let Ok(fs) = std::fs::read_dir(d.path()) else { continue };
            for f in fs.flatten() {
                let n = f.file_name().to_string_lossy().into_owned();
                if n.ends_with(".journal") || n.ends_with(".journal~") {
                    v.push(f.path());
                }
            }
        }
    }
    v.sort();
    v
}

// ------------------------------------------------------------- query

#[derive(Debug, Clone, Default)]
pub struct Query {
    pub unit: Option<String>,
    pub max_priority: Option<u32>,
    pub kernel_only: bool,
    /// boot id (hex, 32) to restrict to
    pub boot_id: Option<String>,
    pub since_usec: u64,
    pub until_usec: u64,
    pub limit: usize,
}

pub fn matches(q: &Query, e: &Entry) -> bool {
    if let Some(b) = &q.boot_id {
        if &e.boot_id != b {
            return false;
        }
    }
    if q.since_usec != 0 && e.realtime_usec < q.since_usec {
        return false;
    }
    if q.until_usec != 0 && e.realtime_usec > q.until_usec {
        return false;
    }
    if q.kernel_only && e.get("_TRANSPORT") != Some("kernel") {
        return false;
    }
    if let Some(p) = q.max_priority {
        // entries without PRIORITY count as info (6), as journalctl does
        let pr = e.get("PRIORITY").and_then(|s| s.parse::<u32>().ok()).unwrap_or(6);
        if pr > p {
            return false;
        }
    }
    if let Some(u) = &q.unit {
        let own = e.get("_SYSTEMD_UNIT") == Some(u.as_str());
        let about = e.get("_PID") == Some("1") && e.get("UNIT") == Some(u.as_str());
        let object = e.get("OBJECT_SYSTEMD_UNIT") == Some(u.as_str());
        if !(own || about || object) {
            return false;
        }
    }
    e.get("MESSAGE").is_some()
}

pub struct Result_ {
    pub entries: Vec<Entry>,
    pub truncated: bool,
    /// boots seen (boot id, first realtime), oldest first
    pub boots: Vec<(String, u64)>,
}

/// Run a query over the files; returns the last `limit` matching entries.
pub fn query(roots: &[PathBuf], q: &Query) -> Result_ {
    let mut all = Vec::new();
    let mut boots: HashMap<String, u64> = HashMap::new();
    for f in files(roots) {
        let r = read_file(&f, |e| {
            let b = boots.entry(e.boot_id.clone()).or_insert(e.realtime_usec);
            if e.realtime_usec < *b {
                *b = e.realtime_usec;
            }
            matches(q, e)
        });
        if let Ok(mut v) = r {
            // keep memory bounded: only the newest `limit` per file can survive
            if v.len() > q.limit {
                v.drain(..v.len() - q.limit);
            }
            all.append(&mut v);
        }
    }
    all.sort_by_key(|e| e.realtime_usec);
    let truncated = all.len() > q.limit;
    if truncated {
        all.drain(..all.len() - q.limit);
    }
    let mut b: Vec<_> = boots.into_iter().collect();
    b.sort_by_key(|x| x.1);
    Result_ { entries: all, truncated, boots: b }
}

/// Boot id for an offset: 0 = current, -1 = previous, ...
pub fn boot_by_offset(boots: &[(String, u64)], current: &str, offset: i32) -> Option<String> {
    let idx = boots.iter().position(|b| b.0 == current).unwrap_or(boots.len().saturating_sub(1));
    let i = idx as i64 + offset as i64;
    (offset <= 0 && i >= 0).then(|| boots.get(i as usize).map(|b| b.0.clone())).flatten()
}

// ------------------------------------------------------------- redaction

fn patterns() -> &'static [(Regex, &'static str)] {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        [
            (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", "[REDACTED private key]"),
            (r"\b[a-z0-9]{6}\.[a-z0-9]{16}\b", "[REDACTED bootstrap token]"),
            (r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}", "[REDACTED jwt]"),
            (r"(?i)(authorization:\s*(bearer|basic)\s+)\S+", "${1}[REDACTED]"),
            (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED access key]"),
            (
                r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)(["']?\s*[:=]\s*["']?)[^\s"',;&]+"#,
                "${1}${2}[REDACTED]",
            ),
        ]
        .into_iter()
        .map(|(p, r)| (Regex::new(p).expect("valid pattern"), r))
        .collect()
    })
}

/// Redact secrets in a log line; also any exact `known` secret values.
/// Returns the text and the number of redactions.
pub fn redact(s: &str, known: &[String]) -> (String, u32) {
    let mut out = s.to_string();
    let mut n = 0;
    for k in known.iter().filter(|k| k.len() >= 8) {
        let c = out.matches(k.as_str()).count() as u32;
        if c > 0 {
            out = out.replace(k.as_str(), "[REDACTED]");
            n += c;
        }
    }
    for (re, rep) in patterns() {
        let c = re.find_iter(&out).count() as u32;
        if c > 0 {
            out = re.replace_all(&out, *rep).into_owned();
            n += c;
        }
    }
    (clip(out), n)
}

/// Cut a message to MAX_MESSAGE bytes (char boundary), marked " [truncated]".
pub fn clip(mut out: String) -> String {
    if out.len() > MAX_MESSAGE {
        let mut cut = MAX_MESSAGE;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str(" [truncated]");
    }
    out
}

/// systemd unit name: name[@instance].type, [A-Za-z0-9:_.\\-@], <= 255.
pub fn valid_unit(u: &str) -> bool {
    const TYPES: &[&str] =
        &[".service", ".socket", ".target", ".device", ".mount", ".automount", ".swap", ".timer", ".path", ".slice", ".scope"];
    !u.is_empty()
        && u.len() <= 255
        && TYPES.iter().any(|t| u.ends_with(t) && u.len() > t.len())
        && u.bytes().all(|b| b.is_ascii_alphanumeric() || b":_.\\-@".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction() {
        let known = vec!["s3cr3t-value-123".to_string()];
        for (input, must_not) in [
            ("join token abcdef.0123456789abcdef ok", "0123456789abcdef"),
            ("Authorization: Bearer xyz.abc.def", "xyz.abc"),
            ("password=hunter2 user=x", "hunter2"),
            ("\"client_secret\": \"aa-bb\"", "aa-bb"),
            ("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----", "MHcCAQEE"), // gitleaks:allow (synthetic test input)
            ("-----BEGIN PRIVATE KEY----- MIIE (cut)", "MIIE"),
            ("tok eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", "eyJzdWIiOi"),
            ("key AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"), // gitleaks:allow (synthetic test input)
            ("leaked s3cr3t-value-123 here", "s3cr3t-value-123"),
        ] {
            let (o, n) = redact(input, &known);
            assert!(!o.contains(must_not), "{input:?} -> {o:?}");
            assert!(n >= 1, "{input:?}");
        }
        let (o, n) = redact("Started kubelet.service - kubelet", &known);
        assert_eq!((o.as_str(), n), ("Started kubelet.service - kubelet", 0));
        let (o, _) = redact(&"x".repeat(10000), &[]);
        assert!(o.len() < 4200 && o.ends_with("[truncated]"));
    }

    #[test]
    fn units_and_boots() {
        assert!(valid_unit("kubelet.service"));
        assert!(valid_unit("foil-install@2026.11.15.service"));
        assert!(valid_unit("dev-vda1.device"));
        assert!(!valid_unit("kubelet"));
        assert!(!valid_unit("../x.service"));
        assert!(!valid_unit("a b.service"));
        let boots = vec![("a".to_string(), 1), ("b".to_string(), 2), ("c".to_string(), 3)];
        assert_eq!(boot_by_offset(&boots, "c", 0).as_deref(), Some("c"));
        assert_eq!(boot_by_offset(&boots, "c", -2).as_deref(), Some("a"));
        assert_eq!(boot_by_offset(&boots, "c", -3), None);
        assert_eq!(boot_by_offset(&boots, "c", 1), None);
    }

    #[test]
    fn filters() {
        let mut e = Entry { realtime_usec: 100, boot_id: "b".into(), fields: HashMap::new() };
        e.fields.insert("MESSAGE".into(), "m".into());
        e.fields.insert("PRIORITY".into(), "3".into());
        e.fields.insert("_SYSTEMD_UNIT".into(), "kubelet.service".into());
        let q = |f: fn(&mut Query)| {
            let mut q = Query { limit: 10, ..Default::default() };
            f(&mut q);
            q
        };
        assert!(matches(&q(|q| q.unit = Some("kubelet.service".into())), &e));
        assert!(!matches(&q(|q| q.unit = Some("containerd.service".into())), &e));
        assert!(matches(&q(|q| q.max_priority = Some(3)), &e));
        assert!(!matches(&q(|q| q.max_priority = Some(2)), &e));
        assert!(!matches(&q(|q| q.kernel_only = true), &e));
        assert!(!matches(&q(|q| q.since_usec = 101), &e));
        assert!(!matches(&q(|q| q.boot_id = Some("x".into())), &e));
        let mut pid1 = e.clone();
        pid1.fields.insert("_SYSTEMD_UNIT".into(), "init.scope".into());
        pid1.fields.insert("_PID".into(), "1".into());
        pid1.fields.insert("UNIT".into(), "kubelet.service".into());
        assert!(matches(&q(|q| q.unit = Some("kubelet.service".into())), &pid1));
    }
}
