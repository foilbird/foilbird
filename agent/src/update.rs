// SPDX-License-Identifier: Apache-2.0
//! StageUpdate (decision 0002): the complete release is downloaded into a
//! staging directory independent of the sysupdate slots and verified there
//! — signed manifest, every file hash, version policy, completeness — before
//! anything touches the inactive slot. Only then the platform installer
//! writes the slot from the staging copy.
//!
//! The default channel location and the release key are part of the image;
//! StageUpdate only names a version. NodeConfig.update_channel (ApplyConfig,
//! DESTRUCTIVE) may replace the location with an https server and its CA, never
//! the key. Trust comes only from the SHA256SUMS signature by the image's
//! release key, never from the channel URL or its scheme (http:// is accepted
//! for lab builds in the image only).

use crate::pb::{ChannelInfo, ChannelOrigin, KeyOpPhase, KeyOperation, Slot, StageError, StagePhase, StageStatus, UpdateChannel, Version};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

pub const MANIFEST: &str = "SHA256SUMS";
pub const MANIFEST_SIG: &str = "SHA256SUMS.gpg";
const MAX_MANIFEST: u64 = 1 << 20;

/// Parts a release must contain (file name after "<image-id>_<version>").
const PARTS: &[(&str, &str)] = &[
    ("uki", ".efi"),
    ("usr", ".usr-x86-64."),
    ("usr-verity", ".usr-x86-64-verity."),
    ("usr-verity-sig", ".usr-x86-64-verity-sig."),
];

// ------------------------------------------------------------- versions

/// Version comparison in the spirit of systemd's strverscmp_improved():
/// runs of digits compare numerically, other runs lexically; '~' sorts
/// before everything (pre-release).
pub fn vercmp(a: &str, b: &str) -> Ordering {
    fn segs(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut digit = None;
        for c in s.chars() {
            if !c.is_ascii_alphanumeric() && c != '~' {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                digit = None;
                continue;
            }
            let d = c.is_ascii_digit();
            if digit.is_some_and(|x| x != d) || c == '~' {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            cur.push(c);
            digit = Some(d);
            if c == '~' {
                out.push(std::mem::take(&mut cur));
                digit = None;
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }
    let (sa, sb) = (segs(a), segs(b));
    for i in 0..sa.len().max(sb.len()) {
        let (x, y) = (sa.get(i), sb.get(i));
        let o = match (x, y) {
            (None, None) => Ordering::Equal,
            (Some(x), None) => if x == "~" { Ordering::Less } else { Ordering::Greater },
            (None, Some(y)) => if y == "~" { Ordering::Greater } else { Ordering::Less },
            (Some(x), Some(y)) if x == "~" || y == "~" => {
                if x == y { Ordering::Equal } else if x == "~" { Ordering::Less } else { Ordering::Greater }
            }
            (Some(x), Some(y)) => {
                let nx = x.bytes().all(|c| c.is_ascii_digit());
                let ny = y.bytes().all(|c| c.is_ascii_digit());
                match (nx, ny) {
                    (true, true) => {
                        let (tx, ty) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                        tx.len().cmp(&ty.len()).then_with(|| tx.cmp(ty))
                    }
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    _ => x.cmp(y),
                }
            }
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

/// systemd-escape for a unit instance: everything outside [A-Za-z0-9:_.-]
/// (and a leading '.') becomes \xNN; `%i` in the unit gives the original.
pub fn systemd_escape(s: &str) -> String {
    let mut o = String::new();
    for (i, b) in s.bytes().enumerate() {
        let ok = b.is_ascii_alphanumeric() || b":_-".contains(&b) || (b == b'.' && i > 0);
        if ok {
            o.push(b as char)
        } else {
            o.push_str(&format!("\\x{b:02x}"))
        }
    }
    o
}

pub fn valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~+-".contains(&b))
        && v.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
}

// ------------------------------------------------------------- manifest

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub sha256: String,
    pub name: String,
}

/// `sha256sum` output: "<64 hex>  <name>" (also " *<name>" binary mode).
pub fn parse_manifest(text: &str) -> Result<Vec<Entry>, String> {
    let mut v = Vec::new();
    for (n, l) in text.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        let (h, rest) = l.split_once(' ').ok_or_else(|| format!("line {}: malformed", n + 1))?;
        let name = rest.trim_start_matches([' ', '*']);
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("line {}: bad hash", n + 1));
        }
        let safe = !name.is_empty()
            && name.len() <= 255
            && !name.starts_with('.')
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~+-".contains(&b));
        if !safe {
            return Err(format!("line {}: unsafe file name", n + 1));
        }
        v.push(Entry { sha256: h.to_ascii_lowercase(), name: name.to_string() });
    }
    Ok(v)
}

/// Files of one release: exactly one per part.
pub fn select(entries: &[Entry], image_id: &str, version: &str) -> Result<Vec<Entry>, StageError> {
    let prefix = format!("{image_id}_{version}");
    let mine: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.name.strip_prefix(&prefix).is_some_and(|r| r.starts_with('.')))
        .collect();
    if mine.is_empty() {
        return Err(StageError::NotInChannel);
    }
    let mut out = Vec::new();
    for (_, marker) in PARTS {
        let m: Vec<_> = mine
            .iter()
            .filter(|e| {
                let r = &e.name[prefix.len()..];
                if *marker == ".efi" { r == ".efi" } else { r.starts_with(marker) }
            })
            .collect();
        if m.len() != 1 {
            return Err(StageError::Incomplete);
        }
        out.push((*m[0]).clone());
    }
    Ok(out)
}

/// Versions announced in the manifest (by their UKI).
pub fn versions(entries: &[Entry], image_id: &str) -> Vec<String> {
    let p = format!("{image_id}_");
    entries.iter().filter_map(|e| e.name.strip_prefix(&p)?.strip_suffix(".efi").map(str::to_string)).collect()
}

// ------------------------------------------------------------- signature

/// Verifies a detached OpenPGP signature against the release keyring built
/// into the image (binary or armored, primary keys and signing subkeys).
pub fn verify_signature(keyring: &[u8], data: &[u8], sig: &[u8]) -> Result<(), String> {
    use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
    let keys: Vec<SignedPublicKey> = if keyring.starts_with(b"-----BEGIN") {
        SignedPublicKey::from_armor_many(std::io::Cursor::new(keyring))
            .map_err(|e| format!("keyring: {e}"))?
            .0
            .collect::<Result<_, _>>()
            .map_err(|e| format!("keyring: {e}"))?
    } else {
        SignedPublicKey::from_bytes_many(std::io::Cursor::new(keyring))
            .map_err(|e| format!("keyring: {e}"))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("keyring: {e}"))?
    };
    if keys.is_empty() {
        return Err("keyring: no keys".into());
    }
    let sig = if sig.starts_with(b"-----BEGIN") {
        DetachedSignature::from_armor_single(std::io::Cursor::new(sig)).map_err(|e| format!("signature: {e}"))?.0
    } else {
        DetachedSignature::from_bytes(std::io::Cursor::new(sig)).map_err(|e| format!("signature: {e}"))?
    };
    for k in &keys {
        if sig.verify(k, data).is_ok() {
            return Ok(());
        }
        for sk in &k.public_subkeys {
            if sig.verify(sk, data).is_ok() {
                return Ok(());
            }
        }
    }
    Err("signature does not verify with the release key".into())
}

// ------------------------------------------------------------- channel

/// Where releases come from. Fixed by the image, never by the caller.
#[tonic::async_trait]
pub trait Channel: Send + Sync {
    /// Copy `name` into `dest`, at most `limit` bytes.
    async fn fetch(&self, name: &str, dest: &Path, limit: u64) -> Result<(), String>;
    /// For status and audit only.
    fn location(&self) -> String {
        String::new()
    }
}

/// A directory (local mirror, or tests).
pub struct DirChannel(pub PathBuf);

#[tonic::async_trait]
impl Channel for DirChannel {
    async fn fetch(&self, name: &str, dest: &Path, limit: u64) -> Result<(), String> {
        let src = self.0.join(name);
        let len = tokio::fs::metadata(&src).await.map_err(|e| format!("{name}: {e}"))?.len();
        if len > limit {
            return Err(format!("{name}: {len} bytes, limit {limit}"));
        }
        tokio::fs::copy(&src, dest).await.map(|_| ()).map_err(|e| format!("{name}: {e}"))
    }
    fn location(&self) -> String {
        self.0.display().to_string()
    }
}

/// Trust comes only from the SHA256SUMS signature by the image's release key, never from the channel URL or its scheme.
/// HTTP(S) channel. The URL gives no trust: the release is accepted only
/// if SHA256SUMS verifies with the release key built into the image.
pub struct HttpChannel {
    base: String,
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Empty<bytes::Bytes>,
    >,
    pub retries: u32,
    pub idle_timeout: std::time::Duration,
}

enum Fail {
    Fatal(String),
    Retry(String),
}

impl HttpChannel {
    /// `ca_pem`: trust anchors for https (the image's channel CA or the system bundle).
    pub fn new(url: &str, ca_pem: Option<&[u8]>) -> Result<Self, String> {
        let ok_scheme = url.starts_with("http://") || url.starts_with("https://");
        let rest = url.split_once("://").map(|x| x.1).unwrap_or("");
        let authority = rest.split('/').next().unwrap_or("");
        if !ok_scheme || authority.is_empty() || authority.contains('@') || url.bytes().any(|b| b <= b' ' || b == b'?' || b == b'#') {
            return Err(format!("channel URL: expected http(s)://host[:port]/path/, got {url:?}"));
        }
        let mut roots = rustls::RootCertStore::empty();
        if let Some(pem) = ca_pem {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            for c in CertificateDer::pem_slice_iter(pem) {
                let c = c.map_err(|e| format!("channel CA: {e}"))?;
                roots.add(c).map_err(|e| format!("channel CA: {e}"))?;
            }
        }
        if url.starts_with("https://") && roots.is_empty() {
            return Err("https channel without a CA".into());
        }
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(std::time::Duration::from_secs(10)));
        let conn = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(conn);
        let base = if url.ends_with('/') { url.to_string() } else { format!("{url}/") };
        Ok(HttpChannel { base, client, retries: 3, idle_timeout: std::time::Duration::from_secs(30) })
    }

    async fn try_fetch(&self, url: &str, dest: &Path, limit: u64) -> Result<(), Fail> {
        use http_body_util::BodyExt;
        use tokio::io::AsyncWriteExt;
        let have = tokio::fs::metadata(dest).await.map(|m| m.len()).unwrap_or(0);
        let mut req = hyper::Request::get(url).header("user-agent", concat!("foil-agent/", env!("CARGO_PKG_VERSION")));
        if have > 0 {
            req = req.header("range", format!("bytes={have}-"));
        }
        let req = req.body(http_body_util::Empty::new()).map_err(|e| Fail::Fatal(e.to_string()))?;
        let resp = tokio::time::timeout(self.idle_timeout, self.client.request(req))
            .await
            .map_err(|_| Fail::Retry("timeout waiting for response".into()))?
            .map_err(|e| request_failure(&e))?;
        let status = resp.status().as_u16();
        let append = match status {
            200 => false,
            206 if have > 0 => true,
            404 | 410 => return Err(Fail::Fatal(format!("HTTP {status}"))),
            s if (400..500).contains(&s) => return Err(Fail::Fatal(format!("HTTP {s}"))),
            s => return Err(Fail::Retry(format!("HTTP {s}"))),
        };
        let start = if append { have } else { 0 };
        if let Some(len) = resp.headers().get("content-length").and_then(|v| v.to_str().ok()?.parse::<u64>().ok()) {
            if start + len > limit {
                return Err(Fail::Fatal(format!("{} bytes, limit {limit}", start + len)));
            }
        }
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(dest)
            .await
            .map_err(|e| Fail::Fatal(e.to_string()))?;
        let mut total = start;
        let mut body = resp.into_body();
        loop {
            let frame = tokio::time::timeout(self.idle_timeout, body.frame())
                .await
                .map_err(|_| Fail::Retry(format!("stalled at {total} bytes")))?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|e| Fail::Retry(format!("at {total} bytes: {e}")))?;
            if let Ok(data) = frame.into_data() {
                total += data.len() as u64;
                if total > limit {
                    return Err(Fail::Fatal(format!("more than {limit} bytes")));
                }
                f.write_all(&data).await.map_err(|e| Fail::Fatal(e.to_string()))?;
            }
        }
        f.flush().await.map_err(|e| Fail::Fatal(e.to_string()))?;
        Ok(())
    }
}

/// How a failed request (connect, TLS handshake, request, response head) is retried. Strict, fail-closed:
/// - anything the TLS layer said (a rustls error anywhere in the chain: certificate not vouched for by the channel CA,
///   expired, wrong name, revoked; an alert from the server; protocol, version or cipher mismatch) is Fatal: it will
///   not get better by trying again;
/// - Retry only for the transport before or during the handshake and before the response: refused, reset or aborted
///   connection, end of stream before the handshake (or the response head) completed, a connect or handshake timeout,
///   and every name resolution error (availability, not trust: a temporary failure and "no such name" are not told
///   apart reliably through the resolver). The backoff and the number of tries are those of every other network retry
///   (HttpChannel::retries); the kind is named in the message ("[transport: <kind>]");
/// - every other error is Fatal (an unknown kind of error is not retried).
/// An attacker who can reset connections gains only the delay up to the retry limit: a denial of service, never a
/// bypass of the certificate check.
fn request_failure(e: &(dyn std::error::Error + 'static)) -> Fail {
    if let Some(t) = tls_rejected(e) {
        return Fail::Fatal(format!("TLS: {t}"));
    }
    if let Some(k) = transport_interrupted(e) {
        return Fail::Retry(format!("{e} [transport: {k}]"));
    }
    Fail::Fatal(format!("unclassified: {e}"))
}

/// The kind of an interrupted transport anywhere in the chain: an io error kind (refused, reset, aborted, early end of
/// stream, timeout), hyper's "connection closed before message completed", or the connector's name resolution error
/// (hyper-util's HttpConnector reports it as "dns error", the resolver's own error below it).
fn transport_interrupted(e: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    use std::io::ErrorKind as K;
    let mut cur = Some(e);
    while let Some(x) = cur {
        if let Some(io) = x.downcast_ref::<std::io::Error>() {
            match io.kind() {
                K::ConnectionRefused => return Some("ConnectionRefused"),
                K::ConnectionReset => return Some("ConnectionReset"),
                K::ConnectionAborted => return Some("ConnectionAborted"),
                K::UnexpectedEof => return Some("UnexpectedEof"),
                K::TimedOut => return Some("TimedOut"),
                _ => {}
            }
        }
        if x.downcast_ref::<hyper::Error>().is_some_and(|h| h.is_incomplete_message()) {
            return Some("incomplete message");
        }
        if x.to_string() == "dns error" {
            return Some("dns");
        }
        cur = match x.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()) {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => x.source(),
        };
    }
    None
}

/// rustls error anywhere in the source chain (certificate refused etc.).
fn tls_rejected(e: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur = Some(e);
    while let Some(x) = cur {
        if let Some(t) = x.downcast_ref::<rustls::Error>() {
            return Some(t.to_string());
        }
        // io::Error::source() skips its payload; descend into it explicitly
        cur = match x.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()) {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => x.source(),
        };
    }
    None
}

#[tonic::async_trait]
impl Channel for HttpChannel {
    async fn fetch(&self, name: &str, dest: &Path, limit: u64) -> Result<(), String> {
        let url = format!("{}{name}", self.base);
        let _ = tokio::fs::remove_file(dest).await;
        let mut last = String::new();
        for attempt in 0..=self.retries {
            match self.try_fetch(&url, dest, limit).await {
                Ok(()) => return Ok(()),
                Err(Fail::Fatal(e)) => return Err(format!("{name}: {e}")),
                Err(Fail::Retry(e)) => {
                    tracing::warn!(name, attempt, "download interrupted: {e}");
                    last = e;
                    tokio::time::sleep(std::time::Duration::from_millis(500 << attempt.min(4))).await;
                }
            }
        }
        Err(format!("{name}: {last} (after {} retries)", self.retries))
    }
    fn location(&self) -> String {
        self.base.clone()
    }
}

/// Base URL of a configured channel (validated by config::validate).
pub fn override_url(u: &UpdateChannel) -> String {
    let p = u.prefix.trim_matches('/');
    if p.is_empty() { format!("https://{}/", u.endpoint) } else { format!("https://{}/{p}/", u.endpoint) }
}

/// Channel from NodeConfig: https only, trusting exactly its own CA.
pub fn channel_from_config(u: &UpdateChannel) -> Result<Arc<dyn Channel>, String> {
    if u.ca_pem.trim().is_empty() {
        return Err("update_channel.ca_pem required".into());
    }
    HttpChannel::new(&override_url(u), Some(u.ca_pem.as_bytes())).map(|c| Arc::new(c) as Arc<dyn Channel>)
}

/// Channel configured in the image: `/usr/lib/foil-agent/channel`, one line —
/// an absolute directory path (local mirror) or an http(s) URL. For https the
/// CA is `/usr/lib/foil-agent/channel-ca.pem`, else the system bundle.
pub fn channel_from_image(path: &Path) -> Option<Arc<dyn Channel>> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.lines().next().unwrap_or("").trim().to_string();
    if s.starts_with('/') {
        return Some(Arc::new(DirChannel(PathBuf::from(s))));
    }
    let ca = std::fs::read(path.with_file_name("channel-ca.pem"))
        .or_else(|_| std::fs::read("/etc/ssl/certs/ca-certificates.crt"))
        .ok();
    match HttpChannel::new(&s, ca.as_deref()) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            tracing::error!("release channel: {e}");
            None
        }
    }
}

// ------------------------------------------------------------- platform

/// What the stager needs from the node; mocked in tests.
#[tonic::async_trait]
pub trait Platform: Send + Sync {
    /// Current boot confirmed (boot-complete) — decision 0002 rule 2.
    async fn boot_confirmed(&self) -> bool;
    /// Write the verified release from `staging` into the inactive slot.
    async fn install(&self, staging: &Path, version: &str) -> Result<(), String>;
    async fn slots(&self) -> Vec<Slot>;
    async fn reboot(&self) -> Result<(), String>;
    /// Image unit `foil-var-epoch@<op>-<version>` (op: enroll | raise): the
    /// unit does all key work and checks the release itself; the agent passes
    /// only the version. Never Running.
    async fn var_epoch(&self, op: &str, version: &str) -> KeyOutcome;
    /// Image unit `foil-rollback@<version>`: takes the booted, committed
    /// release out of systemd-boot's choice (Rollback RPC). Ok = job "done".
    async fn abandon(&self, version: &str) -> Result<(), String>;
}

/// Result of one var-epoch unit run.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyOutcome {
    pub phase: KeyOpPhase,
    pub detail: String,
}

/// Map the unit's job result (JobRemoved) and its result file
/// (`result=ok|noop|refused|error`, `detail=...`) to an outcome. Pure, for tests.
pub fn key_outcome(job: &str, file: Option<&str>) -> KeyOutcome {
    let (mut res, mut detail) = (String::new(), String::new());
    for l in file.unwrap_or("").lines() {
        if let Some(v) = l.strip_prefix("result=") {
            res = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("detail=") {
            detail = v.chars().filter(|c| !c.is_control()).take(512).collect();
        }
    }
    let phase = match (job, res.as_str()) {
        ("done", "ok") => KeyOpPhase::Done,
        ("done", "noop") => KeyOpPhase::Skipped,
        ("done", "") => {
            detail = "unit done, no result file".into();
            KeyOpPhase::Done
        }
        ("done", other) => {
            detail = format!("unit done but result={other}: {detail}");
            KeyOpPhase::Failed
        }
        (j, r) => {
            if detail.is_empty() {
                detail = format!("job {j}");
            } else if !r.is_empty() {
                detail = format!("{r}: {detail}");
            }
            KeyOpPhase::Failed
        }
    };
    KeyOutcome { phase, detail }
}

#[derive(Clone)]
pub struct Policy {
    pub image_id: String,
    pub booted: String,
    /// Floor built into the booted image (os-release FOILBIRD_MIN_VERSION).
    pub min_version: String,
    /// The image's node state (/var/lib/foilbird): `min_version` written by the
    /// raise unit, `committed/<v>`, `var-epochs`. None in unit tests without it.
    pub foilbird_state: Option<PathBuf>,
    pub keyring: Arc<Vec<u8>>,
    /// Upper bound of one release file.
    pub max_file: u64,
    /// FOILBIRD_PCR_EPOCH of the booted release (os-release); None = not set.
    pub booted_epoch: Option<u32>,
    /// /var is a LUKS2 device (GetInfo.var_protection). With no `var-epochs`
    /// this tells "not encrypted" from "encrypted before var-epoch".
    pub var_luks2: bool,
}

/// /var epoch guard of Rollback and StageUpdate.
#[derive(Debug, PartialEq)]
pub enum EpochGuard {
    /// The target's epoch has a key slot, enroll will add a newer one, or /var is not LUKS2.
    Pass,
    /// Not checked: /var is LUKS2 but `var-epochs` is absent or empty. The caller logs a WARN and returns the text.
    Unchecked(String),
    /// The target would not open /var: refuse before any action.
    Refuse(String),
}

impl Policy {
    /// Anti-rollback floor: max(/var/lib/foilbird/min_version, image floor).
    /// Read on every use: the raise unit changes it while the agent runs.
    pub fn floor(&self) -> String {
        let f = self
            .foilbird_state
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join("min_version")).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| valid_version(s))
            .unwrap_or_default();
        let img = if self.min_version.is_empty() { "0".to_string() } else { self.min_version.clone() };
        if vercmp(&f, &img) == Ordering::Greater { f } else { img }
    }

    /// Commit marker of a release (`/var/lib/foilbird/committed/<v>`, written after bless): mtime.
    pub fn committed_at(&self, version: &str) -> Option<i64> {
        let m = std::fs::metadata(self.foilbird_state.as_ref()?.join("committed").join(version)).ok()?;
        m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
    }

    /// Epochs with a live key slot (`var-epochs`, one line "4 5").
    pub fn enrolled(&self) -> Vec<u32> {
        self.var_epochs().unwrap_or_default()
    }

    /// `var-epochs` as written by the image units; None = no such file.
    pub fn var_epochs(&self) -> Option<Vec<u32>> {
        self.foilbird_state
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join("var-epochs")).ok())
            .map(|s| s.split_whitespace().filter_map(|x| x.parse().ok()).collect())
    }

    /// Will `what` (a release) open /var? Its epoch must have a slot in
    /// `var-epochs`. `allow_newer` (StageUpdate): an epoch newer than the booted
    /// one passes, the enroll unit adds its slot; an older one cannot be
    /// re-enrolled (the unit refuses it). `epoch` is read only when the check
    /// applies (it reads the UKI); its signature is not checked here: the guard
    /// can only refuse, and the firmware rejects a forged UKI.
    pub fn epoch_guard(&self, what: &str, allow_newer: bool, epoch: impl FnOnce() -> Result<Option<u32>, String>) -> EpochGuard {
        let list = self.var_epochs().filter(|l| !l.is_empty());
        let Some(list) = list else {
            return if self.var_luks2 {
                EpochGuard::Unchecked(format!(
                    "epoch of {what} not checked: /var is LUKS2 but var-epochs is absent or empty (encrypted before var-epoch)"
                ))
            } else {
                EpochGuard::Pass
            };
        };
        let slots = list.iter().map(u32::to_string).collect::<Vec<_>>().join(" ");
        let e = match epoch() {
            Ok(Some(e)) => e,
            Ok(None) => return EpochGuard::Refuse(format!("EPOCH_NOT_ENROLLED: {what} has no FOILBIRD_PCR_EPOCH in its UKI .osrel; /var key slots: epochs {slots}")),
            Err(x) => return EpochGuard::Refuse(format!("EPOCH_NOT_ENROLLED: epoch of {what} unknown ({x}); /var key slots: epochs {slots}")),
        };
        if list.contains(&e) || (allow_newer && self.booted_epoch.is_some_and(|b| e > b)) {
            return EpochGuard::Pass;
        }
        EpochGuard::Refuse(format!(
            "EPOCH_NOT_ENROLLED: {what} has epoch {e}, /var has key slots only for epochs {slots}; it would not open /var"
        ))
    }
}

// ------------------------------------------------------------- stager

#[derive(Default)]
pub struct UpdateState {
    pub stage: Option<StageStatus>,
    pub seq: u64,
    pub enroll: Option<KeyOperation>,
    pub raise: Option<KeyOperation>,
}

impl UpdateState {
    pub fn busy(&self) -> bool {
        self.stage.as_ref().is_some_and(|s| {
            matches!(
                StagePhase::try_from(s.phase),
                Ok(StagePhase::Downloading | StagePhase::Verifying | StagePhase::Enrolling | StagePhase::Installing)
            )
        })
    }
    pub fn staged_version(&self) -> Option<String> {
        self.stage
            .as_ref()
            .filter(|s| s.phase == StagePhase::Staged as i32)
            .and_then(|s| s.target.as_ref().map(|v| v.image_version.clone()))
    }
}

/// NodeConfig.update_channel in effect: None = use the image channel;
/// Some(Err) = configured but unusable (StageUpdate refuses, no fallback to
/// the image channel: the controller asked for another server).
pub type ChannelOverride = std::sync::Mutex<Option<Result<Arc<dyn Channel>, String>>>;

pub struct Stager {
    /// Channel built into the image (default).
    pub channel: Option<Arc<dyn Channel>>,
    pub channel_override: ChannelOverride,
    pub platform: Arc<dyn Platform>,
    pub policy: Policy,
    pub staging_root: PathBuf,
    pub state: Arc<Mutex<UpdateState>>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn key_op(version: &str, phase: KeyOpPhase, detail: &str) -> KeyOperation {
    KeyOperation { version: Some(Version { image_version: version.into() }), phase: phase as i32, detail: detail.into(), at_unix: now_unix() }
}

/// RaiseMinVersion refusals (FAILED_PRECONDITION, nothing started).
#[derive(Debug, PartialEq)]
pub enum RaiseRefusal {
    NotBooted(String),
    NotCommitted(String),
    Busy(String),
}

/// Synchronous refusals (the RPC fails, the status records why).
pub enum Refusal {
    Busy,
    Invalid(String),
    Policy(StageError, String),
}

fn status(op: &str, target: &str, phase: StagePhase, error: StageError, detail: impl Into<String>) -> StageStatus {
    StageStatus {
        operation_id: op.into(),
        target: Some(Version { image_version: target.into() }),
        phase: phase as i32,
        error: error as i32,
        detail: detail.into(),
    }
}

fn audit(op: &str, target: &str, result: &str, detail: &str) {
    tracing::warn!(target: "audit", op, version = target, result, detail, "stage-update");
}

impl Stager {
    /// Apply NodeConfig.update_channel (None = back to the image channel).
    pub fn set_override(&self, u: Option<&UpdateChannel>) {
        let v = u.map(|u| channel_from_config(u).inspect_err(|e| tracing::error!("update_channel: {e}")));
        let loc = u.map(override_url).unwrap_or_else(|| "image".into());
        tracing::warn!(target: "audit", channel = %loc, ok = v.as_ref().is_none_or(|r| r.is_ok()), "release channel");
        *self.channel_override.lock().unwrap() = v;
    }

    /// Channel for the next operation, and what to report about it.
    pub fn current_channel(&self) -> (Option<Arc<dyn Channel>>, ChannelInfo) {
        let info = |o: ChannelOrigin, c: Option<&Arc<dyn Channel>>, e: &str| ChannelInfo {
            origin: o as i32,
            location: c.map(|c| c.location()).unwrap_or_default(),
            error: e.into(),
        };
        match &*self.channel_override.lock().unwrap() {
            Some(Ok(c)) => (Some(c.clone()), info(ChannelOrigin::Config, Some(c), "")),
            Some(Err(e)) => (None, info(ChannelOrigin::Config, None, e)),
            None => match &self.channel {
                Some(c) => (Some(c.clone()), info(ChannelOrigin::Image, Some(c), "")),
                None => (None, info(ChannelOrigin::None, None, "")),
            },
        }
    }

    /// Validate the request and start the operation in the background.
    pub async fn start(self: &Arc<Self>, target: &str) -> Result<String, Refusal> {
        if !valid_version(target) {
            return Err(Refusal::Invalid("version: [A-Za-z0-9._~+-]{1,64}".into()));
        }
        let mut st = self.state.lock().await;
        if st.busy() {
            return Err(Refusal::Busy);
        }
        st.seq += 1;
        let op = format!("stage-{}-{}", st.seq, std::process::id());
        // A refusal is audited and returned; it does not replace the status
        // of the current (possibly staged) operation.
        let refuse = |_st: &mut UpdateState, e: StageError, d: String| {
            audit(&op, target, e.as_str_name(), &d);
            Err(Refusal::Policy(e, d))
        };
        if target == self.policy.booted {
            return Err(Refusal::Invalid(format!("{target} is the booted version")));
        }
        let floor = self.policy.floor();
        if vercmp(target, &floor) == Ordering::Less {
            let d = format!("{target} is below the minimum version {floor}");
            return refuse(&mut st, StageError::BelowMinVersion, d);
        }
        // systemd-boot picks the newest entry, so an older release
        // staged as A/B would not boot (the newer booted one wins, reported as
        // rollback NotSelected) and the reboot is wasted. Back is Rollback only;
        // a downgrade through the channel is v1. Checked after the floor: below
        // the floor Rollback is no answer either.
        if vercmp(target, &self.policy.booted) == Ordering::Less {
            let d = format!("{target} is older than the booted {}; StageUpdate only moves forward, use Rollback", self.policy.booted);
            return refuse(&mut st, StageError::OlderThanBooted, d);
        }
        if st.staged_version().is_some() || !self.platform.boot_confirmed().await {
            return refuse(&mut st, StageError::NotCommitted, "previous update not committed".into());
        }
        let (ch, info) = self.current_channel();
        let Some(ch) = ch else {
            let d = if info.error.is_empty() { "no release channel configured in the image".into() } else { format!("update_channel: {}", info.error) };
            return refuse(&mut st, StageError::Download, d);
        };
        st.stage = Some(status(&op, target, StagePhase::Downloading, StageError::None, ""));
        drop(st);
        tracing::info!(op, channel = %info.location, "stage-update channel");
        let me = Arc::clone(self);
        let (op2, t2) = (op.clone(), target.to_string());
        tokio::spawn(async move { me.run(ch.as_ref(), &op2, &t2).await });
        Ok(op)
    }

    async fn set(&self, op: &str, target: &str, phase: StagePhase, err: StageError, detail: &str) {
        self.state.lock().await.stage = Some(status(op, target, phase, err, detail));
    }

    async fn run(&self, ch: &dyn Channel, op: &str, target: &str) {
        let dir = self.staging_root.join(format!("{target}.partial"));
        let res = self.stage(ch, op, target, &dir).await;
        match res {
            Ok(warn) => {
                audit(op, target, "STAGED", &warn);
                self.set(op, target, StagePhase::Staged, StageError::None, &warn).await;
            }
            Err((e, d)) => {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                audit(op, target, e.as_str_name(), &d);
                self.set(op, target, StagePhase::Failed, e, &d).await;
            }
        }
    }

    async fn stage(&self, ch: &dyn Channel, op: &str, target: &str, dir: &Path) -> Result<String, (StageError, String)> {
        let dl = |e: String| (StageError::Download, e);
        let _ = tokio::fs::remove_dir_all(dir).await;
        tokio::fs::create_dir_all(dir).await.map_err(|e| dl(e.to_string()))?;

        // 1. signed manifest
        ch.fetch(MANIFEST, &dir.join(MANIFEST), MAX_MANIFEST).await.map_err(dl)?;
        ch.fetch(MANIFEST_SIG, &dir.join(MANIFEST_SIG), 64 * 1024).await.map_err(dl)?;
        self.set(op, target, StagePhase::Verifying, StageError::None, "manifest").await;
        let manifest = tokio::fs::read(dir.join(MANIFEST)).await.map_err(|e| dl(e.to_string()))?;
        let sig = tokio::fs::read(dir.join(MANIFEST_SIG)).await.map_err(|e| dl(e.to_string()))?;
        verify_signature(&self.policy.keyring, &manifest, &sig).map_err(|e| (StageError::BadSignature, e))?;
        let text = String::from_utf8(manifest).map_err(|_| (StageError::BadSignature, "manifest not UTF-8".into()))?;
        let entries = parse_manifest(&text).map_err(|e| (StageError::Incomplete, e))?;
        let files = select(&entries, &self.policy.image_id, target).map_err(|e| (e, format!("release {target}")))?;

        // 2. every file, hash checked while it is still in staging
        self.set(op, target, StagePhase::Downloading, StageError::None, "files").await;
        for f in &files {
            let p = dir.join(&f.name);
            ch.fetch(&f.name, &p, self.policy.max_file).await.map_err(dl)?;
            let got = sha256_file(&p).await.map_err(|e| dl(e.to_string()))?;
            if got != f.sha256 {
                return Err((StageError::HashMismatch, format!("{}: sha256 {got}, manifest {}", f.name, f.sha256)));
            }
        }

        // 3. the target's epoch must open /var (a slot, or a newer epoch enroll adds), before anything is changed
        let uki = dir.join(format!("{}_{target}.efi", self.policy.image_id));
        let policy = self.policy.clone();
        let what = format!("release {target}");
        let g = tokio::task::spawn_blocking(move || {
            policy.epoch_guard(&what, true, || std::fs::read(&uki).map_err(|e| e.to_string()).and_then(|d| crate::rollback::uki_epoch(&d)))
        })
        .await
        .map_err(|e| (StageError::Install, e.to_string()))?;
        let warn = match g {
            EpochGuard::Pass => String::new(),
            EpochGuard::Refuse(d) => return Err((StageError::EpochNotEnrolled, d)),
            EpochGuard::Unchecked(d) => {
                tracing::warn!(target: "audit", op, version = target, detail = %d, "var-epoch guard");
                d
            }
        };

        // 4. only now the inactive slot is touched
        let ready = self.staging_root.join(target);
        let _ = tokio::fs::remove_dir_all(&ready).await;
        tokio::fs::rename(dir, &ready).await.map_err(|e| (StageError::Install, e.to_string()))?;
        // `current` points the image's staged sysupdate component at it
        let cur = self.staging_root.join("current");
        let _ = tokio::fs::remove_file(&cur).await;
        tokio::fs::symlink(target, &cur).await.map_err(|e| (StageError::Install, e.to_string()))?;
        // 5. /var key slot for the target's PCR epoch, before the slot is written: a failure leaves no new UKI on the ESP.
        // The unit re-checks the release itself (copy, signature, hash); it decides whether a new slot is needed.
        self.set(op, target, StagePhase::Enrolling, StageError::None, "").await;
        self.state.lock().await.enroll = Some(key_op(target, KeyOpPhase::Running, ""));
        let o = self.platform.var_epoch("enroll", target).await;
        tracing::warn!(target: "audit", op, version = target, phase = o.phase.as_str_name(), detail = %o.detail, "var-epoch enroll");
        self.state.lock().await.enroll = Some(key_op(target, o.phase, &o.detail));
        if o.phase == KeyOpPhase::Failed {
            let _ = tokio::fs::remove_file(&cur).await;
            let _ = tokio::fs::remove_dir_all(&ready).await;
            return Err((StageError::Enroll, o.detail));
        }
        self.set(op, target, StagePhase::Installing, StageError::None, "").await;
        self.platform.install(&ready, target).await.map_err(|e| (StageError::Install, e))?;
        Ok(warn)
    }
}

impl Stager {
    /// RaiseMinVersion: only facts of the node are checked (booted = expected,
    /// commit marker, no update in progress); soak and SECURITY are the
    /// controller's policy. The image's raise unit wipes older epochs and
    /// writes the floor; the agent never writes it. Idempotent: the unit
    /// answers noop when there is nothing to do.
    pub async fn raise(&self, expect_booted: &str) -> Result<KeyOperation, RaiseRefusal> {
        let booted = self.policy.booted.clone();
        if expect_booted != booted {
            return Err(RaiseRefusal::NotBooted(format!("booted version is {booted}, expected {expect_booted}")));
        }
        if self.policy.committed_at(&booted).is_none() {
            return Err(RaiseRefusal::NotCommitted(format!("release {booted} is not committed (no commit marker)")));
        }
        {
            let mut st = self.state.lock().await;
            if st.busy() {
                return Err(RaiseRefusal::Busy("an update is being staged".into()));
            }
            if st.raise.as_ref().is_some_and(|r| r.phase == KeyOpPhase::Running as i32) {
                return Err(RaiseRefusal::Busy("a raise is running".into()));
            }
            st.raise = Some(key_op(&booted, KeyOpPhase::Running, ""));
        }
        let before = self.policy.floor();
        let o = self.platform.var_epoch("raise", &booted).await;
        let after = self.policy.floor();
        tracing::warn!(target: "audit", version = %booted, phase = o.phase.as_str_name(), floor_before = %before, floor_after = %after, detail = %o.detail, "var-epoch raise");
        let r = key_op(&booted, o.phase, &o.detail);
        self.state.lock().await.raise = Some(r.clone());
        Ok(r)
    }
}

pub async fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = tokio::fs::File::open(p).await?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// an error with a source, as the client nests them (hyper_util -> hyper -> io -> rustls)
    #[derive(Debug)]
    struct Wrap(&'static str, Box<dyn std::error::Error + Send + Sync + 'static>);
    impl std::fmt::Display for Wrap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Wrap {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.1)
        }
    }

    /// A name that does not resolve (.invalid never does): the connector's "dns error" is retried (availability, not
    /// trust), the stage then fails after the retries with the kind named.
    #[tokio::test]
    async fn unresolvable_name_is_retried() {
        let ch = HttpChannel::new("http://foil-test.invalid/foilbird/", None).unwrap();
        let dest = std::env::temp_dir().join(format!("foil-dns-{}", std::process::id()));
        let e = ch.fetch("SHA256SUMS", &dest, 1 << 20).await.unwrap_err();
        assert!(e.contains("[transport: dns]") && e.contains("(after 3 retries)"), "{e}");
    }

    /// request_failure: every kind of error -> Retry or Fatal (strict, fail-closed)
    #[test]
    fn request_failure_table() {
        use rustls::{AlertDescription as A, CertificateError as C, PeerIncompatible as P};
        use std::io::{Error as Io, ErrorKind as K};
        let tls = |e: rustls::Error| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(Wrap("client error (Connect)", Box::new(Io::new(K::InvalidData, e))))
        };
        let io = |k: K| -> Box<dyn std::error::Error + Send + Sync> { Box::new(Wrap("client error (Connect)", Box::new(Io::new(k, "x")))) };
        let cases: Vec<(&str, Box<dyn std::error::Error + Send + Sync>, bool)> = vec![
            // TLS said it: Fatal
            ("unknown CA", tls(rustls::Error::InvalidCertificate(C::UnknownIssuer)), false),
            ("expired", tls(rustls::Error::InvalidCertificate(C::Expired)), false),
            ("wrong name", tls(rustls::Error::InvalidCertificate(C::NotValidForName)), false),
            ("revoked", tls(rustls::Error::InvalidCertificate(C::Revoked)), false),
            ("certificate refused by the verifier (pin)", tls(rustls::Error::InvalidCertificate(C::ApplicationVerificationFailure)), false),
            ("alert from the server", tls(rustls::Error::AlertReceived(A::HandshakeFailure)), false),
            ("no common cipher", tls(rustls::Error::PeerIncompatible(P::NoCipherSuitesInCommon)), false),
            ("no common version", tls(rustls::Error::PeerIncompatible(P::ServerDoesNotSupportTls12Or13)), false),
            ("protocol error", tls(rustls::Error::DecryptError), false),
            // the transport: Retry
            ("refused", io(K::ConnectionRefused), true),
            ("reset", io(K::ConnectionReset), true),
            ("aborted", io(K::ConnectionAborted), true),
            ("EOF before the handshake completed", io(K::UnexpectedEof), true),
            ("connect or handshake timeout", io(K::TimedOut), true),
            // TLS and a reset in one chain: what TLS said wins
            ("reset wrapping a TLS error", Box::new(Wrap("x", Box::new(Io::new(K::ConnectionReset, rustls::Error::InvalidCertificate(C::UnknownIssuer))))), false),
            // anything else: Fatal
            ("name resolution, temporary (the connector's \"dns error\")", Box::new(Wrap("client error (Connect)", Box::new(Wrap("dns error", Box::new(Io::other("Temporary failure in name resolution")))))), true),
            ("name resolution, no such name", Box::new(Wrap("client error (Connect)", Box::new(Wrap("dns error", Box::new(Io::other("Name or service not known")))))), true),
            ("permission denied", io(K::PermissionDenied), false),
            ("other io", io(K::Other), false),
            ("unknown error type", Box::new(Wrap("something new", Box::new(std::fmt::Error))), false),
        ];
        for (what, e, retry) in &cases {
            let got = matches!(request_failure(e.as_ref()), Fail::Retry(_));
            assert_eq!(got, *retry, "{what}: retry={got}, want {retry}");
        }
    }

    #[test]
    fn version_order() {
        use Ordering::*;
        for (a, b, o) in [
            ("2", "10", Less),
            ("1.10", "1.9", Greater),
            ("2026.11.15.1", "2026.11.15", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0", Equal),
            ("01", "1", Equal),
            ("1a", "1", Greater),
        ] {
            assert_eq!(vercmp(a, b), o, "{a} vs {b}");
        }
    }

    #[test]
    fn manifest_and_selection() {
        let h = "a".repeat(64);
        let m = format!(
            "{h}  foilbird_2.efi\n{h}  foilbird_2.usr-x86-64.1234.raw.zst\n{h}  foilbird_2.usr-x86-64-verity.5678.raw.zst\n\
             {h}  foilbird_2.usr-x86-64-verity-sig.9abc.raw.zst\n{h}  foilbird_3.efi\n{h}  foilbird_20.efi\n"
        );
        let e = parse_manifest(&m).unwrap();
        assert_eq!(select(&e, "foilbird", "2").unwrap().len(), 4);
        assert_eq!(select(&e, "foilbird", "3").unwrap_err(), StageError::Incomplete);
        assert_eq!(select(&e, "foilbird", "4").unwrap_err(), StageError::NotInChannel);
        assert_eq!(versions(&e, "foilbird"), vec!["2", "3", "20"]);
        assert!(parse_manifest(&format!("{h}  ../etc/passwd\n")).is_err());
        assert!(parse_manifest("zz  a\n").is_err());
    }

    #[test]
    fn key_outcomes() {
        use KeyOpPhase::*;
        assert_eq!(key_outcome("done", Some("result=ok\ndetail=epoch 2 of release 2 enrolled\n")).phase, Done);
        assert_eq!(key_outcome("done", Some("result=noop\ndetail=already has a key slot\n")).phase, Skipped);
        let o = key_outcome("failed", Some("result=refused\ndetail=release 1 is not committed\n"));
        assert_eq!((o.phase, o.detail.as_str()), (Failed, "refused: release 1 is not committed"));
        assert_eq!(key_outcome("failed", None), KeyOutcome { phase: Failed, detail: "job failed".into() });
        assert_eq!(key_outcome("done", Some("result=error\ndetail=x\n")).phase, Failed);
        assert_eq!(key_outcome("done", None).phase, Done);
        assert!(!key_outcome("failed", Some("result=error\ndetail=a\u{1b}[31mb\n")).detail.contains('\u{1b}'));
    }

    #[test]
    fn floor_from_file_and_image() {
        let d = std::env::temp_dir().join(format!("foil-floor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("committed")).unwrap();
        let mut p = Policy { image_id: "x".into(), booted: "2".into(), min_version: "1".into(), foilbird_state: Some(d.clone()), keyring: Arc::new(vec![]), max_file: 1, booted_epoch: Some(5), var_luks2: false };
        assert_eq!(p.floor(), "1");
        std::fs::write(d.join("min_version"), "2\n").unwrap();
        assert_eq!(p.floor(), "2");
        p.min_version = "3".into();
        assert_eq!(p.floor(), "3", "image floor wins when higher");
        std::fs::write(d.join("min_version"), "../9\n").unwrap();
        assert_eq!(p.floor(), "3", "garbage in the file is ignored");
        assert!(p.committed_at("2").is_none());
        std::fs::write(d.join("committed/2"), "").unwrap();
        assert!(p.committed_at("2").is_some());
        std::fs::write(d.join("var-epochs"), "4 5\n").unwrap();
        assert_eq!(p.enrolled(), vec![4, 5]);
        p.foilbird_state = None;
        assert_eq!(p.floor(), "3");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn epoch_guard_cases() {
        use EpochGuard::*;
        let d = std::env::temp_dir().join(format!("foil-epguard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut p = Policy { image_id: "x".into(), booted: "3".into(), min_version: "1".into(), foilbird_state: Some(d.clone()), keyring: Arc::new(vec![]), max_file: 1, booted_epoch: Some(2), var_luks2: true };
        let refused = |g: EpochGuard| matches!(g, Refuse(ref t) if t.starts_with("EPOCH_NOT_ENROLLED"));
        // T20b run 1 after raise: only epoch 2 left, release 1 is epoch 1
        std::fs::write(d.join("var-epochs"), "2\n").unwrap();
        assert!(refused(p.epoch_guard("release 1", false, || Ok(Some(1)))), "rollback to a wiped epoch");
        assert!(refused(p.epoch_guard("release 1", true, || Ok(Some(1)))), "stage of a wiped (older) epoch");
        assert_eq!(p.epoch_guard("release 4", true, || Ok(Some(3))), Pass, "stage: newer epoch, enroll adds it");
        assert!(refused(p.epoch_guard("release 4", false, || Ok(Some(3)))), "rollback cannot enroll");
        assert_eq!(p.epoch_guard("release 2", false, || Ok(Some(2))), Pass, "same epoch");
        assert!(refused(p.epoch_guard("release 1", false, || Ok(None))), "no epoch in .osrel");
        assert!(refused(p.epoch_guard("release 1", false, || Err("not a PE image".into()))));
        // before raise both epochs are live
        std::fs::write(d.join("var-epochs"), "1 2\n").unwrap();
        assert_eq!(p.epoch_guard("release 1", false, || Ok(Some(1))), Pass);
        // no list: LUKS2 -> unchecked with a warning; not LUKS2 -> pass, UKI not read
        for content in [None, Some("\n")] {
            let _ = std::fs::remove_file(d.join("var-epochs"));
            if let Some(c) = content {
                std::fs::write(d.join("var-epochs"), c).unwrap();
            }
            p.var_luks2 = true;
            assert!(matches!(p.epoch_guard("release 1", false, || panic!("read")), Unchecked(ref t) if t.contains("LUKS2")));
            p.var_luks2 = false;
            assert_eq!(p.epoch_guard("release 1", false, || panic!("read")), Pass);
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn escape() {
        assert_eq!(systemd_escape("2026.11.15.1"), "2026.11.15.1");
        assert_eq!(systemd_escape("1.0~rc1+b2"), "1.0\\x7erc1\\x2bb2");
    }

    #[test]
    fn version_syntax() {
        assert!(valid_version("2026.11.15.1"));
        assert!(!valid_version("../1"));
        assert!(!valid_version(""));
        assert!(!valid_version("1 2"));
    }
}
