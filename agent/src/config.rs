// SPDX-License-Identifier: Apache-2.0
//! Node configuration: strict validation, rendering into /run/foilbird/config/<name>
//! (same names and formats as the temporary credentials bridge), persistence.

use crate::pb::{ConfigError, HostEntry, Interface, K8sConfig, NodeConfig, NodeRole, RegistryHost, TaintEffect, UpdateChannel, interface};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const SCHEMA: u32 = 1;
const MAX_INTERFACES: usize = 16;
const MAX_LIST: usize = 32;
const MAX_LABELS: usize = 64;
const MAX_BRIDGE_FILE: u64 = 16 * 1024;

/// Bridge credential names = rendered file names.
pub const NODE_HOSTNAME: &str = "node.hostname";
pub const NODE_NETWORK: &str = "node.network";
pub const K8S_JOIN: &str = "k8s.join";
pub const K8S_LABELS: &str = "k8s.node-labels";
pub const K8S_TAINTS: &str = "k8s.node-taints";
/// Control plane v0: kubeadm init configuration and the operator's cluster CA (copied to /etc/kubernetes/pki by
/// foil-kubeadm-init.service right before kubeadm init; the agent itself cannot write /etc/kubernetes).
pub const K8S_INIT: &str = "k8s.init";
pub const K8S_CA_CRT: &str = "k8s.ca.crt";
pub const K8S_CA_KEY: &str = "k8s.ca.key";

/// File system locations. Overridable for tests (`FOILBIRD_ROOT` prefix).
#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,   // /run/foilbird/config
    pub networkd_dir: PathBuf, // /run/systemd/network
    pub state_dir: PathBuf,    // /var/lib/foil-agent
    pub credentials: PathBuf,  // /run/credentials/@system
    pub esp_bridge: PathBuf,   // /boot/loader/foilbird (temporary bridge, TEST)
    pub journal_roots: Vec<PathBuf>, // /var/log/journal, /run/log/journal
    pub run_dir: PathBuf,      // /run/foilbird
    pub timesyncd_dir: PathBuf, // /run/systemd/timesyncd.conf.d
    pub foilbird_state: PathBuf, // /var/lib/foilbird (image units: min_version, committed/<v>, var-epochs)
    pub sys_block: PathBuf,    // /sys/class/block (partition names, read only)
    /// false under a test root: no sethostname, no D-Bus calls.
    pub live: bool,
}

impl Paths {
    /// UKIs on the ESP (systemd-boot type #2 entries).
    pub fn esp_linux(&self) -> PathBuf {
        self.esp_bridge.parent().and_then(|p| p.parent()).map(|b| b.join("EFI/Linux")).unwrap_or_default()
    }

    pub fn from_env() -> Self {
        Self::with_root(PathBuf::from(std::env::var("FOILBIRD_ROOT").unwrap_or_else(|_| "/".into())))
    }

    pub fn with_root(root: PathBuf) -> Self {
        let live = root == Path::new("/");
        let p = |s: &str| root.join(s);
        Paths {
            config_dir: p("run/foilbird/config"),
            networkd_dir: p("run/systemd/network"),
            state_dir: p("var/lib/foil-agent"),
            credentials: p("run/credentials/@system"),
            esp_bridge: p("boot/loader/foilbird"),
            journal_roots: vec![p("var/log/journal"), p("run/log/journal")],
            run_dir: p("run/foilbird"),
            timesyncd_dir: p("run/systemd/timesyncd.conf.d"),
            foilbird_state: p("var/lib/foilbird"),
            sys_block: p("sys/class/block"),
            live,
        }
    }
}

// ------------------------------------------------------------- validation

struct V(Vec<ConfigError>);
impl V {
    fn err(&mut self, field: impl Into<String>, msg: impl Into<String>) {
        self.0.push(ConfigError { field: field.into(), message: msg.into() });
    }
}

pub fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn valid_dns_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    })
}

fn valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_ifname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = s.split_once('/')?;
    let ip: IpAddr = a.parse().ok()?;
    if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let p: u8 = p.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (p <= max).then_some((ip, p))
}

fn valid_endpoint(s: &str) -> bool {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((h, p)) => (h, p),
            None => return false,
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => return false,
        }
    };
    let port_ok = !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().map(|p| p > 0).unwrap_or(false);
    let host_ok = if s.starts_with('[') {
        host.parse::<Ipv6Addr>().is_ok()
    } else {
        host.parse::<Ipv4Addr>().is_ok() || valid_dns_name(host)
    };
    port_ok && host_ok
}

/// "host" or "host:port" (DNS name, IPv4, [IPv6]); port 1..65535.
pub fn valid_server(s: &str) -> bool {
    if valid_endpoint(s) {
        return true;
    }
    match s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().is_ok(),
        None => !s.contains(':') && (s.parse::<Ipv4Addr>().is_ok() || valid_dns_name(s)),
    }
}

/// URL path prefix: "/a/b/", [A-Za-z0-9._~/-], no "..", no "//", at most 200.
pub fn valid_prefix(s: &str) -> bool {
    s.len() <= 200
        && (s.is_empty() || s.starts_with('/'))
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b))
        && !s.split('/').any(|seg| seg == ".." || seg == ".")
        && !s.contains("//")
}

const MAX_CA_PEM: usize = 64 * 1024;
const MAX_CA_CERTS: usize = 16;

/// PEM with 1..16 X.509 certificates and nothing secret; returns their DER.
pub fn parse_ca_pem(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    if pem.len() > MAX_CA_PEM {
        return Err(format!("larger than {MAX_CA_PEM} bytes"));
    }
    if pem.contains("PRIVATE KEY") {
        return Err("must not contain a private key".into());
    }
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let c = c.map_err(|e| format!("PEM: {e}"))?;
        x509_parser::parse_x509_certificate(&c).map_err(|e| format!("certificate {}: {e}", out.len()))?;
        out.push(c.to_vec());
    }
    if out.is_empty() || out.len() > MAX_CA_CERTS {
        return Err(format!("1..{MAX_CA_CERTS} certificates required"));
    }
    Ok(out)
}

fn validate_update_channel(v: &mut V, u: &UpdateChannel) {
    if !valid_server(&u.endpoint) {
        v.err("update_channel.endpoint", "expected host[:port]; the scheme is always https");
    }
    if !valid_prefix(&u.prefix) {
        v.err("update_channel.prefix", "expected /dir/, [A-Za-z0-9._~/-], no '..'");
    }
    if let Err(e) = parse_ca_pem(&u.ca_pem) {
        v.err("update_channel.ca_pem", e);
    }
}

const MAX_REGISTRIES: usize = 32;
const MAX_MIRRORS: usize = 8;

fn validate_registries(v: &mut V, regs: &[RegistryHost]) {
    if regs.len() > MAX_REGISTRIES {
        v.err("registries", format!("at most {MAX_REGISTRIES}"));
    }
    let mut seen = std::collections::HashSet::new();
    for (i, r) in regs.iter().enumerate() {
        let f = format!("registries[{i}]");
        // the name becomes a directory under certs.d: no '/', no "..", lower case
        if !valid_server(&r.registry) || r.registry != r.registry.to_ascii_lowercase() || r.registry.starts_with('.') {
            v.err(format!("{f}.registry"), "expected a lower-case host[:port], e.g. docker.io");
        } else if !seen.insert(r.registry.clone()) {
            v.err(format!("{f}.registry"), "duplicate");
        }
        if r.mirrors.len() > MAX_MIRRORS {
            v.err(format!("{f}.mirrors"), format!("at most {MAX_MIRRORS}"));
        }
        if r.mirrors.is_empty() && r.ca_pem.is_empty() {
            v.err(f.clone(), "mirrors or ca_pem required");
        }
        if !r.mirrors.is_empty() && !r.ca_pem.is_empty() {
            v.err(format!("{f}.ca_pem"), "the registry itself is not used when mirrors are set; give the CA per mirror");
        } else if !r.ca_pem.is_empty() {
            if let Err(e) = parse_ca_pem(&r.ca_pem) {
                v.err(format!("{f}.ca_pem"), e);
            }
        }
        for (j, m) in r.mirrors.iter().enumerate() {
            let mf = format!("{f}.mirrors[{j}]");
            if !valid_server(&m.endpoint) {
                v.err(format!("{mf}.endpoint"), "expected host[:port]; the scheme is always https");
            }
            if !valid_prefix(&m.prefix) || m.prefix == "/" {
                v.err(format!("{mf}.prefix"), "empty or /path, [A-Za-z0-9._~/-], no '..'");
            }
            if !m.ca_pem.is_empty() {
                if let Err(e) = parse_ca_pem(&m.ca_pem) {
                    v.err(format!("{mf}.ca_pem"), e);
                }
            }
        }
    }
}

const MAX_HOST_ENTRIES: usize = 64;
const MAX_HOSTNAMES: usize = 8;

fn validate_hosts(v: &mut V, hosts: &[HostEntry]) {
    if hosts.len() > MAX_HOST_ENTRIES {
        v.err("extra_host_entries", format!("at most {MAX_HOST_ENTRIES}"));
    }
    for (i, h) in hosts.iter().enumerate() {
        let f = format!("extra_host_entries[{i}]");
        if h.ip.parse::<IpAddr>().is_err() {
            v.err(format!("{f}.ip"), "expected an IPv4 or IPv6 address");
        }
        if h.hostnames.is_empty() || h.hostnames.len() > MAX_HOSTNAMES {
            v.err(format!("{f}.hostnames"), format!("1..{MAX_HOSTNAMES} names"));
        }
        for (j, n) in h.hostnames.iter().enumerate() {
            if !valid_dns_name(n) || *n != n.to_ascii_lowercase() || n == "localhost" {
                v.err(format!("{f}.hostnames[{j}]"), "expected a lower-case RFC 1123 name (not localhost)");
            }
        }
    }
}

const MAX_NTP_SERVERS: usize = 8;

fn validate_time(v: &mut V, servers: &[String]) {
    if servers.len() > MAX_NTP_SERVERS {
        v.err("time.servers", format!("at most {MAX_NTP_SERVERS}"));
    }
    for (i, s) in servers.iter().enumerate() {
        // all-numeric labels ("192.0.2.300") are a mistyped address, not a name
        let numeric = s.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
        let ok = s.parse::<IpAddr>().is_ok() || (!numeric && valid_dns_name(s) && *s == s.to_ascii_lowercase());
        if !ok {
            v.err(format!("time.servers[{i}]"), "expected an IPv4/IPv6 address or a lower-case DNS name, no port");
        }
        if servers[..i].contains(s) {
            v.err(format!("time.servers[{i}]"), "duplicate");
        }
    }
}

pub fn valid_token(s: &str) -> bool {
    let ok = |p: &str, n: usize| p.len() == n && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    matches!(s.split_once('.'), Some((a, b)) if ok(a, 6) && ok(b, 16))
}

fn valid_ca_hash(s: &str) -> bool {
    matches!(s.strip_prefix("sha256:"), Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

/// Kubernetes label key: optional DNS-subdomain prefix + "/" + name.
pub fn valid_label_key(s: &str) -> bool {
    let (prefix, name) = match s.split_once('/') {
        Some((p, n)) => (Some(p), n),
        None => (None, s),
    };
    prefix.is_none_or(valid_dns_name) && valid_label_name(name, false)
}

/// Label name or value: <=63, alphanumeric at ends, [-_.] inside.
pub fn valid_label_name(s: &str, allow_empty: bool) -> bool {
    if s.is_empty() {
        return allow_empty;
    }
    let b = s.as_bytes();
    s.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(c))
}

pub fn validate(c: &NodeConfig) -> Vec<ConfigError> {
    let mut v = V(Vec::new());
    if c.schema != SCHEMA {
        v.err("schema", format!("unsupported schema {}, expected {SCHEMA}", c.schema));
    }
    if !valid_hostname(&c.hostname) {
        v.err("hostname", "must be an RFC 1123 label: [a-z0-9-], 1..63 chars");
    }
    match &c.network {
        None => v.err("network", "required"),
        Some(n) => {
            if n.interfaces.is_empty() || n.interfaces.len() > MAX_INTERFACES {
                v.err("network.interfaces", format!("1..{MAX_INTERFACES} interfaces required"));
            }
            for (i, ifc) in n.interfaces.iter().enumerate() {
                validate_interface(&mut v, &format!("network.interfaces[{i}]"), ifc);
            }
        }
    }
    validate_role(&mut v, c);
    if let (Some(k), Ok(r @ (NodeRole::Worker | NodeRole::ControlPlane))) = (&c.k8s, NodeRole::try_from(c.role)) {
        validate_k8s(&mut v, k, r);
    }
    if let Some(u) = &c.update_channel {
        validate_update_channel(&mut v, u);
    }
    validate_registries(&mut v, &c.registries);
    validate_hosts(&mut v, &c.extra_host_entries);
    if let Some(t) = &c.time {
        validate_time(&mut v, &t.servers);
    }
    v.0
}

fn validate_interface(v: &mut V, f: &str, i: &Interface) {
    match &i.r#match {
        None => v.err(format!("{f}.match"), "mac_address or name required"),
        Some(interface::Match::MacAddress(m)) if !valid_mac(m) => {
            v.err(format!("{f}.mac_address"), "expected xx:xx:xx:xx:xx:xx")
        }
        Some(interface::Match::Name(n)) if !valid_ifname(n) => {
            v.err(format!("{f}.name"), "invalid interface name")
        }
        _ => {}
    }
    if i.dhcp4 && !i.addresses.is_empty() {
        v.err(f.to_string(), "dhcp4 and addresses are mutually exclusive");
    }
    if !i.dhcp4 && i.addresses.is_empty() {
        v.err(format!("{f}.addresses"), "static addresses required when dhcp4 is false");
    }
    if i.addresses.len() > MAX_LIST {
        v.err(format!("{f}.addresses"), "too many");
    }
    for (j, a) in i.addresses.iter().enumerate() {
        if parse_cidr(a).is_none() {
            v.err(format!("{f}.addresses[{j}]"), "expected CIDR, e.g. 192.0.2.10/24");
        }
    }
    if !i.gateway4.is_empty() && i.gateway4.parse::<Ipv4Addr>().is_err() {
        v.err(format!("{f}.gateway4"), "expected IPv4 address");
    }
    if !i.gateway6.is_empty() && i.gateway6.parse::<Ipv6Addr>().is_err() {
        v.err(format!("{f}.gateway6"), "expected IPv6 address");
    }
    if i.dns.len() > MAX_LIST || i.domains.len() > MAX_LIST {
        v.err(format!("{f}"), "too many dns servers or domains");
    }
    for (j, d) in i.dns.iter().enumerate() {
        if d.parse::<IpAddr>().is_err() {
            v.err(format!("{f}.dns[{j}]"), "expected IP address");
        }
    }
    for (j, d) in i.domains.iter().enumerate() {
        if !valid_dns_name(d) {
            v.err(format!("{f}.domains[{j}]"), "invalid domain");
        }
    }
    if i.mtu != 0 && !(576..=9216).contains(&i.mtu) {
        v.err(format!("{f}.mtu"), "0 or 576..9216");
    }
}

const MAX_INIT: usize = 64 * 1024;
const MAX_KEY_PEM: usize = 16 * 1024;

/// The node's role decides which k8s fields are allowed: a control plane (v0) runs kubeadm init, a worker joins.
pub fn is_control_plane(c: &NodeConfig) -> bool {
    c.role == NodeRole::ControlPlane as i32
}

/// Role of a config as the agent compares it between generations: UNSPECIFIED without k8s.
pub fn role(c: &NodeConfig) -> NodeRole {
    NodeRole::try_from(c.role).unwrap_or(NodeRole::Unspecified)
}

/// Role exactly when k8s is set: a node without Kubernetes (a profile without k8s) has no role, so UNSPECIFIED
/// is refused only together with k8s.
fn validate_role(v: &mut V, c: &NodeConfig) {
    match (NodeRole::try_from(c.role), &c.k8s) {
        (Err(_), _) => v.err("role", format!("unknown value {}", c.role)),
        (Ok(NodeRole::Unspecified), Some(_)) => v.err("role", "required with k8s: WORKER or CONTROL_PLANE"),
        (Ok(r), None) if r != NodeRole::Unspecified => v.err("role", "needs k8s (a node without Kubernetes has no role)"),
        _ => {}
    }
}

/// A config persisted before the role existed (schema 1, k8s set, role UNSPECIFIED): the role the agent used to
/// infer (init set = control plane, otherwise worker). In memory only: the file is not rewritten (ADR 0005), the next
/// ApplyConfig must carry the role. Returns whether the role was inferred.
pub fn infer_legacy_role(c: &mut NodeConfig) -> bool {
    let Some(k) = c.k8s.as_ref() else { return false };
    if c.schema != SCHEMA || c.role != NodeRole::Unspecified as i32 {
        return false;
    }
    let cp = k.init.as_ref().is_some_and(|i| !i.value.is_empty());
    c.role = if cp { NodeRole::ControlPlane } else { NodeRole::Worker } as i32;
    true
}

fn has_join(k: &K8sConfig) -> bool {
    !k.api_server_endpoint.is_empty() || k.bootstrap_token.as_ref().is_some_and(|t| !t.value.is_empty()) || !k.ca_cert_hashes.is_empty()
}

fn validate_k8s_init(v: &mut V, k: &K8sConfig) {
    if has_join(k) {
        v.err("k8s.api_server_endpoint", "join fields (api_server_endpoint, bootstrap_token, ca_cert_hashes) are for a WORKER, not a CONTROL_PLANE");
    }
    let init = k.init.as_ref().map(|i| i.value.as_str()).unwrap_or("");
    let kinds = |kind: &str| init.lines().any(|l| l.trim() == format!("kind: {kind}"));
    if init.is_empty() {
        v.err("k8s.init", "required for a CONTROL_PLANE");
    } else if init.len() > MAX_INIT || init.contains('\0') {
        v.err("k8s.init", format!("at most {MAX_INIT} bytes, no NUL"));
    } else if !kinds("InitConfiguration") || !kinds("ClusterConfiguration") || !init.lines().any(|l| l.trim() == "apiVersion: kubeadm.k8s.io/v1beta4") {
        v.err("k8s.init", "expected kubeadm.k8s.io/v1beta4 InitConfiguration and ClusterConfiguration");
    }
    if !init.is_empty() {
        if let Err(e) = check_kubelet_shutdown(init) {
            v.err("k8s.init", e);
        }
        if let Err(e) = check_bootstrap_ttl(init) {
            v.err("k8s.init", e);
        }
        if let Err(e) = check_apiserver_audit(init) {
            v.err("k8s.init", e);
        }
    }
    match parse_ca_pem(&k.cluster_ca_crt) {
        Ok(c) if c.len() == 1 => {}
        Ok(_) => v.err("k8s.cluster_ca_crt", "exactly one certificate"),
        Err(e) => v.err("k8s.cluster_ca_crt", e),
    }
    let key = k.cluster_ca_key.as_ref().map(|x| x.value.as_str()).unwrap_or("");
    let blocks = key.matches("-----BEGIN ").count();
    if key.len() > MAX_KEY_PEM || blocks != 1 || !key.trim_start().starts_with("-----BEGIN ") || !key.contains("PRIVATE KEY-----") || !key.trim_end().ends_with("-----") {
        v.err("k8s.cluster_ca_key", "expected one PEM private key");
    }
}

/// A Go duration of the kubelet configuration (`60s`, `1m`, `1m30s`, `"20s"`), in whole seconds; `None` for
/// anything else (fractions, ms/us/ns, a sign, garbage).
fn go_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim().trim_matches('"');
    if s == "0" {
        return Some(0);
    }
    let (mut total, mut num, mut any) = (0u64, String::new(), false);
    for ch in s.chars() {
        match ch {
            '0'..='9' => num.push(ch),
            'h' | 'm' | 's' if !num.is_empty() && num.len() <= 6 => {
                let n: u64 = num.parse().ok()?;
                total += n * match ch { 'h' => 3600, 'm' => 60, _ => 1 };
                num.clear();
                any = true;
            }
            _ => return None,
        }
    }
    (any && num.is_empty()).then_some(total)
}

/// Graceful node shutdown: the control plane's init configuration must carry a
/// `KubeletConfiguration` with `shutdownGracePeriod` > `shutdownGracePeriodCriticalPods` > 0. `kubeadm init` uploads
/// it as the ConfigMap `kubelet-config`, from which every joining node gets it. Without it the kubelet does not
/// take its logind inhibitor, and systemd stops all containers at once, waiting 90 s for each that does not exit.
/// Line based (top-level keys of that document), as the rest of the init checks.
fn check_kubelet_shutdown(init: &str) -> Result<(), String> {
    let mut docs = vec![Vec::new()];
    for l in init.lines() {
        if l.trim_end() == "---" {
            docs.push(Vec::new());
        } else {
            docs.last_mut().unwrap().push(l);
        }
    }
    let top = |d: &Vec<&str>, key: &str| -> Option<String> {
        d.iter().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')).map(|r| r.split('#').next().unwrap_or("").trim().to_string()))
    };
    let kc: Vec<_> = docs.iter().filter(|d| top(d, "kind").as_deref() == Some("KubeletConfiguration")).collect();
    let [d] = kc.as_slice() else {
        return Err("expected one KubeletConfiguration document (graceful node shutdown: shutdownGracePeriod, shutdownGracePeriodCriticalPods)".into());
    };
    if top(d, "apiVersion").as_deref() != Some("kubelet.config.k8s.io/v1beta1") {
        return Err("KubeletConfiguration: expected apiVersion kubelet.config.k8s.io/v1beta1".into());
    }
    let dur = |key: &str| top(d, key).as_deref().and_then(go_duration_secs);
    match (dur("shutdownGracePeriod"), dur("shutdownGracePeriodCriticalPods")) {
        (Some(g), Some(c)) if c > 0 && c < g => Ok(()),
        _ => Err("KubeletConfiguration: expected shutdownGracePeriod > shutdownGracePeriodCriticalPods > 0 (whole seconds, e.g. 60s / 20s)".into()),
    }
}

/// The image's kube-apiserver audit policy: Metadata for every request, Secrets, ConfigMaps, service account tokens,
/// TokenReviews and CSRs pinned at Metadata (no bodies), health and lease requests not logged. In /usr, so verity-signed.
pub const AUDIT_POLICY: &str = "/usr/lib/foilbird/kubernetes/audit-policy.yaml";

/// Entries of a list under `top:` -> `key:` of one YAML document, line based (like the other init checks): block
/// entries (`- name: x` + `  value: y`) or one simple flow mapping per entry (`- {name: x, value: y}`). Anything the line
/// reading could get wrong - anchors, aliases, tags, merge keys, nested flow, a flow list for the whole key - is an error.
/// `None` when `top` or `key` is absent.
fn yaml_list(d: &[&str], top: &str, key: &str) -> Option<Result<Vec<Vec<(String, String)>>, ()>> {
    let content = |l: &str| -> String {
        let l = l.trim_end();
        match l.find(" #") {
            Some(i) => l[..i].trim_end().to_string(),
            None if l.trim_start().starts_with('#') => String::new(),
            None => l.to_string(),
        }
    };
    let indent = |l: &str| l.len() - l.trim_start().len();
    let lines: Vec<String> = d.iter().map(|l| content(l)).filter(|c| !c.trim().is_empty()).collect();
    let t = lines.iter().position(|l| indent(l) == 0 && l.trim_end() == format!("{top}:"))?;
    // the block of `top`: until the next top-level line
    let block: Vec<&String> = lines[t + 1..].iter().take_while(|l| indent(l) > 0).collect();
    let ki = block.first().map(|l| indent(l))?;
    let k = block.iter().position(|l| indent(l) == ki && l.trim_start().split(':').next() == Some(key))?;
    let bad = || Some(Err(()));
    if !block[k].trim_start()[key.len() + 1..].trim().is_empty() {
        return bad(); // flow list or scalar for the whole key
    }
    let items: Vec<&&String> = block[k + 1..].iter().take_while(|l| indent(l) > ki || (indent(l) == ki && l.trim_start().starts_with('-'))).collect();
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    let Some(first) = items.first() else { return Some(Ok(out)) };
    let ii = indent(first);
    let kv = |s: &str| -> Option<(String, String)> {
        let (a, b) = s.split_once(':')?;
        let (a, b) = (a.trim(), b.trim().trim_matches('"').trim_matches('\''));
        (!a.is_empty() && !a.starts_with(['&', '*', '!', '<', '{', '[']) && !b.starts_with(['&', '*', '!', '{', '[', '|', '>'])).then(|| (a.to_string(), b.to_string()))
    };
    let mut key_col = 0;
    for l in items {
        let (ind, t) = (indent(l), l.trim_start());
        if ind == ii && t.starts_with('-') {
            let rest = t[1..].trim_start();
            out.push(Vec::new());
            if let Some(f) = rest.strip_prefix('{') {
                let Some(f) = f.strip_suffix('}') else { return bad() };
                if f.contains(['{', '[', '}', ']']) {
                    return bad();
                }
                for part in f.split(',') {
                    let Some(p) = kv(part) else { return bad() };
                    out.last_mut().unwrap().push(p);
                }
                key_col = usize::MAX; // a flow entry has no continuation lines
                continue;
            }
            if rest.is_empty() {
                return bad();
            }
            key_col = ind + (t.len() - rest.len());
            let Some(p) = kv(rest) else { return bad() };
            out.last_mut().unwrap().push(p);
        } else if ind == key_col {
            let Some(p) = kv(t) else { return bad() };
            out.last_mut().unwrap().push(p);
        } else {
            return bad(); // deeper nesting or a continuation of a flow entry
        }
    }
    Some(Ok(out))
}

/// kube-apiserver audit is on (Talos sets these flags in code): the control plane's ClusterConfiguration carries
/// `apiServer.extraArgs` `audit-policy-file` = the image's policy (no other policy: the image's is the reviewed one) and an
/// `audit-log-path` on the persistent /var, each once, and `apiServer.extraVolumes` that mount both into the static pod
/// (hostPath = mountPath; without them kube-apiserver does not start). Rotation flags are the operator's (README).
fn check_apiserver_audit(init: &str) -> Result<(), String> {
    const NEED: &str = "ClusterConfiguration apiServer: audit required (profiles/k8s-worker/README.md \"Control plane audit log\")";
    let mut docs = vec![Vec::new()];
    for l in init.lines() {
        if l.trim_end() == "---" {
            docs.push(Vec::new());
        } else {
            docs.last_mut().unwrap().push(l);
        }
    }
    let Some(d) = docs.iter().find(|d| d.iter().any(|l| l.trim_end() == "kind: ClusterConfiguration")) else {
        return Ok(()); // reported by the kind check
    };
    const STYLE: &str = "apiServer extraArgs/extraVolumes: block entries or one simple flow mapping per entry expected (no anchors, aliases, tags or nested flow)";
    let args = match yaml_list(d, "apiServer", "extraArgs") {
        None => return Err(format!("{NEED}: no apiServer.extraArgs with audit-policy-file and audit-log-path")),
        Some(Err(())) => return Err(STYLE.into()),
        Some(Ok(a)) => a,
    };
    let arg = |n: &str| -> Result<Option<String>, String> {
        let v: Vec<String> = args.iter().filter(|e| e.iter().any(|(k, v)| k == "name" && v == n)).filter_map(|e| e.iter().find(|(k, _)| k == "value").map(|(_, v)| v.clone())).collect();
        match v.as_slice() {
            [] => Ok(None),
            [x] => Ok(Some(x.clone())),
            _ => Err(format!("apiServer.extraArgs: {n} given more than once")),
        }
    };
    match arg("audit-policy-file")? {
        Some(p) if p == AUDIT_POLICY => {}
        Some(_) => return Err(format!("apiServer.extraArgs: audit-policy-file must be the image's policy {AUDIT_POLICY}")),
        None => return Err(format!("{NEED}: audit-policy-file missing")),
    }
    let log = match arg("audit-log-path")? {
        Some(p) if p.starts_with("/var/") && !p.ends_with('/') && !p.contains("/../") => p,
        Some(_) => return Err("apiServer.extraArgs: audit-log-path must be a file on the persistent /var (not stdout \"-\")".into()),
        None => return Err(format!("{NEED}: audit-log-path missing")),
    };
    let vols = match yaml_list(d, "apiServer", "extraVolumes") {
        None => Vec::new(),
        Some(Err(())) => return Err(STYLE.into()),
        Some(Ok(v)) => v,
    };
    let get = |e: &Vec<(String, String)>, k: &str| e.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let mounted = |path: &str| {
        vols.iter().any(|e| {
            let (h, m) = (get(e, "hostPath"), get(e, "mountPath"));
            h == m && !m.is_empty() && (path == m || path.starts_with(&format!("{}/", m.trim_end_matches('/'))))
        })
    };
    if !mounted(AUDIT_POLICY) {
        return Err(format!("apiServer.extraVolumes: mount the audit policy {AUDIT_POLICY} (hostPath = mountPath)"));
    }
    if !mounted(&log) {
        return Err("apiServer.extraVolumes: mount the directory of audit-log-path (hostPath = mountPath) so the log is on the node's /var".into());
    }
    Ok(())
}

/// Ceiling of a bootstrap token's ttl in the control plane's init configuration: 24 h, as kubeadm's
/// own default; the installation guide recommends 2 h. A token that never expires (ttl 0) is refused.
pub const MAX_BOOTSTRAP_TTL_SECS: u64 = 24 * 3600;

/// Join tokens of the control plane must expire: the InitConfiguration document carries `bootstrapTokens:` in
/// block style, and every entry exactly one `ttl:` with 0 < ttl <= 24h, no `expires:` (an absolute time cannot be
/// checked on a node whose clock is not synchronized yet). Line based like the rest of the init checks, so where a
/// ttl could hide from it - a flow sequence or mapping for the list or an entry, anchors, aliases, tags or a merge
/// key at the entry level - the init is refused ("block style expected") rather than guessed. Flow values of other
/// keys (`usages: [signing, authentication]`) are fine. Messages name the field and the rule, never a value.
fn check_bootstrap_ttl(init: &str) -> Result<(), String> {
    const BLOCK: &str = "bootstrapTokens: block style expected (a list of `- token: ...` entries; no flow style, anchors, aliases, tags or merge keys around ttl)";
    let content = |l: &str| -> String {
        // drop a comment that starts a word (" #"), keep quoted '#' in simple cases
        let l = l.trim_end();
        match l.find(" #") {
            Some(i) => l[..i].trim_end().to_string(),
            None if l.trim_start().starts_with('#') => String::new(),
            None => l.to_string(),
        }
    };
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut docs = vec![Vec::new()];
    for l in init.lines() {
        if l.trim_end() == "---" {
            docs.push(Vec::new());
        } else {
            docs.last_mut().unwrap().push(l);
        }
    }
    let Some(d) = docs.iter().find(|d| d.iter().any(|l| content(l) == "kind: InitConfiguration")) else {
        return Ok(()); // reported by the kind check
    };
    let Some(start) = d.iter().position(|l| content(l).starts_with("bootstrapTokens:") && indent(l) == 0) else {
        return Err("bootstrapTokens with an explicit ttl required (kubeadm would create a token on its own)".into());
    };
    if !content(d[start])["bootstrapTokens:".len()..].trim().is_empty() {
        return Err(BLOCK.into());
    }
    // the block: until the next top-level key (a top-level "- " still belongs to it)
    let block: Vec<&str> = d[start + 1..]
        .iter()
        .copied()
        .take_while(|l| { let c = content(l); c.is_empty() || indent(l) > 0 || c.starts_with("- ") || c == "-" })
        .filter(|l| !content(l).is_empty())
        .collect();
    let Some(first) = block.first() else {
        return Err("bootstrapTokens: at least one entry with a ttl".into());
    };
    let item_indent = indent(first);
    let flowish = |v: &str| v.starts_with(['{', '[', '&', '*', '!', '|', '>']);
    // entries: (keys at the entry level)
    let mut entries: Vec<Vec<(String, String)>> = Vec::new();
    let mut key_col = 0;
    for l in &block {
        let c = content(l);
        let t = c.trim_start();
        let ind = indent(&c);
        if ind == item_indent && (t == "-" || t.starts_with("- ")) {
            let rest = t[1..].trim_start();
            if rest.is_empty() || flowish(rest) {
                return Err(BLOCK.into());
            }
            key_col = ind + (t.len() - rest.len());
            entries.push(Vec::new());
        } else if ind < item_indent || entries.is_empty() {
            return Err(BLOCK.into());
        } else if ind != key_col || t == "-" || t.starts_with("- ") {
            continue; // nested under an entry key (usages as a block list, also "- x" at the key column)
        }
        let kv = c[key_col..].to_string();
        let Some((k, v)) = kv.split_once(':') else {
            return Err(BLOCK.into());
        };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        if k == "<<" || flowish(&k) || ((k == "ttl" || k == "expires") && flowish(&v)) {
            return Err(BLOCK.into());
        }
        entries.last_mut().unwrap().push((k, v));
    }
    for e in &entries {
        if e.iter().any(|(k, _)| k == "expires") {
            return Err("bootstrapTokens: expires is not allowed, use ttl (the node may not have synchronized time when kubeadm init runs)".into());
        }
        let ttls: Vec<&String> = e.iter().filter(|(k, _)| k == "ttl").map(|(_, v)| v).collect();
        let [ttl] = ttls.as_slice() else {
            return Err("bootstrapTokens: every entry needs exactly one ttl".into());
        };
        match go_duration_secs(ttl.trim_matches('\'')) {
            Some(0) => return Err("bootstrapTokens: ttl 0 (a token that never expires) is not allowed".into()),
            Some(t) if t > MAX_BOOTSTRAP_TTL_SECS => return Err("bootstrapTokens: ttl at most 24h (2h recommended)".into()),
            Some(_) => {}
            None => return Err("bootstrapTokens: ttl must be a duration in whole seconds, e.g. 2h, 90m, 2h0m0s".into()),
        }
    }
    Ok(())
}

fn validate_k8s(v: &mut V, k: &K8sConfig, role: NodeRole) {
    if role == NodeRole::ControlPlane {
        validate_k8s_init(v, k);
        validate_labels_taints(v, k);
        return;
    }
    if k.init.as_ref().is_some_and(|i| !i.value.is_empty()) {
        v.err("k8s.init", "init is for a CONTROL_PLANE, not a WORKER");
    }
    if !k.cluster_ca_crt.is_empty() || k.cluster_ca_key.as_ref().is_some_and(|x| !x.value.is_empty()) {
        v.err("k8s.cluster_ca_key", "the cluster CA is for a CONTROL_PLANE, not a WORKER");
    }
    if !valid_endpoint(&k.api_server_endpoint) {
        v.err("k8s.api_server_endpoint", "expected host:port");
    }
    match &k.bootstrap_token {
        Some(t) if valid_token(&t.value) => {}
        _ => v.err("k8s.bootstrap_token", "expected [a-z0-9]{6}.[a-z0-9]{16}"),
    }
    if k.ca_cert_hashes.is_empty() || k.ca_cert_hashes.len() > MAX_LIST {
        v.err("k8s.ca_cert_hashes", "1..32 hashes required");
    }
    for (j, h) in k.ca_cert_hashes.iter().enumerate() {
        if !valid_ca_hash(h) {
            v.err(format!("k8s.ca_cert_hashes[{j}]"), "expected sha256:<64 lower-case hex>");
        }
    }
    validate_labels_taints(v, k);
}

fn validate_labels_taints(v: &mut V, k: &K8sConfig) {
    if !k.node_ip.is_empty() && k.node_ip.parse::<IpAddr>().is_err() {
        v.err("k8s.node_ip", "expected an IPv4 or IPv6 address");
    }
    if k.node_labels.len() > MAX_LABELS || k.node_taints.len() > MAX_LABELS {
        v.err("k8s", "too many labels or taints");
    }
    for (key, val) in &k.node_labels {
        if !valid_label_key(key) || !valid_label_name(val, true) {
            v.err(format!("k8s.node_labels[{key}]"), "invalid label");
        }
    }
    for (j, t) in k.node_taints.iter().enumerate() {
        if !valid_label_key(&t.key) || !valid_label_name(&t.value, true) {
            v.err(format!("k8s.node_taints[{j}]"), "invalid key or value");
        }
        if !matches!(
            TaintEffect::try_from(t.effect),
            Ok(TaintEffect::NoSchedule | TaintEffect::PreferNoSchedule | TaintEffect::NoExecute)
        ) {
            v.err(format!("k8s.node_taints[{j}].effect"), "effect required");
        }
    }
}

// ------------------------------------------------------------- rendering

pub fn render_network(i: &Interface) -> String {
    let mut s = String::from("# generated by foil-agent\n[Match]\n");
    match &i.r#match {
        Some(interface::Match::MacAddress(m)) => s += &format!("MACAddress={}\n", m.to_ascii_lowercase()),
        Some(interface::Match::Name(n)) => s += &format!("Name={n}\n"),
        None => {}
    }
    if i.mtu != 0 {
        s += &format!("\n[Link]\nMTUBytes={}\n", i.mtu);
    }
    s += "\n[Network]\n";
    if i.dhcp4 {
        s += "DHCP=ipv4\n";
    }
    for a in &i.addresses {
        s += &format!("Address={a}\n");
    }
    for g in [&i.gateway4, &i.gateway6] {
        if !g.is_empty() {
            s += &format!("Gateway={g}\n");
        }
    }
    for d in &i.dns {
        s += &format!("DNS={d}\n");
    }
    if !i.domains.is_empty() {
        s += &format!("Domains={}\n", i.domains.join(" "));
    }
    // As Talos: static addresses and routes do not depend on the carrier. Without this networkd
    // drops them when the cable is out and the boot gate (static address required) would roll back a healthy release.
    if !i.addresses.is_empty() {
        s += "ConfigureWithoutCarrier=yes\nIgnoreCarrierLoss=yes\n";
    }
    s
}

pub fn render_join(hostname: &str, k: &K8sConfig) -> String {
    // All values are validated against strict character sets; quoting is safe.
    let token = k.bootstrap_token.as_ref().map(|t| t.value.as_str()).unwrap_or("");
    let mut s = String::from(
        "# generated by foil-agent\napiVersion: kubeadm.k8s.io/v1beta4\nkind: JoinConfiguration\n\
         discovery:\n  bootstrapToken:\n",
    );
    s += &format!("    apiServerEndpoint: \"{}\"\n", k.api_server_endpoint);
    s += &format!("    token: \"{token}\"\n    caCertHashes:\n");
    for h in &k.ca_cert_hashes {
        s += &format!("      - \"{h}\"\n");
    }
    s += &format!("nodeRegistration:\n  name: \"{hostname}\"\n");
    if !k.node_ip.is_empty() {
        s += &format!("  kubeletExtraArgs:\n    - name: \"node-ip\"\n      value: \"{}\"\n", k.node_ip);
    }
    s
}

pub fn render_labels(k: &K8sConfig) -> String {
    let mut kv: Vec<_> = k.node_labels.iter().map(|(a, b)| format!("{a}={b}")).collect();
    kv.sort();
    kv.join(",") + "\n"
}

pub fn render_taints(k: &K8sConfig) -> String {
    let eff = |e: i32| match TaintEffect::try_from(e) {
        Ok(TaintEffect::NoSchedule) => "NoSchedule",
        Ok(TaintEffect::PreferNoSchedule) => "PreferNoSchedule",
        Ok(TaintEffect::NoExecute) => "NoExecute",
        _ => "",
    };
    let v: Vec<_> = k.node_taints.iter().map(|t| format!("{}={}:{}", t.key, t.value, eff(t.effect))).collect();
    v.join(",") + "\n"
}

/// Files to write into the config dir: (name, contents, secret).
pub fn render(c: &NodeConfig) -> Vec<(&'static str, String, bool)> {
    let mut out = vec![(NODE_HOSTNAME, format!("{}\n", c.hostname), false)];
    if let Some(i) = c.network.as_ref().and_then(|n| n.interfaces.first()) {
        out.push((NODE_NETWORK, render_network(i), false));
    }
    if let Some(k) = c.k8s.as_ref().filter(|_| is_control_plane(c)) {
        let init = k.init.as_ref().map(|i| i.value.clone()).unwrap_or_default();
        out.push((K8S_INIT, if init.ends_with('\n') { init } else { init + "\n" }, true));
        out.push((K8S_CA_CRT, parse_ca_pem(&k.cluster_ca_crt).map(|d| pem_encode(&d)).unwrap_or_default(), false));
        let key = k.cluster_ca_key.as_ref().map(|x| x.value.trim().to_string() + "\n").unwrap_or_default();
        out.push((K8S_CA_KEY, key, true));
        out.push((K8S_LABELS, render_labels(k), false));
        out.push((K8S_TAINTS, render_taints(k), false));
    } else if let Some(k) = &c.k8s {
        out.push((K8S_JOIN, render_join(&c.hostname, k), true));
        out.push((K8S_LABELS, render_labels(k), false));
        out.push((K8S_TAINTS, render_taints(k), false));
    }
    out
}

// ------------------------------------------------------------- registries

/// Where containerd reads them on the node (config_path in the image).
pub const CERTS_D: &str = "/run/foilbird/containerd/certs.d";

fn pem_encode(ders: &[Vec<u8>]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for der in ders {
        let mut b64 = String::new();
        for ch in der.chunks(3) {
            let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
            for k in 0..4 {
                b64.push(if k <= ch.len() { T[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
            }
        }
        out += "-----BEGIN CERTIFICATE-----\n";
        for line in b64.as_bytes().chunks(64) {
            out += std::str::from_utf8(line).unwrap();
            out.push('\n');
        }
        out += "-----END CERTIFICATE-----\n";
    }
    out
}

fn upstream(registry: &str) -> String {
    // containerd's own default for the docker.io namespace
    if registry == "docker.io" { "https://registry-1.docker.io".into() } else { format!("https://{registry}") }
}

/// Files per registry directory: (registry, file name, contents). CA files
/// are re-encoded from the parsed certificates (no stray text is copied).
///
/// With mirrors the registry itself never appears: containerd tries the
/// [host] entries in order and then `server`, so the last mirror becomes
/// `server` and a failing mirror fails the pull instead of silently going to
/// the upstream (which may be unreachable or not allowed from the node).
pub fn render_registries(regs: &[RegistryHost]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for r in regs {
        let dir = format!("{CERTS_D}/{}", r.registry);
        let mut t = String::from("# generated by foil-agent\n");
        let mut ca_line = |file: &str, pem: &str, indent: &str, t: &mut String| {
            if let Ok(ders) = parse_ca_pem(pem) {
                out.push((r.registry.clone(), file.to_string(), pem_encode(&ders)));
                *t += &format!("{indent}ca = \"{dir}/{file}\"\n");
            }
        };
        let url = |m: &crate::pb::RegistryMirror| format!("https://{}{}", m.endpoint, m.prefix.trim_end_matches('/'));
        let caps_path = |m: &crate::pb::RegistryMirror, indent: &str| {
            let mut s = format!("{indent}capabilities = [\"pull\", \"resolve\"]\n");
            if !m.prefix.trim_end_matches('/').is_empty() {
                s += &format!("{indent}override_path = true\n");
            }
            s
        };
        match r.mirrors.split_last() {
            None => {
                t += &format!("server = \"{}\"\n", upstream(&r.registry));
                ca_line("ca.crt", &r.ca_pem, "", &mut t);
            }
            Some((last, rest)) => {
                t += &format!("# mirrors only: no fallback to {}\n", upstream(&r.registry));
                t += &format!("server = \"{}\"\n", url(last));
                t += &caps_path(last, "");
                ca_line(&format!("mirror-{}.crt", rest.len()), &last.ca_pem, "", &mut t);
                for (j, m) in rest.iter().enumerate() {
                    t += &format!("\n[host.\"{}\"]\n", url(m));
                    t += &caps_path(m, "  ");
                    ca_line(&format!("mirror-{j}.crt"), &m.ca_pem, "  ", &mut t);
                }
            }
        }
        out.push((r.registry.clone(), "hosts.toml".into(), t));
    }
    out
}

/// Replace the agent's certs.d tree as a whole (containerd reads hosts.toml
/// on every pull; no restart). No registries = no tree.
pub fn install_registries(paths: &Paths, regs: &[RegistryHost]) -> std::io::Result<()> {
    let base = paths.run_dir.join("containerd/certs.d");
    let parent = base.parent().expect("has parent");
    let (new, old) = (parent.join(".certs.d.new"), parent.join(".certs.d.old"));
    let _ = fs::remove_dir_all(&new);
    let _ = fs::remove_dir_all(&old);
    if regs.is_empty() {
        return match fs::remove_dir_all(&base) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    for (reg, name, data) in render_registries(regs) {
        write_atomic(&new.join(&reg).join(&name), data.as_bytes(), 0o644)?;
    }
    if base.exists() {
        fs::rename(&base, &old)?;
    }
    fs::rename(&new, &base)?;
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

// ------------------------------------------------------------- hosts

pub const HOSTS: &str = "hosts";

pub fn render_hosts(hosts: &[HostEntry]) -> String {
    let mut s = String::from("# generated by foil-agent (NodeConfig.extra_host_entries)\n127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n");
    for h in hosts {
        s += &format!("{} {}\n", h.ip, h.hostnames.join(" "));
    }
    s
}

/// /run/foilbird/hosts, always written (localhost lines even without entries):
/// /etc/hosts in the image points at it.
pub fn install_hosts(paths: &Paths, hosts: &[HostEntry]) -> std::io::Result<()> {
    write_atomic(&paths.run_dir.join(HOSTS), render_hosts(hosts).as_bytes(), 0o644)
}

// ------------------------------------------------------------- time

/// Drop-in name: sorts after the image's 10-foil.conf (which empties NTP= and
/// FallbackNTP=), so a non-empty NTP= here sets the servers.
pub const TIMESYNCD_DROPIN: &str = "50-foil.conf";

pub fn render_time(servers: &[String]) -> Option<String> {
    (!servers.is_empty()).then(|| format!("# generated by foil-agent (NodeConfig.time)\n[Time]\nNTP={}\n", servers.join(" ")))
}

/// Write or remove the timesyncd drop-in; true if it changed (timesyncd
/// must be restarted to pick it up).
pub fn install_time(paths: &Paths, servers: &[String]) -> std::io::Result<bool> {
    let f = paths.timesyncd_dir.join(TIMESYNCD_DROPIN);
    let old = fs::read_to_string(&f).ok();
    let new = render_time(servers);
    if old == new {
        return Ok(false);
    }
    match &new {
        Some(d) => write_atomic(&f, d.as_bytes(), 0o644)?,
        None => fs::remove_file(&f).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })?,
    }
    Ok(true)
}

// ------------------------------------------------------------- files

pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().expect("absolute path");
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)
}

/// Write the rendered set; files of names not in the set are removed.
pub fn install(paths: &Paths, files: &[(&str, String, bool)], generation: u64, interfaces: &[Interface]) -> std::io::Result<()> {
    fs::create_dir_all(&paths.config_dir)?;
    for name in [NODE_HOSTNAME, NODE_NETWORK, K8S_JOIN, K8S_LABELS, K8S_TAINTS, K8S_INIT, K8S_CA_CRT, K8S_CA_KEY] {
        if !files.iter().any(|(n, _, _)| *n == name) {
            let _ = fs::remove_file(paths.config_dir.join(name));
        }
    }
    for (name, data, secret) in files {
        write_atomic(&paths.config_dir.join(name), data.as_bytes(), if *secret { 0o600 } else { 0o644 })?;
    }
    // networkd: one file per interface (API) or the bridge file as is.
    if let Ok(rd) = fs::read_dir(&paths.networkd_dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("50-foil-") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    if interfaces.is_empty() {
        if let Some((_, data, _)) = files.iter().find(|(n, _, _)| *n == NODE_NETWORK) {
            write_atomic(&paths.networkd_dir.join("50-foil-0.network"), data.as_bytes(), 0o644)?;
        }
    } else {
        for (i, ifc) in interfaces.iter().enumerate() {
            write_atomic(&paths.networkd_dir.join(format!("50-foil-{i}.network")), render_network(ifc).as_bytes(), 0o644)?;
        }
    }
    write_atomic(&paths.config_dir.join("generation"), format!("{generation}\n").as_bytes(), 0o644)
}

/// Early boot (no D-Bus yet): set the kernel host name directly. /etc is a
/// tmpfs and is not written; hostnamed reports the transient name.
pub fn set_hostname_syscall(paths: &Paths, name: &str) -> std::io::Result<()> {
    if !paths.live {
        return Ok(());
    }
    // SAFETY: valid pointer/length of a validated ASCII name.
    let rc = unsafe { libc::sethostname(name.as_ptr() as *const libc::c_char, name.len()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ------------------------------------------------------------- persistence

pub struct Persisted {
    pub generation: u64,
    pub config: NodeConfig,
}

const CONFIG_PB: &str = "config.pb";
const GENERATION: &str = "generation";

fn tmp_of(path: &Path) -> PathBuf {
    path.with_file_name(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()))
}

fn write_synced(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let _ = fs::remove_file(path);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Lab build only (feature `lab-crash-points`): stop the save at a named point,
/// as `<point>:kill[:<generation>]` (SIGKILL to itself) or `<point>:hang[:<generation>]`
/// (block, for a hard reset from outside), read from `lab.crash` in the ESP
/// bridge directory; with a generation, only the save of that generation stops.
#[cfg(feature = "lab-crash-points")]
fn crash_point(paths: &Paths, point: &str, generation: u64) {
    let file = paths.esp_bridge.join("lab.crash");
    let spec = match fs::read_to_string(&file) {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(point, file = %file.display(), "lab crash point: no spec ({e})");
            return;
        }
    };
    tracing::info!(point, generation, spec = %spec.trim(), "lab crash point: spec");
    let f: Vec<&str> = spec.trim().split(':').collect();
    if f.len() == 3 && f[2].parse::<u64>().ok() != Some(generation) {
        return;
    }
    match (f.first().copied(), f.get(1).copied()) {
        (Some(p), Some("kill")) if p == point => {
            tracing::warn!(point, "lab crash point: SIGKILL");
            let rc = unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            tracing::error!(rc, "lab crash point: SIGKILL did not land ({}), aborting", std::io::Error::last_os_error());
            std::process::abort();
        }
        (Some(p), Some("hang")) if p == point => {
            tracing::warn!(point, "lab crash point: hanging until reset");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        _ => {}
    }
}
#[cfg(not(feature = "lab-crash-points"))]
fn crash_point(_: &Paths, _: &str, _: u64) {}

pub const LAB_CRASH_POINTS: bool = cfg!(feature = "lab-crash-points");

/// The on-disk format is unchanged: `config.pb` and `generation`. Both are
/// written as `.<name>.tmp` first and committed by two renames; the temporary
/// files are the intent log that `load` uses to finish or drop a write cut
/// between the renames:
///   1. `.config.pb.tmp` (fsync), then `.generation.tmp` (fsync), fsync dir;
///   2. rename `config.pb`, fsync dir;
///   3. rename `generation`, fsync dir.
pub fn save(paths: &Paths, generation: u64, c: &NodeConfig) -> std::io::Result<()> {
    let d = &paths.state_dir;
    fs::create_dir_all(d)?;
    let (cp, gp) = (d.join(CONFIG_PB), d.join(GENERATION));
    let (ct, gt) = (tmp_of(&cp), tmp_of(&gp));
    write_synced(&ct, &c.encode_to_vec(), 0o600)?;
    crash_point(paths, "config-tmp", generation);
    write_synced(&gt, format!("{generation}\n").as_bytes(), 0o600)?;
    sync_dir(d)?;
    fs::rename(&ct, &cp)?;
    sync_dir(d)?;
    crash_point(paths, "config-rename", generation);
    fs::rename(&gt, &gp)?;
    sync_dir(d)
}

/// What `recover` did with a write that was cut short.
#[derive(Debug, PartialEq)]
pub enum Recovery {
    None,
    /// `.config.pb.tmp` present: nothing was committed, both temporaries removed.
    Discarded,
    /// cut between the renames: `generation` committed from `.generation.tmp`.
    Completed(u64),
    /// `.generation.tmp` not exactly generation + 1 (empty, truncated, or left
    /// by an older agent whose state moved on): removed, the pair stays as is.
    StaleGeneration,
}

/// Finish or drop an interrupted `save` (see there). Only a `.generation.tmp`
/// whose number is exactly the committed generation + 1 is taken (any number
/// when no generation was committed yet). With
/// `commit` false nothing is written (foil-config: /var/lib/foil-agent is read
/// only there) and the decision is only returned; the agent commits it.
pub fn recover(paths: &Paths, commit: bool) -> std::io::Result<Recovery> {
    let d = &paths.state_dir;
    let (cp, gp) = (d.join(CONFIG_PB), d.join(GENERATION));
    let (ct, gt) = (tmp_of(&cp), tmp_of(&gp));
    let r = if ct.exists() {
        Recovery::Discarded
    } else if gt.exists() {
        let parse = |p: &Path| fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u64>().ok());
        // No committed generation yet (the first API config; the bridge
        // counts as generation 1 in memory only): no older pair to protect.
        let on_disk = if gp.exists() { parse(&gp) } else { None };
        match (parse(&gt), on_disk) {
            (Some(t), Some(n)) if cp.exists() && t == n + 1 => Recovery::Completed(t),
            (Some(t), None) if cp.exists() && !gp.exists() && t >= 1 => Recovery::Completed(t),
            (t, n) => {
                if commit {
                    tracing::warn!(tmp = ?t, on_disk = ?n, "stale generation tmp discarded");
                }
                Recovery::StaleGeneration
            }
        }
    } else {
        return Ok(Recovery::None);
    };
    if !commit {
        return Ok(r);
    }
    match &r {
        Recovery::Discarded => {
            fs::remove_file(&ct)?;
            let _ = fs::remove_file(&gt);
            tracing::warn!("interrupted config write discarded (nothing was committed)");
        }
        Recovery::Completed(t) => {
            fs::rename(&gt, &gp)?;
            tracing::warn!(generation = t, "completed interrupted config write (generation committed)");
        }
        _ => fs::remove_file(&gt)?,
    }
    sync_dir(d)?;
    Ok(r)
}

/// The persisted pair, after `recover` (committed by the agent; only
/// evaluated by foil-config, which must not write /var/lib/foil-agent).
pub fn load(paths: &Paths, commit: bool) -> Option<Persisted> {
    let r = recover(paths, commit).unwrap_or_else(|e| {
        tracing::warn!("config write recovery: {e}");
        Recovery::None
    });
    let data = fs::read(paths.state_dir.join(CONFIG_PB)).ok()?;
    let generation = match r {
        Recovery::Completed(t) => t,
        _ => fs::read_to_string(paths.state_dir.join(GENERATION)).ok()?.trim().parse().ok()?,
    };
    let mut config = NodeConfig::decode(&data[..]).ok()?;
    if infer_legacy_role(&mut config) {
        tracing::warn!(
            generation,
            role = role(&config).as_str_name(),
            "persisted config has k8s but no role (written before node roles existed): role inferred from k8s.init, file not rewritten; the next ApplyConfig must set the role"
        );
    }
    Some(Persisted { generation, config })
}

/// Copy for GetConfig: secrets replaced by their SHA-256. Every SecretString of the config is listed here; a test
/// fills all of them and checks that no value survives (`secrets_never_leave_getconfig`).
pub fn redacted(c: &NodeConfig) -> NodeConfig {
    let mut c = c.clone();
    let hide = |t: &mut crate::pb::SecretString| {
        t.sha256 = hex::encode(Sha256::digest(t.value.as_bytes()));
        t.value.clear();
    };
    if let Some(k) = c.k8s.as_mut() {
        for t in [k.bootstrap_token.as_mut(), k.init.as_mut(), k.cluster_ca_key.as_mut()].into_iter().flatten() {
            hide(t);
        }
    }
    c
}

/// Secret values of a config, for the journal redaction of ReadJournal (exact matches): the join token, and the
/// bootstrap tokens written inside a control plane's init configuration.
pub fn secret_values(c: &NodeConfig) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(k) = &c.k8s {
        if let Some(t) = k.bootstrap_token.as_ref().filter(|t| !t.value.is_empty()) {
            v.push(t.value.clone());
        }
        if let Some(i) = &k.init {
            let re = regex::Regex::new(r"\b[a-z0-9]{6}\.[a-z0-9]{16}\b").expect("valid pattern");
            v.extend(re.find_iter(&i.value).map(|m| m.as_str().to_string()));
        }
    }
    v
}

// ------------------------------------------------------------- bridge

/// Bridge input: raw credential files, validated and copied as is.
pub struct Bridge {
    pub hostname: String,
    pub files: Vec<(&'static str, String, bool)>,
}

const NETWORKD_SECTIONS: &[&str] =
    &["Match", "Link", "Network", "Address", "Route", "DHCPv4", "DHCPv6", "IPv6AcceptRA"];

fn validate_networkd(s: &str) -> Result<(), String> {
    for (n, line) in s.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(sec) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            if !NETWORKD_SECTIONS.contains(&sec) {
                return Err(format!("line {}: section [{sec}] not allowed", n + 1));
            }
        } else if !l.contains('=') {
            return Err(format!("line {}: expected key=value", n + 1));
        }
    }
    Ok(())
}

fn validate_labels_str(s: &str) -> bool {
    s.is_empty() || s.split(',').all(|kv| matches!(kv.split_once('='), Some((k, v)) if valid_label_key(k) && valid_label_name(v, true)))
}

fn validate_taints_str(s: &str) -> bool {
    s.is_empty()
        || s.split(',').all(|t| {
            let Some((kv, eff)) = t.rsplit_once(':') else { return false };
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            valid_label_key(k)
                && valid_label_name(v, true)
                && matches!(eff, "NoSchedule" | "PreferNoSchedule" | "NoExecute")
        })
}

fn read_cred(dir: &Path, name: &str) -> Result<Option<String>, String> {
    let p = dir.join(name);
    match fs::metadata(&p) {
        Err(_) => Ok(None),
        Ok(m) if m.len() > MAX_BRIDGE_FILE => Err(format!("{name}: larger than {MAX_BRIDGE_FILE} bytes")),
        Ok(_) => fs::read_to_string(&p).map(Some).map_err(|e| format!("{name}: {e}")),
    }
}

/// Read and validate the bridge credentials. Ok(None) = no bridge present.
pub fn read_bridge(dir: &Path) -> Result<Option<Bridge>, String> {
    let Some(hostname) = read_cred(dir, NODE_HOSTNAME)? else { return Ok(None) };
    let hostname = hostname.trim().to_string();
    if !valid_hostname(&hostname) {
        return Err(format!("{NODE_HOSTNAME}: invalid host name"));
    }
    let mut files = vec![(NODE_HOSTNAME, format!("{hostname}\n"), false)];
    if let Some(n) = read_cred(dir, NODE_NETWORK)? {
        validate_networkd(&n).map_err(|e| format!("{NODE_NETWORK}: {e}"))?;
        files.push((NODE_NETWORK, n, false));
    }
    if let Some(j) = read_cred(dir, K8S_JOIN)? {
        if !j.lines().any(|l| l.trim() == "kind: JoinConfiguration") {
            return Err(format!("{K8S_JOIN}: not a kubeadm JoinConfiguration"));
        }
        files.push((K8S_JOIN, j, true));
    }
    if let Some(l) = read_cred(dir, K8S_LABELS)? {
        let l = l.trim().to_string();
        if !validate_labels_str(&l) {
            return Err(format!("{K8S_LABELS}: invalid"));
        }
        files.push((K8S_LABELS, l + "\n", false));
    }
    if let Some(t) = read_cred(dir, K8S_TAINTS)? {
        let t = t.trim().to_string();
        if !validate_taints_str(&t) {
            return Err(format!("{K8S_TAINTS}: invalid"));
        }
        files.push((K8S_TAINTS, t + "\n", false));
    }
    Ok(Some(Bridge { hostname, files }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::{NetworkConfig, SecretString, Taint};

    fn sample() -> NodeConfig {
        NodeConfig {
            schema: 1,
            hostname: "gpu-01".into(),
            network: Some(NetworkConfig {
                interfaces: vec![Interface {
                    r#match: Some(interface::Match::MacAddress("52:54:00:AA:bb:01".into())),
                    dhcp4: false,
                    addresses: vec!["192.0.2.10/24".into()],
                    gateway4: "192.0.2.1".into(),
                    gateway6: String::new(),
                    dns: vec!["192.0.2.53".into()],
                    domains: vec!["example.org".into()],
                    mtu: 1500,
                }],
            }),
            role: NodeRole::Worker as i32,
            k8s: Some(K8sConfig {
                api_server_endpoint: "k8s.example.org:6443".into(),
                bootstrap_token: Some(SecretString { value: "abcdef.0123456789abcdef".into(), sha256: String::new() }),
                ca_cert_hashes: vec![format!("sha256:{}", "a".repeat(64))],
                node_labels: [("node-role.example.org/gpu".to_string(), "true".to_string())].into(),
                node_taints: vec![Taint { key: "gpu".into(), value: "true".into(), effect: TaintEffect::NoSchedule as i32 }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Self-signed CA certificate (PEM) for tests.
    pub fn test_ca() -> String {
        let k = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.self_signed(&k).unwrap().pem()
    }

    #[test]
    fn time_servers() {
        use crate::pb::TimeConfig;
        let mut c = sample();
        c.time = Some(TimeConfig { servers: vec!["192.0.2.3".into(), "fd00::1".into(), "ntp.example.org".into()] });
        assert!(validate(&c).is_empty(), "{:?}", validate(&c));
        assert_eq!(
            render_time(&c.time.as_ref().unwrap().servers).unwrap(),
            "# generated by foil-agent (NodeConfig.time)\n[Time]\nNTP=192.0.2.3 fd00::1 ntp.example.org\n"
        );
        assert_eq!(render_time(&[]), None);
        for bad in ["192.0.2.300", "ntp.example.org:123", "[fd00::1]", "NTP.example.org", "a b", "x\nFallbackNTP=evil", "", "-a.example", "udp://x"] {
            c.time = Some(TimeConfig { servers: vec![bad.into()] });
            assert!(validate(&c).iter().any(|e| e.field == "time.servers[0]"), "{bad:?} accepted");
        }
        c.time = Some(TimeConfig { servers: vec!["192.0.2.3".into(), "192.0.2.3".into()] });
        assert!(validate(&c).iter().any(|e| e.field == "time.servers[1]" && e.message == "duplicate"));
        c.time = Some(TimeConfig { servers: (0..9).map(|i| format!("10.0.0.{i}")).collect() });
        assert!(validate(&c).iter().any(|e| e.field == "time.servers"));
        // install: write, unchanged, remove
        let root = std::env::temp_dir().join(format!("foil-time-{}", std::process::id()));
        let paths = Paths::with_root(root.clone());
        let s = vec!["192.0.2.3".to_string()];
        assert!(install_time(&paths, &s).unwrap());
        assert!(!install_time(&paths, &s).unwrap());
        assert!(paths.timesyncd_dir.join(TIMESYNCD_DROPIN).exists());
        assert!(install_time(&paths, &[]).unwrap());
        assert!(!paths.timesyncd_dir.join(TIMESYNCD_DROPIN).exists());
        assert!(!install_time(&paths, &[]).unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn registries_render() {
        use crate::pb::RegistryMirror;
        let ca = test_ca();
        let mut c = sample();
        c.registries = vec![
            RegistryHost {
                registry: "docker.io".into(),
                mirrors: vec![
                    RegistryMirror { endpoint: "harbor.example.org".into(), prefix: "/v2/dockerhub-proxy".into(), ca_pem: format!("junk\n{ca}") },
                    RegistryMirror { endpoint: "mirror.example.org:5000".into(), prefix: String::new(), ca_pem: String::new() },
                ],
                ca_pem: String::new(),
            },
            RegistryHost { registry: "harbor.example.org:8443".into(), mirrors: vec![], ca_pem: ca.clone() },
        ];
        assert_eq!(validate(&c), vec![]);
        let files = render_registries(&c.registries);
        let get = |r: &str, n: &str| files.iter().find(|f| f.0 == r && f.1 == n).map(|f| f.2.clone());
        let h = get("docker.io", "hosts.toml").unwrap();
        // mirrors only: the upstream is named in a comment, never as a host
        assert_eq!(
            h,
            "# generated by foil-agent\n# mirrors only: no fallback to https://registry-1.docker.io\n\
             server = \"https://mirror.example.org:5000\"\ncapabilities = [\"pull\", \"resolve\"]\n\
             \n[host.\"https://harbor.example.org/v2/dockerhub-proxy\"]\n  capabilities = [\"pull\", \"resolve\"]\n  override_path = true\n\
             \x20 ca = \"/run/foilbird/containerd/certs.d/docker.io/mirror-0.crt\"\n"
        );
        let one = render_registries(&[RegistryHost {
            registry: "docker.io".into(),
            mirrors: vec![RegistryMirror { endpoint: "harbor.example.org".into(), prefix: "/v2/dockerhub".into(), ca_pem: ca.clone() }],
            ca_pem: String::new(),
        }]);
        let h1 = &one.iter().find(|f| f.1 == "hosts.toml").unwrap().2;
        assert!(h1.ends_with("server = \"https://harbor.example.org/v2/dockerhub\"\ncapabilities = [\"pull\", \"resolve\"]\noverride_path = true\nca = \"/run/foilbird/containerd/certs.d/docker.io/mirror-0.crt\"\n"), "{h1}");
        assert!(!h1.contains("[host"));
        // re-encoded PEM equals the input certificate, stray text dropped
        let m0 = get("docker.io", "mirror-0.crt").unwrap();
        assert_eq!(parse_ca_pem(&m0).unwrap(), parse_ca_pem(&ca).unwrap());
        assert!(!m0.contains("junk"));
        assert_eq!(m0.replace('\n', "").replace("\r", ""), ca.replace('\n', "").replace("\r", ""));
        let p = get("harbor.example.org:8443", "hosts.toml").unwrap();
        assert!(p.contains("server = \"https://harbor.example.org:8443\"\nca = \"/run/foilbird/containerd/certs.d/harbor.example.org:8443/ca.crt\"\n"), "{p}");

        // install: tree replaced as a whole, removed when empty
        let root = std::env::temp_dir().join(format!("foil-reg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = Paths::with_root(root.clone());
        install_registries(&paths, &c.registries).unwrap();
        let base = root.join("run/foilbird/containerd/certs.d");
        assert!(base.join("docker.io/hosts.toml").exists() && base.join("harbor.example.org:8443/ca.crt").exists());
        install_registries(&paths, &c.registries[..1]).unwrap();
        assert!(!base.join("harbor.example.org:8443").exists(), "dropped registry removed");
        install_registries(&paths, &[]).unwrap();
        assert!(!base.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn registries_rules() {
        use crate::pb::RegistryMirror;
        let m = |ep: &str, pre: &str| RegistryMirror { endpoint: ep.into(), prefix: pre.into(), ca_pem: String::new() };
        let mut c = sample();
        for (r, field) in [
            (RegistryHost { registry: "Docker.io".into(), mirrors: vec![m("x", "")], ca_pem: String::new() }, "registries[0].registry"),
            (RegistryHost { registry: "../etc".into(), mirrors: vec![m("x", "")], ca_pem: String::new() }, "registries[0].registry"),
            (RegistryHost { registry: "docker.io".into(), mirrors: vec![], ca_pem: String::new() }, "registries[0]"),
            (RegistryHost { registry: "docker.io".into(), mirrors: vec![m("http://x", "")], ca_pem: String::new() }, "registries[0].mirrors[0].endpoint"),
            (RegistryHost { registry: "docker.io".into(), mirrors: vec![m("x", "/v2/a\"]\nskip_verify = true")], ca_pem: String::new() }, "registries[0].mirrors[0].prefix"),
            (RegistryHost { registry: "docker.io".into(), mirrors: vec![m("x", "")], ca_pem: "nope".into() }, "registries[0].ca_pem"),
        ] {
            c.registries = vec![r];
            let f: Vec<_> = validate(&c).into_iter().map(|e| e.field).collect();
            assert_eq!(f, vec![field.to_string()]);
        }
        c.registries = vec![RegistryHost { registry: "docker.io".into(), mirrors: vec![m("x", "")], ca_pem: test_ca() }];
        let f: Vec<_> = validate(&c).into_iter().map(|e| e.field).collect();
        assert_eq!(f, vec!["registries[0].ca_pem".to_string()], "registry CA is unused with mirrors");
        let ok = RegistryHost { registry: "docker.io".into(), mirrors: vec![m("x", "")], ca_pem: String::new() };
        c.registries = vec![ok.clone(), ok];
        let f: Vec<_> = validate(&c).into_iter().map(|e| e.field).collect();
        assert_eq!(f, vec!["registries[1].registry".to_string()]);
    }

    #[test]
    fn host_entries() {
        let mut c = sample();
        c.extra_host_entries = vec![
            HostEntry { ip: "192.0.2.200".into(), hostnames: vec!["harbor.example.org".into(), "registry.example.org".into()] },
            HostEntry { ip: "fd00::10".into(), hostnames: vec!["mirror.example.org".into()] },
        ];
        assert_eq!(validate(&c), vec![]);
        let h = render_hosts(&c.extra_host_entries);
        assert!(h.contains("\n127.0.0.1 localhost\n"));
        assert!(h.ends_with("192.0.2.200 harbor.example.org registry.example.org\nfd00::10 mirror.example.org\n"), "{h}");
        for (ip, names, field) in [
            ("192.0.2.300", vec!["a.example"], "extra_host_entries[0].ip"),
            ("192.0.2.1", vec![], "extra_host_entries[0].hostnames"),
            ("192.0.2.1", vec!["Harbor.example"], "extra_host_entries[0].hostnames[0]"),
            ("192.0.2.1", vec!["a b"], "extra_host_entries[0].hostnames[0]"),
            ("192.0.2.1", vec!["x\n10.0.0.1 evil"], "extra_host_entries[0].hostnames[0]"),
            ("192.0.2.1", vec!["localhost"], "extra_host_entries[0].hostnames[0]"),
        ] {
            c.extra_host_entries = vec![HostEntry { ip: ip.into(), hostnames: names.iter().map(|n| n.to_string()).collect() }];
            let f: Vec<_> = validate(&c).into_iter().map(|e| e.field).collect();
            assert_eq!(f, vec![field.to_string()], "{ip} {names:?}");
        }
        c.extra_host_entries = vec![HostEntry { ip: "192.0.2.1".into(), hostnames: vec!["a.example".into()] }; 65];
        assert_eq!(validate(&c).len(), 1);
    }

    #[test]
    fn update_channel_rules() {
        let ok = UpdateChannel { endpoint: "updates.example.org:8443".into(), prefix: "/foilbird/".into(), ca_pem: test_ca() };
        let mut c = sample();
        c.update_channel = Some(ok.clone());
        assert_eq!(validate(&c), vec![]);
        assert_eq!(crate::update::override_url(&ok), "https://updates.example.org:8443/foilbird/");
        for (ep, pre, ca, field) in [
            ("http://x", "/", ok.ca_pem.as_str(), "update_channel.endpoint"),
            ("x:0", "/", ok.ca_pem.as_str(), "update_channel.endpoint"),
            ("user@x", "/", ok.ca_pem.as_str(), "update_channel.endpoint"),
            ("x", "/a/../b/", ok.ca_pem.as_str(), "update_channel.prefix"),
            ("x", "a?b", ok.ca_pem.as_str(), "update_channel.prefix"),
            ("x", "/", "", "update_channel.ca_pem"),
            ("x", "/", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "update_channel.ca_pem"), // gitleaks:allow (synthetic test input)
        ] {
            c.update_channel = Some(UpdateChannel { endpoint: ep.into(), prefix: pre.into(), ca_pem: ca.into() });
            let f: Vec<_> = validate(&c).into_iter().map(|e| e.field).collect();
            assert_eq!(f, vec![field.to_string()], "{ep} {pre}");
        }
        assert!(valid_server("[fd00::1]:443") && valid_server("192.0.2.1") && valid_server("[fd00::1]"));
        assert!(!valid_server("fd00::1") && !valid_server(""));
    }

    fn cp_sample() -> NodeConfig {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = p.self_signed(&key).unwrap();
        let mut c = sample();
        c.role = NodeRole::ControlPlane as i32;
        let k = c.k8s.as_mut().unwrap();
        k.api_server_endpoint.clear();
        k.bootstrap_token = None;
        k.ca_cert_hashes.clear();
        k.init = Some(SecretString {
            value: "apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nbootstrapTokens:\n- token: \"abcdef.0123456789abcdef\"\n  ttl: 2h\n---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}\n  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}\n  extraVolumes:\n  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}\n---\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nshutdownGracePeriod: 60s\nshutdownGracePeriodCriticalPods: 20s\n".into(),
            sha256: String::new(),
        });
        k.cluster_ca_crt = ca.pem();
        k.cluster_ca_key = Some(SecretString { value: key.serialize_pem(), sha256: String::new() });
        c
    }

    #[test]
    fn cp_init_valid_and_rendered() {
        let c = cp_sample();
        assert!(validate(&c).is_empty(), "{:?}", validate(&c));
        let r = render(&c);
        let get = |n: &str| r.iter().find(|x| x.0 == n).cloned();
        assert!(get(K8S_JOIN).is_none(), "a control plane renders no join");
        assert!(get(K8S_INIT).unwrap().2 && get(K8S_CA_KEY).unwrap().2, "init and CA key are secret (0600)");
        assert!(!get(K8S_CA_CRT).unwrap().2 && get(K8S_CA_CRT).unwrap().1.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(get(K8S_CA_KEY).unwrap().1.contains("PRIVATE KEY-----"));
        assert_eq!(secret_values(&c), vec!["abcdef.0123456789abcdef".to_string()]);
    }

    #[test]
    fn cp_init_needs_kubelet_shutdown() {
        let set = |init: &str| {
            let mut c = cp_sample();
            c.k8s.as_mut().unwrap().init.as_mut().unwrap().value = init.into();
            validate(&c).iter().any(|e| e.field == "k8s.init")
        };
        let base = "apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nbootstrapTokens:\n- ttl: 2h\n---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}\n  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}\n  extraVolumes:\n  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}\n";
        let kc = |g: &str, c: &str| format!("{base}---\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nshutdownGracePeriod: {g}\nshutdownGracePeriodCriticalPods: {c}\n");
        assert!(!set(&kc("60s", "20s")) && !set(&kc("\"1m\"", "20s # critical")) && !set(&kc("1m30s", "30s")));
        assert!(set(base), "no KubeletConfiguration");
        assert!(set(&kc("0s", "0s")) && set(&kc("60s", "0s")) && set(&kc("20s", "20s")) && set(&kc("60s", "")));
        assert!(set(&kc("60s", "1.5s")) && set(&kc("60s", "-20s")) && set(&kc("60", "20s")) && set(&kc("60s", "20ms")));
        assert!(set(&kc("60s", "20s").replace("kubelet.config.k8s.io/v1beta1", "kubelet.config.k8s.io/v1")));
        assert!(set(&(kc("60s", "20s") + &kc("60s", "20s")[base.len()..])), "two KubeletConfiguration documents");
        // nested keys do not count
        assert!(set(&kc("60s", "20s").replace("shutdownGracePeriod: 60s", "x:\n  shutdownGracePeriod: 60s")));
        assert_eq!(go_duration_secs("1h2m3s"), Some(3723));
        assert_eq!(go_duration_secs("m"), None);
        assert_eq!(go_duration_secs("5s3"), None);
    }

    /// As Talos: kube-apiserver audit is required in the control plane's ClusterConfiguration - the image's
    /// policy, a log on /var, both mounted into the static pod. An init configuration with audit as an operator writes it passes.
    #[test]
    fn r2_apiserver_audit_required() {
        let head = "apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nbootstrapTokens:\n- ttl: 2h\n---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\n";
        let kc = "---\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nshutdownGracePeriod: 60s\nshutdownGracePeriodCriticalPods: 20s\n";
        let errs = |cc: &str| -> Vec<String> {
            let mut c = cp_sample();
            c.k8s.as_mut().unwrap().init.as_mut().unwrap().value = format!("{head}{cc}{kc}");
            validate(&c).into_iter().map(|e| format!("{}: {}", e.field, e.message)).collect()
        };
        let ok = |cc: &str| assert!(errs(cc).is_empty(), "{cc:?}: {:?}", errs(cc));
        let has = |cc: &str, what: &str| {
            let e = errs(cc);
            assert!(e.iter().any(|m| m.starts_with("k8s.init: ") && m.contains(what)), "{cc:?}: expected {what:?}, got {e:?}");
        };
        let pol = "  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}\n";
        let logp = "  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}\n";
        let vols = "  extraVolumes:\n  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}\n";
        let cc = |args: &str, vols: &str| format!("apiServer:\n  certSANs: [198.51.100.10, 127.0.0.1]\n  extraArgs:\n{args}{vols}");
        // with audit: flow entries (README), block entries, a policy directory mount, rotation flags and comments
        ok(&cc(&format!("{pol}{logp}"), vols));
        ok(&cc(
            "  - name: audit-policy-file\n    value: \"/usr/lib/foilbird/kubernetes/audit-policy.yaml\"\n  - name: audit-log-path\n    value: /var/log/kubernetes/audit/audit.log\n  - {name: audit-log-maxsize, value: \"100\"}   # rotation\n",
            "  extraVolumes:\n  - name: foil-k8s\n    hostPath: /usr/lib/foilbird/kubernetes\n    mountPath: /usr/lib/foilbird/kubernetes\n    readOnly: true\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit}\n",
        ));
        // an init configuration with audit as an operator writes it (flow entries, YAML comments)
        ok("apiServer:\n  certSANs: [198.51.100.10, 127.0.0.1]\n  # audit log\n  extraArgs:\n  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}\n  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}\n  - {name: audit-log-maxsize, value: \"1\"}   # small for a test\n  - {name: audit-log-maxbackup, value: \"5\"}\n  - {name: audit-log-maxage, value: \"7\"}\n  - {name: audit-log-compress, value: \"true\"}\n  extraVolumes:\n  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}\n");
        // without audit: no apiServer, no extraArgs, one of the two flags missing
        has("", "audit required");
        has("apiServer:\n  certSANs: [198.51.100.10]\n", "audit required");
        has(&cc(logp, vols), "audit-policy-file missing");
        has(&cc(pol, vols), "audit-log-path missing");
        // another policy, the log on stdout or off /var, a flag twice
        has(&cc(&format!("  - {{name: audit-policy-file, value: /etc/kubernetes/my-policy.yaml}}\n{logp}"), vols), "the image's policy");
        has(&cc(&format!("{pol}  - {{name: audit-log-path, value: \"-\"}}\n"), vols), "persistent /var");
        has(&cc(&format!("{pol}  - {{name: audit-log-path, value: /tmp/audit.log}}\n"), vols), "persistent /var");
        has(&cc(&format!("{pol}{pol}{logp}"), vols), "more than once");
        // not mounted into the static pod: kube-apiserver would not start
        has(&cc(&format!("{pol}{logp}"), ""), "mount the audit policy");
        has(&cc(&format!("{pol}{logp}"), &vols.replace("hostPath: /var/log/kubernetes/audit,", "hostPath: /srv/audit,")), "directory of audit-log-path");
        // shapes the line reading cannot follow are refused, not guessed
        has(&cc(&format!("  - &a {{name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}}\n{logp}"), vols), "simple flow mapping");
        has("apiServer:\n  extraArgs: [{name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}]\n", "simple flow mapping");
    }

    /// Join tokens of the init configuration must expire, 0 < ttl <= 24h, block style; errors name the
    /// rule only. An init configuration as an operator writes it, with a dummy token, passes.
    #[test]
    fn r6b_bootstrap_ttl() {
        const TOK: &str = "abcdef.0123456789abcdef";
        let tail = "---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}\n  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}\n  extraVolumes:\n  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}\n---\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nshutdownGracePeriod: 60s\nshutdownGracePeriodCriticalPods: 20s\n";
        let errs = |tokens: &str| -> Vec<String> {
            let mut c = cp_sample();
            let init = format!("apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\n{tokens}{tail}");
            c.k8s.as_mut().unwrap().init.as_mut().unwrap().value = init;
            let e: Vec<String> = validate(&c).into_iter().map(|e| format!("{}: {}", e.field, e.message)).collect();
            assert!(e.iter().all(|m| !m.contains(TOK) && !m.contains("0123456789abcdef")), "token value in an error: {e:?}");
            e
        };
        let has = |tokens: &str, what: &str| {
            let e = errs(tokens);
            assert!(e.iter().any(|m| m.starts_with("k8s.init: ") && m.contains(what)), "{tokens:?}: expected {what:?}, got {e:?}");
        };
        let ok = |tokens: &str| assert!(errs(tokens).is_empty(), "{tokens:?}: {:?}", errs(tokens));
        let t = |ttl: &str| format!("bootstrapTokens:\n- token: \"{TOK}\"\n  ttl: {ttl}\n");
        // ok: 2h (the guide), Go forms, the 24h ceiling, quotes, comments, entries indented under the key
        for ttl in ["2h", "90m", "2h0m0s", "\"2h\"", "'2h'", "24h", "24h0m0s", "2h # two hours", "1s"] {
            ok(&t(ttl));
        }
        ok(&format!("bootstrapTokens:\n  - token: \"{TOK}\"\n    ttl: 2h\n    usages:\n    - signing\n    - authentication\n"));
        ok(&format!("bootstrapTokens:\n- token: \"{TOK}\"\n  usages:\n  - signing\n  ttl: 2h\n  groups: [system:bootstrappers:kubeadm:default-node-token]\n"));
        ok(&format!("{}- ttl: 1h\n", t("2h"))); // two entries, both with ttl
        // refused
        has("", "bootstrapTokens with an explicit ttl required");
        has("bootstrapTokens:\nlocalAPIEndpoint:\n  bindPort: 6443\n", "at least one entry");
        for ttl in ["0", "0s", "\"0s\"", "0h0m0s"] {
            has(&t(ttl), "ttl 0");
        }
        for ttl in ["25h", "24h0m1s", "8760h"] {
            has(&t(ttl), "at most 24h");
        }
        for ttl in ["1.5h", "90ms", "-2h", "2", "two hours", ""] {
            has(&t(ttl), "whole seconds");
        }
        has(&format!("{}  expires: \"2026-11-22T00:00:00Z\"\n", t("2h")), "expires is not allowed");
        has(&format!("bootstrapTokens:\n- token: \"{TOK}\"\n  expires: \"2026-11-22T00:00:00Z\"\n"), "expires is not allowed");
        has(&format!("bootstrapTokens:\n- token: \"{TOK}\"\n  usages: [signing]\n"), "exactly one ttl");
        has(&format!("{}- token: \"{TOK}\"\n", t("2h")), "exactly one ttl"); // two tokens, one without ttl
        has(&format!("{}  ttl: 48h\n", t("2h")), "exactly one ttl");
        // nested "ttl" is not the entry's ttl
        has(&format!("bootstrapTokens:\n- token: \"{TOK}\"\n  x:\n    ttl: 2h\n"), "exactly one ttl");
        // not block style around ttl: refused, not guessed
        for bad in [
            format!("bootstrapTokens: [{{token: \"{TOK}\", ttl: 2h}}]\n"),
            format!("bootstrapTokens:\n- {{token: \"{TOK}\", ttl: 2h}}\n"),
            format!("bootstrapTokens:\n- &t\n  token: \"{TOK}\"\n  ttl: 2h\n"),
            format!("bootstrapTokens:\n- token: \"{TOK}\"\n  <<: *base\n"),
            format!("bootstrapTokens:\n- token: \"{TOK}\"\n  ttl: *ttl\n"),
            format!("bootstrapTokens:\n- token: \"{TOK}\"\n  ttl: !!str 2h\n"),
            format!("bootstrapTokens:\n- token: \"{TOK}\"\n  ttl: |\n    2h\n"),
            format!("bootstrapTokens:\n-\n  token: \"{TOK}\"\n  ttl: 2h\n"),
            format!("bootstrapTokens: *tokens\n"),
        ] {
            has(&bad, "block style expected");
        }
        // a typical control-plane init (token replaced by a dummy), ttl 2h and kubeadm's default 24h0m0s
        let stand = |ttl: &str| {
            format!(
                "bootstrapTokens:\n- token: \"{TOK}\"\n  ttl: {ttl}\n  usages: [signing, authentication]\n  groups: [system:bootstrappers:kubeadm:default-node-token]\n\
                 localAPIEndpoint:\n  advertiseAddress: 198.51.100.10\n  bindPort: 6443\nnodeRegistration:\n  name: cp-1\n  criSocket: unix:///run/containerd/containerd.sock\n\
                 \x20 kubeletExtraArgs:\n  - name: node-ip\n    value: \"198.51.100.10\"\n"
            )
        };
        ok(&stand("2h"));
        ok(&stand("24h0m0s"));
        has(&stand("0s"), "ttl 0");
    }

    #[test]
    fn join_node_ip() {
        let mut c = sample();
        assert!(!render_join(&c.hostname, c.k8s.as_ref().unwrap()).contains("node-ip"));
        c.k8s.as_mut().unwrap().node_ip = "198.51.100.11".into();
        assert!(validate(&c).is_empty());
        assert!(render_join(&c.hostname, c.k8s.as_ref().unwrap()).contains("  kubeletExtraArgs:\n    - name: \"node-ip\"\n      value: \"198.51.100.11\"\n"));
        c.k8s.as_mut().unwrap().node_ip = "198.51.100.11; rm".into();
        assert!(validate(&c).iter().any(|e| e.field == "k8s.node_ip"));
    }

    #[test]
    fn cp_init_and_join_are_exclusive() {
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().api_server_endpoint = "192.0.2.1:6443".into();
        assert!(validate(&c).iter().any(|e| e.field == "k8s.api_server_endpoint" && e.message.contains("for a WORKER")));
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().bootstrap_token = Some(SecretString { value: "abcdef.0123456789abcdef".into(), sha256: String::new() });
        assert!(validate(&c).iter().any(|e| e.field == "k8s.api_server_endpoint"));
        // CA without init (a worker) is refused too
        let mut w = sample();
        w.k8s.as_mut().unwrap().cluster_ca_crt = cp_sample().k8s.unwrap().cluster_ca_crt;
        assert!(validate(&w).iter().any(|e| e.field == "k8s.cluster_ca_key"));
        // init without the CA, or not a kubeadm init configuration
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().cluster_ca_key = None;
        assert!(validate(&c).iter().any(|e| e.field == "k8s.cluster_ca_key"));
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().init.as_mut().unwrap().value = "kind: JoinConfiguration\n".into();
        assert!(validate(&c).iter().any(|e| e.field == "k8s.init"));
    }

    #[test]
    fn secrets_never_leave_getconfig() {
        // every SecretString of NodeConfig filled: none of the values may appear in the GetConfig copy
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().bootstrap_token = Some(SecretString { value: "zzzzzz.9999999999999999".into(), sha256: String::new() });
        let k = c.k8s.clone().unwrap();
        let secrets = [k.bootstrap_token.unwrap().value, k.init.unwrap().value, k.cluster_ca_key.unwrap().value];
        let out = format!("{:?}", redacted(&c));
        for v in &secrets {
            assert!(!out.contains(v.as_str()), "secret leaked into GetConfig");
            assert!(out.contains(&hex::encode(Sha256::digest(v.as_bytes()))), "sha256 missing");
        }
        // the init configuration carries a bootstrap token: not even that part may survive
        assert!(!out.contains("abcdef.0123456789abcdef"));
        // all SecretString fields of the schema are covered: count them in the .proto
        let proto = include_str!("../../api/proto/foilbird/agent/v1alpha1/agent.proto");
        let n = proto.lines().filter(|l| l.trim_start().starts_with("SecretString ")).count();
        assert_eq!(n, 3, "a new SecretString field must be added to redacted() and this test");
    }

    #[test]
    fn sample_is_valid() {
        assert_eq!(validate(&sample()), vec![]);
    }

    #[test]
    fn static_interfaces_keep_addresses_without_carrier() {
        // static -> ConfigureWithoutCarrier + IgnoreCarrierLoss; DHCP-only -> neither
        let c = sample();
        let mut i = c.network.unwrap().interfaces[0].clone();
        let r = render_network(&i);
        assert!(r.ends_with("ConfigureWithoutCarrier=yes\nIgnoreCarrierLoss=yes\n"), "{r}");
        assert!(validate_networkd(&r).is_ok());
        let p = crate::system::parse_net_match("50-foil-0.network", &r);
        assert_eq!(p.addresses, vec!["192.0.2.10".parse::<std::net::IpAddr>().unwrap()]);
        i.addresses.clear();
        i.dhcp4 = true;
        let r = render_network(&i);
        assert!(!r.contains("ConfigureWithoutCarrier") && !r.contains("IgnoreCarrierLoss"), "{r}");
        assert!(crate::system::parse_net_match("50-foil-0.network", &r).dhcp);
    }

    #[test]
    fn rejects_bad_values() {
        let mut c = sample();
        c.hostname = "Bad_Host".into();
        let n = c.network.as_mut().unwrap();
        n.interfaces[0].addresses = vec!["192.0.2.1/33".into(), "x".into()];
        n.interfaces[0].dhcp4 = true;
        n.interfaces[0].mtu = 100;
        let k = c.k8s.as_mut().unwrap();
        k.bootstrap_token = Some(SecretString { value: "short".into(), sha256: String::new() });
        k.api_server_endpoint = "host:0".into();
        k.ca_cert_hashes = vec!["md5:00".into()];
        k.node_taints[0].effect = 0;
        let fields: Vec<_> = validate(&c).into_iter().map(|e| e.field).collect();
        for f in [
            "hostname",
            "network.interfaces[0]",
            "network.interfaces[0].addresses[0]",
            "network.interfaces[0].addresses[1]",
            "network.interfaces[0].mtu",
            "k8s.api_server_endpoint",
            "k8s.bootstrap_token",
            "k8s.ca_cert_hashes[0]",
            "k8s.node_taints[0].effect",
        ] {
            assert!(fields.iter().any(|x| x == f), "missing {f} in {fields:?}");
        }
    }

    #[test]
    fn injection_is_rejected() {
        let mut c = sample();
        c.network.as_mut().unwrap().interfaces[0].domains = vec!["a\n[Network]\nDNS=203.0.113.53".into()];
        c.k8s.as_mut().unwrap().api_server_endpoint = "x:1\"\ntoken: y".into();
        assert_eq!(validate(&c).len(), 2);
    }

    #[test]
    fn renders_bridge_formats() {
        let c = sample();
        let files = render(&c);
        let get = |n| files.iter().find(|f| f.0 == n).unwrap();
        assert_eq!(get(NODE_HOSTNAME).1, "gpu-01\n");
        assert!(get(NODE_NETWORK).1.contains("MACAddress=52:54:00:aa:bb:01\n"));
        assert!(get(NODE_NETWORK).1.contains("Address=192.0.2.10/24\nGateway=192.0.2.1\nDNS=192.0.2.53\n"));
        let j = &get(K8S_JOIN);
        assert!(j.2, "join must be secret");
        assert!(j.1.contains("kind: JoinConfiguration\n"));
        assert!(j.1.contains("token: \"abcdef.0123456789abcdef\"\n"));
        assert!(j.1.contains("  name: \"gpu-01\"\n"));
        assert_eq!(get(K8S_LABELS).1, "node-role.example.org/gpu=true\n");
        assert_eq!(get(K8S_TAINTS).1, "gpu=true:NoSchedule\n");
    }

    #[test]
    fn redaction_hides_token() {
        let r = redacted(&sample());
        let t = r.k8s.unwrap().bootstrap_token.unwrap();
        assert!(t.value.is_empty());
        assert_eq!(t.sha256.len(), 64);
    }

    #[test]
    fn bridge_validation() {
        assert!(validate_networkd("[Match]\nName=e*\n[Network]\nDHCP=yes\n").is_ok());
        assert!(validate_networkd("[NetDev]\nKind=wireguard\n").is_err());
        assert!(validate_labels_str("a=b,example.org/c=d"));
        assert!(!validate_labels_str("a b=c"));
        assert!(validate_taints_str("gpu=true:NoSchedule,dedicated:NoExecute"));
        assert!(!validate_taints_str("gpu=true:Sometimes"));
    }

    // ---- persistence: two renames, the temporaries as the intent log

    fn state_root(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("foil-save-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let p = Paths::with_root(root);
        fs::create_dir_all(&p.state_dir).unwrap();
        p
    }

    fn named(h: &str) -> NodeConfig {
        let mut c = sample();
        c.hostname = h.into();
        c
    }

    fn files(p: &Paths) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&p.state_dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    /// State of a save cut after `steps`: 1 = .config.pb.tmp written,
    /// 2 = both temporaries, 3 = config.pb renamed (generation not yet).
    fn cut(p: &Paths, generation: u64, c: &NodeConfig, steps: u32) {
        let d = &p.state_dir;
        write_synced(&d.join(".config.pb.tmp"), &c.encode_to_vec(), 0o600).unwrap();
        if steps >= 2 {
            write_synced(&d.join(".generation.tmp"), format!("{generation}\n").as_bytes(), 0o600).unwrap();
        }
        if steps >= 3 {
            fs::rename(d.join(".config.pb.tmp"), d.join("config.pb")).unwrap();
        }
    }

    /// The role is required exactly with k8s and decides which k8s fields are allowed.
    #[test]
    fn r2_role_validation() {
        let has = |c: &NodeConfig, f: &str, m: &str| validate(c).iter().any(|e| e.field == f && e.message.contains(m));
        assert_eq!(validate(&sample()), vec![], "WORKER with join fields");
        assert_eq!(validate(&cp_sample()), vec![], "CONTROL_PLANE with init and the CA");
        // a node without Kubernetes has no role
        let mut base = sample();
        base.k8s = None;
        base.role = NodeRole::Unspecified as i32;
        assert_eq!(validate(&base), vec![], "no k8s, no role (a profile without k8s)");
        base.role = NodeRole::Worker as i32;
        assert!(has(&base, "role", "needs k8s"));
        base.role = NodeRole::ControlPlane as i32;
        assert!(has(&base, "role", "needs k8s"));
        // k8s without a role (also a control plane config whose role was left out)
        let mut c = sample();
        c.role = NodeRole::Unspecified as i32;
        assert!(has(&c, "role", "required with k8s"));
        let mut c = cp_sample();
        c.role = NodeRole::Unspecified as i32;
        assert!(has(&c, "role", "required with k8s"));
        let mut c = sample();
        c.role = 3;
        assert!(has(&c, "role", "unknown value 3"));
        // WORKER + init, WORKER + cluster CA
        let mut c = sample();
        c.k8s.as_mut().unwrap().init = cp_sample().k8s.unwrap().init;
        assert!(has(&c, "k8s.init", "for a CONTROL_PLANE"));
        let mut c = sample();
        c.k8s.as_mut().unwrap().cluster_ca_key = cp_sample().k8s.unwrap().cluster_ca_key;
        assert!(has(&c, "k8s.cluster_ca_key", "for a CONTROL_PLANE"));
        // a complete control plane section labelled WORKER: refused, not silently joined
        let mut c = cp_sample();
        c.role = NodeRole::Worker as i32;
        assert!(has(&c, "k8s.init", "for a CONTROL_PLANE") && has(&c, "k8s.api_server_endpoint", "host:port"));
        // CONTROL_PLANE without init, without the CA, with join fields; a worker section labelled CONTROL_PLANE
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().init = None;
        assert!(has(&c, "k8s.init", "required for a CONTROL_PLANE"));
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().cluster_ca_crt.clear();
        assert!(has(&c, "k8s.cluster_ca_crt", ""));
        let mut c = cp_sample();
        c.k8s.as_mut().unwrap().ca_cert_hashes = vec![format!("sha256:{}", "a".repeat(64))];
        assert!(has(&c, "k8s.api_server_endpoint", "for a WORKER"));
        let mut c = sample();
        c.role = NodeRole::ControlPlane as i32;
        assert!(has(&c, "k8s.init", "required for a CONTROL_PLANE") && has(&c, "k8s.api_server_endpoint", "for a WORKER"));
        // the rendered files follow the role
        let names = |c: &NodeConfig| render(c).into_iter().map(|x| x.0).collect::<Vec<_>>();
        assert!(names(&sample()).contains(&K8S_JOIN) && !names(&sample()).contains(&K8S_INIT));
        assert!(names(&cp_sample()).contains(&K8S_INIT) && !names(&cp_sample()).contains(&K8S_JOIN));
    }

    /// A config persisted before the role (schema 1, k8s, UNSPECIFIED) loads with the role inferred the old way;
    /// the file is not rewritten. A config without k8s keeps no role.
    #[test]
    fn r2_legacy_config_role_inferred_on_load() {
        for (c, want) in [(sample(), NodeRole::Worker), (cp_sample(), NodeRole::ControlPlane)] {
            let p = state_root(&format!("legacy-{}", want.as_str_name()));
            let mut old = c.clone();
            old.role = NodeRole::Unspecified as i32;
            save(&p, 4, &old).unwrap();
            let before = fs::read(p.state_dir.join(CONFIG_PB)).unwrap();
            let l = load(&p, true).unwrap();
            assert_eq!((l.generation, role(&l.config)), (4, want));
            assert_eq!(validate(&l.config), vec![], "the inferred config is valid");
            assert_eq!(fs::read(p.state_dir.join(CONFIG_PB)).unwrap(), before, "config.pb not rewritten");
            assert_eq!(NodeConfig::decode(&before[..]).unwrap().role, NodeRole::Unspecified as i32);
        }
        // nothing to infer: no k8s, an explicit role, another schema
        let mut c = sample();
        c.k8s = None;
        assert!(!infer_legacy_role(&mut c) && c.role == NodeRole::Worker as i32);
        let mut c = cp_sample();
        assert!(!infer_legacy_role(&mut c) && role(&c) == NodeRole::ControlPlane);
        let mut c = sample();
        c.role = NodeRole::Unspecified as i32;
        c.schema = 2;
        assert!(!infer_legacy_role(&mut c) && c.role == 0);
    }

    #[test]
    fn save_then_load() {
        let p = state_root("ok");
        assert!(load(&p, true).is_none());
        save(&p, 1, &named("a")).unwrap();
        save(&p, 2, &named("b")).unwrap();
        let l = load(&p, true).unwrap();
        assert_eq!((l.generation, l.config.hostname.as_str()), (2, "b"));
        assert_eq!(files(&p), vec!["config.pb", "generation"]);
    }

    #[test]
    fn cut_while_writing_temporaries_keeps_the_old_pair() {
        for steps in [1, 2] {
            let p = state_root(&format!("tmp{steps}"));
            save(&p, 4, &named("old")).unwrap();
            cut(&p, 5, &named("new"), steps);
            // foil-config only looks
            let l = load(&p, false).unwrap();
            assert_eq!((l.generation, l.config.hostname.as_str()), (4, "old"));
            assert!(files(&p).contains(&".config.pb.tmp".to_string()));
            assert_eq!(recover(&p, true).unwrap(), Recovery::Discarded);
            let l = load(&p, true).unwrap();
            assert_eq!((l.generation, l.config.hostname.as_str()), (4, "old"));
            assert_eq!(files(&p), vec!["config.pb", "generation"]);
        }
    }

    #[test]
    fn cut_between_renames_is_completed() {
        let p = state_root("ren");
        save(&p, 4, &named("old")).unwrap();
        cut(&p, 5, &named("new"), 3);
        let l = load(&p, false).unwrap(); // foil-config: same answer, nothing written
        assert_eq!((l.generation, l.config.hostname.as_str()), (5, "new"));
        assert!(files(&p).contains(&".generation.tmp".to_string()));
        let l = load(&p, true).unwrap();
        assert_eq!((l.generation, l.config.hostname.as_str()), (5, "new"));
        assert_eq!(files(&p), vec!["config.pb", "generation"]);
        assert_eq!(fs::read_to_string(p.state_dir.join("generation")).unwrap(), "5\n");
    }

    #[test]
    fn first_save_cut_between_renames() {
        // from the bridge (generation 1 in memory) the first API config is 2
        for g in [1, 2] {
            let p = state_root(&format!("first{g}"));
            cut(&p, g, &named("new"), 3);
            let l = load(&p, true).unwrap();
            assert_eq!((l.generation, l.config.hostname.as_str()), (g, "new"));
            assert_eq!(files(&p), vec!["config.pb", "generation"]);
        }
    }

    #[test]
    fn stale_or_garbage_generation_tmp_is_dropped() {
        // empty, truncated, not a number, not N+1 (older agent moved on: N+1 or later
        // committed after a rollback, then this tmp is left over)
        for (i, t) in ["", "5", "x\n", "9\n", "4\n"].iter().enumerate() {
            let p = state_root(&format!("stale{i}"));
            save(&p, 6, &named("current")).unwrap();
            fs::write(p.state_dir.join(".generation.tmp"), t).unwrap();
            assert_eq!(recover(&p, true).unwrap(), Recovery::StaleGeneration, "{t:?}");
            let l = load(&p, true).unwrap();
            assert_eq!((l.generation, l.config.hostname.as_str()), (6, "current"), "{t:?}");
            assert_eq!(files(&p), vec!["config.pb", "generation"]);
        }
    }

    #[test]
    fn old_agent_applied_after_a_cut_tmp_is_dropped() {
        // new agent cut between the renames at 5 -> rollback to an old agent that
        // never looks at the tmp and commits 5 itself (its write_atomic) -> back to
        // the new agent: the tmp says 5, the disk says 5: not N+1, dropped.
        let p = state_root("old");
        save(&p, 4, &named("a")).unwrap();
        cut(&p, 5, &named("b"), 3);
        fs::write(p.state_dir.join("config.pb"), named("old-agent").encode_to_vec()).unwrap();
        fs::write(p.state_dir.join("generation"), "5\n").unwrap();
        let l = load(&p, true).unwrap();
        assert_eq!((l.generation, l.config.hostname.as_str()), (5, "old-agent"));
        assert_eq!(files(&p), vec!["config.pb", "generation"]);
    }
}

