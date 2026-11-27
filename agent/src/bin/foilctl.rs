// SPDX-License-Identifier: Apache-2.0
//! foilctl — minimal client for the node agent (diagnostics and lab tests).
//!
//!   foilctl --addr https://HOST:7443 --tls-dir DIR [--server-name NAME] info|health|config|update-status
//!   foilctl ... --hostname H --mac M (--address CIDR --gateway IP --dns IP | --dhcp)
//!          [--role worker --k8s-endpoint HOST:PORT --k8s-token T --k8s-ca-hash sha256:H [--k8s-labels K=V,..] [--k8s-taints K=V:Effect,..]]
//!          [--role control-plane --k8s-init FILE --k8s-ca-crt FILE --k8s-ca-key FILE]   (--role is required with any --k8s-*)
//!          [--channel HOST[:PORT][/prefix/] --channel-ca FILE]
//!          [--mirror REGISTRY=HOST[:PORT][/prefix] [--mirror-ca FILE] [--registry-ca FILE]]
//!          [--host IP=NAME[,NAME]] --expected-generation N apply
//!   foilctl ... [--reason TEXT] [--expect-staged V] reboot
//!   foilctl ... --expect-booted V [--reason TEXT] rollback   (DESTRUCTIVE: back to the previous release, reboots)
//!   foilctl --on-behalf-of WHO ...   (any command: recorded in the node's audit log, never grants anything)
//!   foilctl ... --target V stage
//!   foilctl ... [--failed] units
//!   foilctl ... [--unit NAME.TYPE] [--priority 0-7] [--boot 0|-1|..] [--since UNIX] [--until UNIX] [--limit N] journal
//!          (--unit: the full unit name, e.g. foil-agent.service, kubelet.service; a short name is refused, InvalidArgument.
//!          The agent's audit lines are WARN, priority 4: --priority 4 shows them)
//!   foilctl ... [--boot 0|-1|..] [--priority 0-7] [--limit N] dmesg
//!
//! DIR holds client.crt, client.key and ca.crt (PEM).
//! A call the agent does not serve because it speaks another API version fails with
//! "API version mismatch: the agent speaks API X, foilctl speaks API Y" (exit 1).
use foil_agent::pb::{self, node_agent_client::NodeAgentClient};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

/// The role is explicit; with any --k8s-* flag it is required (checked before connecting to the agent).
fn role_arg(args: &[String]) -> Result<pb::NodeRole, String> {
    let role = match arg(args, "--role").as_deref() {
        None => pb::NodeRole::Unspecified,
        Some("worker") => pb::NodeRole::Worker,
        Some("control-plane") => pb::NodeRole::ControlPlane,
        Some(r) => return Err(format!("--role {r}: expected worker or control-plane")),
    };
    if role == pb::NodeRole::Unspecified && args.iter().any(|x| x.starts_with("--k8s-")) {
        return Err("--role worker|control-plane is required with --k8s-* flags".into());
    }
    Ok(role)
}

fn arg(args: &[String], n: &str) -> Option<String> {
    args.iter().position(|a| a == n).and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A CLI dies quietly when its reader goes away (`foilctl ... | head -1`): the Rust runtime ignores SIGPIPE, so
    // println! on a closed pipe panicked (exit 101 and a panic message). Default action: killed by SIGPIPE (shell
    // status 141), no core. Sockets are unaffected: the gRPC connection writes with MSG_NOSIGNAL.
    // SAFETY: first statement of main, no thread of ours runs yet (current_thread runtime).
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = arg(&args, "--addr").ok_or("--addr required")?;
    let dir = std::path::PathBuf::from(arg(&args, "--tls-dir").ok_or("--tls-dir required")?);
    let cmd = args.last().cloned().unwrap_or_default();
    if cmd == "apply" {
        role_arg(&args)?; // before reading TLS material or connecting
    }
    let rd = |n: &str| std::fs::read(dir.join(n)).map_err(|e| format!("{n}: {e}"));
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(rd("ca.crt")?))
        .identity(Identity::from_pem(rd("client.crt")?, rd("client.key")?));
    if let Some(n) = arg(&args, "--server-name") {
        tls = tls.domain_name(n);
    }
    let ch = Channel::from_shared(addr)?.tls_config(tls)?.connect().await?;
    // x-foilbird-on-behalf-of: audit only (the gateway's human/ticket); roles come from the certificate
    let obo: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>> =
        arg(&args, "--on-behalf-of").map(|v| v.parse()).transpose().map_err(|_| "--on-behalf-of: printable ASCII")?;
    let mut c = NodeAgentClient::with_interceptor(ch.clone(), move |mut req: tonic::Request<()>| {
        if let Some(v) = &obo {
            req.metadata_mut().insert("x-foilbird-on-behalf-of", v.clone());
        }
        Ok(req)
    });
    // ADR 0016: ask Discovery first; an agent that does not serve foilctl's API is refused before any call. An agent
    // without Discovery (older) goes on: its Unimplemented is explained below (header, earlier packages)
    if let Some(d) = foil_agent::compat::discover(ch.clone()).await? {
        foil_agent::compat::served(&d, foil_agent::API)?;
    }
    // a call the agent does not serve (another API version) is reported as "agent API X, foilctl API Y"
    let r: Result<(), Box<dyn std::error::Error>> = async {
        match cmd.as_str() {
            "info" => println!("{:#?}", c.get_info(pb::GetInfoRequest {}).await?.into_inner()),
            "health" => println!("{:#?}", c.get_health(pb::GetHealthRequest {}).await?.into_inner()),
            "config" => println!("{:#?}", c.get_config(pb::GetConfigRequest {}).await?.into_inner()),
            "update-status" => println!("{:#?}", c.get_update_status(pb::GetUpdateStatusRequest {}).await?.into_inner()),
            "apply" => {
                let a = |n: &str| arg(&args, n).unwrap_or_default();
                let many = |n: &str| -> Vec<String> { arg(&args, n).map(|s| s.split(',').map(str::to_string).collect()).unwrap_or_default() };
                let rd = |n: &str| -> Result<String, String> {
                    match arg(&args, n) {
                        Some(f) => std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}")),
                        None => Ok(String::new()),
                    }
                };
                // worker: --k8s-endpoint/--k8s-token/--k8s-ca-hash; control plane v0: --k8s-init FILE --k8s-ca-crt FILE --k8s-ca-key FILE
                let init = rd("--k8s-init")?;
                let secret = |v: String| (!v.is_empty()).then(|| pb::SecretString { value: v, sha256: String::new() });
                let k8s = arg(&args, "--k8s-endpoint").or_else(|| (!init.is_empty()).then(String::new)).map(|ep| pb::K8sConfig {
                    api_server_endpoint: ep,
                    bootstrap_token: secret(a("--k8s-token")),
                    ca_cert_hashes: many("--k8s-ca-hash"),
                    init: secret(init.clone()),
                    node_ip: a("--k8s-node-ip"),
                    cluster_ca_crt: rd("--k8s-ca-crt").unwrap_or_default(),
                    cluster_ca_key: secret(rd("--k8s-ca-key").unwrap_or_default()),
                    // --k8s-labels k=v,k2=v2  --k8s-taints key=value:Effect,key:Effect (bridge formats)
                    node_labels: arg(&args, "--k8s-labels")
                        .map(|s| s.split(',').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect())
                        .unwrap_or_default(),
                    node_taints: arg(&args, "--k8s-taints")
                        .map(|s| {
                            s.split(',')
                                .filter_map(|t| {
                                    let (kv, eff) = t.rsplit_once(':')?;
                                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                                    let effect = match eff {
                                        "NoSchedule" => pb::TaintEffect::NoSchedule,
                                        "PreferNoSchedule" => pb::TaintEffect::PreferNoSchedule,
                                        "NoExecute" => pb::TaintEffect::NoExecute,
                                        _ => pb::TaintEffect::Unspecified,
                                    } as i32;
                                    Some(pb::Taint { key: k.into(), value: v.into(), effect })
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                });
                let role = role_arg(&args)?;
                let cfg = pb::NodeConfig {
                    schema: 1,
                    role: role as i32,
                    hostname: a("--hostname"),
                    network: Some(pb::NetworkConfig {
                        // second interface (lab: private L2 between QEMU guests): --mac2 MAC --address2 CIDR
                        interfaces: [pb::Interface {
                            r#match: Some(pb::interface::Match::MacAddress(a("--mac"))),
                            dhcp4: args.iter().any(|x| x == "--dhcp"),
                            addresses: many("--address"),
                            gateway4: a("--gateway"),
                            dns: many("--dns"),
                            ..Default::default()
                        }]
                        .into_iter()
                        .chain(arg(&args, "--mac2").map(|m| pb::Interface {
                            r#match: Some(pb::interface::Match::MacAddress(m)),
                            addresses: many("--address2"),
                            ..Default::default()
                        }))
                        .collect(),
                    }),
                    k8s,
                    // --channel HOST[:PORT][/prefix/] --channel-ca FILE (always https)
                    update_channel: match arg(&args, "--channel") {
                        None => None,
                        Some(ch) => {
                            let (endpoint, prefix) = match ch.split_once('/') {
                                Some((e, p)) => (e.to_string(), format!("/{p}")),
                                None => (ch.clone(), String::new()),
                            };
                            let ca = arg(&args, "--channel-ca").ok_or("--channel-ca required with --channel")?;
                            Some(pb::UpdateChannel { endpoint, prefix, ca_pem: std::fs::read_to_string(&ca).map_err(|e| format!("{ca}: {e}"))? })
                        }
                    },
                    // --mirror REGISTRY=HOST[:PORT][/v2/prefix] [--mirror-ca FILE] [--registry-ca FILE] (one registry)
                    registries: match arg(&args, "--mirror") {
                        None => vec![],
                        // several registries: --mirror REGISTRY=HOST/prefix,REGISTRY=HOST/prefix (same --mirror-ca/--registry-ca for all)
                        Some(m) => {
                            let rd = |n: &str| -> Result<String, String> {
                                arg(&args, n).map(|f| std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}"))).transpose().map(Option::unwrap_or_default)
                            };
                            let (mca, rca) = (rd("--mirror-ca")?, rd("--registry-ca")?);
                            let mut out = Vec::new();
                            for one in m.split(',') {
                                let (registry, target) = one.split_once('=').ok_or("--mirror REGISTRY=HOST[:PORT][/prefix][,...]")?;
                                let (endpoint, prefix) = match target.split_once('/') {
                                    Some((e, p)) => (e.to_string(), format!("/{p}")),
                                    None => (target.to_string(), String::new()),
                                };
                                out.push(pb::RegistryHost {
                                    registry: registry.to_string(),
                                    mirrors: vec![pb::RegistryMirror { endpoint, prefix, ca_pem: mca.clone() }],
                                    ca_pem: rca.clone(),
                                });
                            }
                            out
                        }
                    },
                    // --host IP=NAME[,NAME...] (one entry)
                    extra_host_entries: match arg(&args, "--host") {
                        None => vec![],
                        Some(h) => {
                            let (ip, names) = h.split_once('=').ok_or("--host IP=NAME[,NAME]")?;
                            vec![pb::HostEntry { ip: ip.into(), hostnames: names.split(',').map(str::to_string).collect() }]
                        }
                    },
                    // --ntp SERVER[,SERVER...]
                    time: arg(&args, "--ntp").map(|_| pb::TimeConfig { servers: many("--ntp") }),
                    ..Default::default()
                };
                let expected_generation = arg(&args, "--expected-generation").ok_or("--expected-generation required")?.parse()?;
                println!("{:#?}", c.apply_config(pb::ApplyConfigRequest { config: Some(cfg), expected_generation }).await?.into_inner());
            }
            "reboot" => {
                let expect_staged = arg(&args, "--expect-staged").map(|v| pb::Version { image_version: v });
                let reason = arg(&args, "--reason").unwrap_or_else(|| "foilctl".into());
                println!("{:#?}", c.reboot(pb::RebootRequest { reason, expect_staged }).await?.into_inner());
            }
            // DESTRUCTIVE: the booted, committed release is abandoned and the node reboots into the previous one
            "rollback" => {
                let v = arg(&args, "--expect-booted").ok_or("--expect-booted VERSION required")?;
                let reason = arg(&args, "--reason").unwrap_or_else(|| "foilctl".into());
                println!("{:#?}", c.rollback(pb::RollbackRequest { expect_booted: Some(pb::Version { image_version: v }), reason }).await?.into_inner());
            }
            // DESTRUCTIVE: wipes the /var key slots of older PCR epochs (image unit), raises the floor
            "raise" => {
                let v = arg(&args, "--expect-booted").ok_or("--expect-booted VERSION required")?;
                let r = c.raise_min_version(pb::RaiseMinVersionRequest { expect_booted: Some(pb::Version { image_version: v }) }).await?.into_inner();
                println!("{r:#?}");
            }
            "stage" => {
                let v = arg(&args, "--target").ok_or("--target required")?;
                println!("{:#?}", c.stage_update(pb::StageUpdateRequest { target: Some(pb::Version { image_version: v }) }).await?.into_inner());
            }
            "units" => {
                let r = c.list_units(pb::ListUnitsRequest { failed_only: args.iter().any(|x| x == "--failed") }).await?.into_inner();
                for u in r.units {
                    println!("{:<50} {:<10} {:<10} {:<10} {}", u.name, u.load_state, u.active_state, u.sub_state, u.description);
                }
            }
            "journal" | "dmesg" => {
                let num = |n: &str| arg(&args, n).map(|s| s.parse::<i64>()).transpose();
                let boot = num("--boot")?.unwrap_or(0) as i32;
                let limit = num("--limit")?.unwrap_or(0) as u32;
                let max_priority = num("--priority")?.map(|p| p as u32);
                let r = if cmd == "dmesg" {
                    c.read_kernel_log(pb::ReadKernelLogRequest { boot, max_priority, limit }).await?.into_inner()
                } else {
                    c.read_journal(pb::ReadJournalRequest {
                        unit: arg(&args, "--unit").unwrap_or_default(),
                        max_priority,
                        boot,
                        since_unix: num("--since")?.unwrap_or(0),
                        until_unix: num("--until")?.unwrap_or(0),
                        limit,
                    })
                    .await?
                    .into_inner()
                };
                for e in &r.entries {
                    let who = if e.identifier.is_empty() { e.unit.clone() } else { e.identifier.clone() };
                    println!("{} <{}> {}[{}]: {}", utc(e.realtime_usec / 1_000_000), e.priority, who, e.pid, e.message);
                }
                let boots: Vec<String> = r.boots.iter().map(|b| format!("{}={}", b.offset, &b.boot_id[..8.min(b.boot_id.len())])).collect();
                eprintln!("-- {} entries{}, {} redactions; boots: {}", r.entries.len(), if r.truncated { " (truncated)" } else { "" }, r.redactions, boots.join(" "));
            }
            // EMERGENCY: the unredacted journal goes only to --out (mode 0600), never to
            // stdout; stdout gets metadata (counts, bytes, sha256 of the file).
            "collect" => {
                let out = arg(&args, "--out").ok_or("--out FILE required (the dump is not printed)")?;
                let boot = arg(&args, "--boot").map(|s| s.parse::<i32>()).transpose()?.unwrap_or(0);
                let max_entries = arg(&args, "--limit").map(|s| s.parse::<u32>()).transpose()?.unwrap_or(0);
                let r = c.collect_diagnostics(pb::CollectDiagnosticsRequest { boot, max_entries }).await?.into_inner();
                let boots: Vec<String> = r.boots.iter().map(|b| format!("{}={}", b.offset, &b.boot_id[..8.min(b.boot_id.len())])).collect();
                let header = format!(
                    "# foilbird CollectDiagnostics boot={boot} entries={} message_bytes={} truncated={} boots: {}\n",
                    r.entries.len(),
                    r.message_bytes,
                    r.truncated,
                    boots.join(" ")
                );
                let mut body = header.clone();
                for e in &r.entries {
                    let who = if e.identifier.is_empty() { e.unit.clone() } else { e.identifier.clone() };
                    body += &format!("{} <{}> {}[{}]: {}\n", utc(e.realtime_usec / 1_000_000), e.priority, who, e.pid, e.message);
                }
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&out).map_err(|e| format!("{out}: {e}"))?;
                f.write_all(body.as_bytes())?;
                use sha2::Digest;
                print!("{header}");
                println!("file={out} bytes={} sha256={}", body.len(), hex::encode(sha2::Sha256::digest(body.as_bytes())));
            }
            _ => return Err("command: info|health|config|update-status|stage|apply|reboot|rollback|units|journal|dmesg|collect|raise".into()),
        }
        Ok(())
    }
    .await;
    if let Some(st) = r.as_ref().err().and_then(|e| e.downcast_ref::<tonic::Status>()) {
        if let Some(m) = foil_agent::compat::explain(&ch, st, foil_agent::API).await {
            return Err(m.into());
        }
    }
    r
}

/// Unix seconds -> "YYYY-MM-DDTHH:MM:SSZ" (civil-from-days, no time zone).
fn utc(secs: i64) -> String {
    let (d, s) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = d + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
}
