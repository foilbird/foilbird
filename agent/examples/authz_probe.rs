// SPDX-License-Identifier: Apache-2.0
//! T12 ext (lab tool, not shipped in the image): call every RPC once with a
//! certificate and print "<Rpc> <ALLOW|DENY> <grpc code>" per line, or
//! "<Rpc> ERROR transport" when the call never reached the server (exit 1 then);
//! compare with
//! the matrix from the .proto (api/tools/authz_matrix.py). Arguments are chosen
//! so that no allowed call changes the node (tests/common/authz_calls.rs).
//!
//!   authz_probe --addr https://HOST:7443 --tls-dir DIR [--server-name NAME]
#[path = "../tests/common/authz_calls.rs"]
mod authz_calls;
use foil_agent::pb::node_agent_client::NodeAgentClient;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

fn arg(args: &[String], n: &str) -> Option<String> {
    args.iter().position(|a| a == n).and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = arg(&args, "--addr").ok_or("--addr required")?;
    let dir = std::path::PathBuf::from(arg(&args, "--tls-dir").ok_or("--tls-dir required")?);
    let rd = |n: &str| std::fs::read(dir.join(n)).map_err(|e| format!("{n}: {e}"));
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(rd("ca.crt")?))
        .identity(Identity::from_pem(rd("client.crt")?, rd("client.key")?));
    if let Some(n) = arg(&args, "--server-name") {
        tls = tls.domain_name(n);
    }
    let ch = Channel::from_shared(addr)?.tls_config(tls)?.connect().await?;
    let mut c = NodeAgentClient::new(ch);
    let mut errors = 0;
    for (m, o) in authz_calls::probe(&mut c).await {
        match o {
            authz_calls::Outcome::Allow(code) | authz_calls::Outcome::Deny(code) => println!("{m} {} {code:?}", o.label()),
            authz_calls::Outcome::Error => {
                errors += 1;
                println!("{m} ERROR transport");
            }
        }
    }
    if errors > 0 {
        eprintln!("{errors} call(s) did not reach the server: not an authorization result");
        std::process::exit(1);
    }
    Ok(())
}
