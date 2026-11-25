// SPDX-License-Identifier: Apache-2.0
// Compiles api/proto without protoc (protox) and generates the RPC -> (access
// level, roles) table from the (foilbird.agent.v1alpha1.access) and (foilbird.agent.v1alpha1.roles)
// method options, so the .proto stays the single source of truth for
// authorization. An RPC without a level or without roles fails the build.
use std::{env, fmt::Write, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("../api/proto");
    println!("cargo:rerun-if-changed={}", root.display());

    let mut c = protox::Compiler::new([&root])?;
    c.include_imports(true).include_source_info(false);
    c.open_file("foilbird/agent/v1alpha1/agent.proto")?;
    // Discovery (ADR 0016): the unversioned, frozen service a client asks for the API versions an agent serves
    c.open_file("foilbird/agent/discovery.proto")?;
    let pool = c.descriptor_pool();
    let ext = pool
        .get_extension_by_name("foilbird.agent.v1alpha1.access")
        .ok_or("extension foilbird.agent.v1alpha1.access not found")?;
    let roles_ext = pool
        .get_extension_by_name("foilbird.agent.v1alpha1.roles")
        .ok_or("extension foilbird.agent.v1alpha1.roles not found")?;

    // API version = the package of the one service (foilbird.agent.v1alpha1): reported by the agent (GetInfo.api, header x-foilbird-api)
    // and compared by foilctl, so a client of another package gets "agent API X, foilctl API Y" instead of a bare error.
    // Two services: the versioned NodeAgent (<prefix>.agent.<version>) and Discovery in the unversioned package
    // <prefix>.agent (no method options: any client of the agent's CA may call it, authz.rs).
    let (agents, disc): (Vec<_>, Vec<_>) = pool.services().partition(|s| s.name() == "NodeAgent");
    if agents.len() != 1 || disc.len() != 1 || disc[0].name() != "Discovery" {
        return Err(format!("expected one NodeAgent and one Discovery service, found {:?}", pool.services().map(|s| s.full_name().to_string()).collect::<Vec<_>>()).into());
    }
    let api = agents[0].full_name().rsplit_once('.').map(|(p, _)| p.to_string()).ok_or("service without a package")?;
    let disc_pkg = disc[0].full_name().rsplit_once('.').map(|(p, _)| p.to_string()).ok_or("Discovery without a package")?;
    if api.rsplit_once('.').map(|(p, _)| p) != Some(disc_pkg.as_str()) {
        return Err(format!("Discovery must be in the package of the API without its version: {disc_pkg} vs {api}").into());
    }
    for m in disc[0].methods() {
        if m.options().has_extension(&ext) || m.options().has_extension(&roles_ext) {
            return Err(format!("{}: Discovery carries no access options (any client of the CA)", m.full_name()).into());
        }
    }
    let mut table = format!(
        "pub const API: &str = {api:?};\npub const DISCOVERY: &str = \"/{}/\";\npub const ACCESS: &[(&str, i32, &[i32])] = &[\n",
        disc[0].full_name()
    );
    for svc in agents {
        for m in svc.methods() {
            let opts = m.options();
            if !opts.has_extension(&ext) {
                return Err(format!("{}: no access option", m.full_name()).into());
            }
            let lvl = opts
                .get_extension(&ext)
                .as_enum_number()
                .ok_or("access option is not an enum")?;
            if lvl == 0 {
                return Err(format!("{}: access level UNSPECIFIED", m.full_name()).into());
            }
            let roles: Vec<i32> = if opts.has_extension(&roles_ext) {
                opts.get_extension(&roles_ext)
                    .as_list()
                    .ok_or("roles option is not a list")?
                    .iter()
                    .map(|v| v.as_enum_number().ok_or("role is not an enum"))
                    .collect::<Result<_, _>>()?
            } else {
                Vec::new()
            };
            if roles.is_empty() || roles.contains(&0) {
                return Err(format!("{}: no roles or ROLE_UNSPECIFIED", m.full_name()).into());
            }
            writeln!(table, "    (\"/{}/{}\", {}, &{:?}),", svc.full_name(), m.name(), lvl, roles)?;
        }
    }
    table.push_str("];\n");
    fs::write(PathBuf::from(env::var("OUT_DIR")?).join("access.rs"), table)?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(c.file_descriptor_set())?;
    Ok(())
}
