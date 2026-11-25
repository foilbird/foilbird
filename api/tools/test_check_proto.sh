#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# T8: the real API passes, the negative fixture fails with every rule hit.
set -eu
d=$(dirname "$0")
python3 -I "$d/check_proto.py"
out=$(python3 -I "$d/check_proto.py" "$d/testdata/bad" 2>&1) && { echo "negative fixture passed"; exit 1; }
echo "$out" | grep -q 'check_proto: 1 files, 2 rpcs, 10 errors' || { echo "$out"; exit 1; }
# Discovery is frozen (ADR 0016): each change of a copy of the real tree must fail with its own message
mut() { # mut <expected message> <file under proto/> <sed expression>
  t=$(mktemp -d); cp -r "$d/../proto" "$t/proto"; sed -i "$3" "$t/proto/$2"
  o=$(python3 -I "$d/check_proto.py" "$t/proto" 2>&1) && { echo "mutation passed: $3"; rm -rf "$t"; exit 1; }
  echo "$o" | grep -q -F "$1" || { echo "mutation $3: expected '$1':"; echo "$o"; rm -rf "$t"; exit 1; }
  rm -rf "$t"; n=$((n + 1))
}
n=0; D=foilbird/agent/discovery.proto
mut "frozen: GetApiVersionsResponse.served_apis must stay = 2 repeated string" $D '/served_apis = 2/d'
mut "frozen: GetApiVersionsResponse.served_apis must stay = 2 repeated string" $D 's/served_apis = 2/served_apis = 4/'
mut "frozen: GetApiVersionsResponse.agent_version must stay = 1 single string" $D 's/string agent_version = 1/bytes agent_version = 1/'
mut "frozen: GetApiVersionsResponse reserved 3 removed" $D '/reserved 3;/d'
mut "a new Discovery field needs its line in discovery.fields" $D 's/reserved 3;/reserved 3;\n  string build = 4;/'
mut "Discovery carries no options" $D 's/returns (GetApiVersionsResponse);/returns (GetApiVersionsResponse) { option (foilbird.agent.v1alpha1.access) = ACCESS_LEVEL_READ; }/'
mut "Discovery imports nothing" $D 's/^package foilbird.agent;/package foilbird.agent;\nimport "foilbird\/agent\/v1alpha1\/options.proto";/'
mut "frozen: service Discovery rpc GetApiVersions" $D 's/rpc GetApiVersions/rpc ListApis/'
mut "must be the API package without its version" $D 's/^package foilbird.agent;/package foilbird.node;/'
mut "a service lives in" foilbird/agent/v1alpha1/agent.proto 's/^package foilbird.agent.v1alpha1;/package foilbird.agent.latest;/'
echo "discovery mutations: $n/10 fail as expected"
# MCP level filter: no EMERGENCY RPC is ever published (api/README.md, access levels; T12).
mcp=$(python3 -I "$d/check_proto.py" --mcp)
echo "$mcp" | grep -q '^GetInfo ACCESS_LEVEL_READ$' || { echo "mcp filter lost GetInfo"; exit 1; }
echo "$mcp" | grep -q '^RaiseMinVersion ACCESS_LEVEL_DESTRUCTIVE$' || { echo "mcp filter lost RaiseMinVersion"; exit 1; }
if echo "$mcp" | grep -q -e EMERGENCY -e '^CollectDiagnostics '; then echo "EMERGENCY rpc in MCP list"; exit 1; fi
grep -q 'rpc CollectDiagnostics' "$d/../proto/foilbird/agent/v1alpha1/agent.proto" || { echo "no EMERGENCY rpc to check"; exit 1; }
echo "T8 check_proto: ok"
