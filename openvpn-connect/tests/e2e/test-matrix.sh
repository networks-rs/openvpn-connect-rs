#!/bin/sh
set -eu

run_e2e() {
    label=$1
    features=$2
    echo "E2E feature scenario: $label ($features)"
    cargo test \
        -p openvpn-connect \
        --test e2e \
        --no-default-features \
        --features "$features" \
        -- \
        --include-ignored \
        --nocapture \
        --test-threads=1
}

# Run the complete ordinary and ignored suite once with every optional native
# adapter enabled. DCO is compiled and driven through its deterministic
# callback probe while live sessions deliberately use the portable TUN path.
cargo test \
    -p openvpn-connect \
    --tests \
    --no-default-features \
    --features vendor,tokio,dco,external-transport,external-tun \
    -- \
    --include-ignored \
    --nocapture \
    --test-threads=1

# Exercise each packet-I/O topology independently. The dynamic baseline also
# verifies the source-built shared-library mode; optional factory scenarios use
# the static vendor mode so both supported link modes reach a real server.
run_e2e "dynamic native transport + native TUN" "tokio"
run_e2e "external transport + native TUN" "vendor,tokio,external-transport"
run_e2e "native transport + external TUN" "vendor,tokio,external-tun"
