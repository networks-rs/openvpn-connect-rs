use std::env;

use openvpn_connect::{Config, evaluate_config, merge_config_path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: cargo run -p openvpn-connect --example profile -- client.ovpn")?;
    let merged = merge_config_path(&path, true);
    if !merged.error_text.is_empty() {
        return Err(merged.error_text.into());
    }

    let evaluation = evaluate_config(&Config::new(merged.profile_content))?;
    println!("profile: {}", evaluation.profile_name);
    println!(
        "remote: {}:{} ({})",
        evaluation.remote_host, evaluation.remote_port, evaluation.remote_proto
    );
    println!("autologin: {}", evaluation.autologin);
    println!("external PKI: {}", evaluation.external_pki);
    println!("DCO compatible: {}", evaluation.dco_compatible);
    if !evaluation.dco_incompatibility_reason.is_empty() {
        println!("DCO reason: {}", evaluation.dco_incompatibility_reason);
    }
    for server in evaluation.servers {
        println!("server: {} ({})", server.server, server.friendly_name);
    }
    Ok(())
}
