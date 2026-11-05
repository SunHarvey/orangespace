use orangespace_core::tunnel::{TunnelSettings, sing_box_config};
use orangespace_core::{Binding, NodeId, SandboxId, TunnelId, UserId};
use serde_json::json;

fn config(
    endpoint: &str,
    identity: &str,
) -> Result<serde_json::Value, orangespace_core::tunnel::ConfigError> {
    let binding = Binding {
        user_id: UserId::new(),
        sandbox_id: SandboxId::new(),
        node_id: NodeId::new(),
        generation: 1,
        tunnel_id: TunnelId::new(),
    };
    let settings: TunnelSettings = serde_json::from_value(json!({
        "node_id":binding.node_id,"endpoint_ip":endpoint,"endpoint_port":443,
        "tls_server_name":identity,"tuic_uuid":uuid::Uuid::new_v4(),
        "tuic_password":"fixture-only-tuic-password","socks_port":19080,
        "socks_username":"fixture-broker","socks_password":"fixture-only-socks-password"
    }))
    .unwrap();
    sing_box_config(binding, &settings)
}

#[test]
fn canonical_ip_san_identity_matching_endpoint_keeps_normal_tls_validation() {
    for ip in ["203.0.113.10", "2001:db8::10"] {
        let value = config(ip, ip).expect("normal IP-SAN verification is a valid TLS identity");
        assert_eq!(value["outbounds"][0]["tls"]["server_name"], ip);
        assert_eq!(value["outbounds"][0]["tls"]["insecure"], false);
        assert!(
            value["outbounds"][0]["tls"]
                .get("certificate_path")
                .is_none()
        );
    }
}

#[test]
fn mismatched_or_noncanonical_ip_identity_does_not_become_a_dns_name() {
    for identity in [
        "203.0.113.11",
        "203.0.113.010",
        "2001:0db8::10",
        "[2001:db8::10]",
        "203.0.113.10 ",
    ] {
        assert!(
            config("203.0.113.10", identity).is_err(),
            "accepted invalid identity"
        );
    }
    assert!(config("203.0.113.10", "node.example.test").is_ok());
}
