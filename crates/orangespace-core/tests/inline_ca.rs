use orangespace_core::tunnel::{TunnelSettings, sing_box_config};
use orangespace_core::{Binding, NodeId, SandboxId, TunnelId, UserId};
use serde_json::json;
#[test]
fn inline_ca_is_explicit_and_old_settings_remain_unchanged() {
    let b = Binding {
        user_id: UserId::new(),
        sandbox_id: SandboxId::new(),
        node_id: NodeId::new(),
        generation: 1,
        tunnel_id: TunnelId::new(),
    };
    let value = json!({"node_id":b.node_id,"endpoint_ip":"127.0.0.1","endpoint_port":443,"tls_server_name":"node.example.test","tuic_uuid":uuid::Uuid::new_v4(),"tuic_password":"fixture-only-tuic-password","socks_port":12345,"socks_username":"fixture","socks_password":"fixture-only-socks-password"});
    let mut s: TunnelSettings = serde_json::from_value(value).unwrap();
    let original = sing_box_config(b, &s).unwrap();
    assert!(original["outbounds"][0]["tls"].get("certificate").is_none());
    s.certificate = Some("fixture-inline-ca".into());
    let actual = sing_box_config(b, &s).unwrap();
    assert_eq!(
        actual["outbounds"][0]["tls"]["certificate"],
        "fixture-inline-ca"
    );
    assert_eq!(actual["outbounds"][0]["tls"]["insecure"], false);
    s.certificate = None;
    assert_eq!(sing_box_config(b, &s).unwrap(), original);
}
