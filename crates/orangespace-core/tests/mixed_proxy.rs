use orangespace_core::tunnel::{
    LocalProxyProtocol, TunnelSettings, sing_box_config, sing_box_config_for_protocol,
};
use orangespace_core::{Binding, NodeId, SandboxId, TunnelId, UserId};
use serde_json::json;

fn fixture() -> (Binding, serde_json::Value) {
    let binding = Binding {
        user_id: UserId::new(),
        sandbox_id: SandboxId::new(),
        node_id: NodeId::new(),
        generation: 1,
        tunnel_id: TunnelId::new(),
    };
    let value = json!({"node_id":binding.node_id,"endpoint_ip":"127.0.0.1","endpoint_port":443,"tls_server_name":"node.example.test","tuic_uuid":uuid::Uuid::new_v4(),"tuic_password":"fixture-only-tuic-password","socks_port":12345,"socks_username":"fixture-user","socks_password":"fixture-only-local-password","certificate":"fixture-inline-ca"});
    (binding, value)
}

#[test]
fn mixed_is_explicit_and_changes_only_inbound_protocol_and_system_proxy_setting() {
    let (binding, value) = fixture();
    let settings: TunnelSettings = serde_json::from_value(value).unwrap();
    let legacy = sing_box_config(binding, &settings).unwrap();
    assert_eq!(legacy["inbounds"][0]["type"], "socks");
    assert_eq!(
        sing_box_config_for_protocol(binding, &settings, LocalProxyProtocol::Socks).unwrap(),
        legacy
    );
    let mut expected = legacy.clone();
    expected["inbounds"][0]["type"] = json!("mixed");
    expected["inbounds"][0]["set_system_proxy"] = json!(false);
    let mixed =
        sing_box_config_for_protocol(binding, &settings, LocalProxyProtocol::AuthenticatedMixed)
            .unwrap();
    assert_eq!(mixed, expected);
    assert_eq!(mixed["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(mixed["inbounds"][0]["users"].as_array().unwrap().len(), 1);
    assert_eq!(mixed["outbounds"].as_array().unwrap().len(), 1);
    assert_eq!(mixed["outbounds"][0]["type"], "tuic");
    assert_eq!(mixed["route"]["final"], mixed["outbounds"][0]["tag"]);
    assert_eq!(sing_box_config(binding, &settings).unwrap(), legacy);
}

#[test]
fn mixed_keeps_all_existing_identity_and_credential_rejections() {
    let (binding, value) = fixture();
    for field in [
        "socks_password",
        "socks_username",
        "tuic_password",
        "tls_server_name",
    ] {
        let mut invalid = value.clone();
        invalid[field] = json!("");
        let settings: TunnelSettings = serde_json::from_value(invalid).unwrap();
        assert!(
            sing_box_config_for_protocol(
                binding,
                &settings,
                LocalProxyProtocol::AuthenticatedMixed
            )
            .is_err()
        );
    }
    let mut invalid = value;
    invalid["node_id"] = json!(NodeId::new());
    let settings: TunnelSettings = serde_json::from_value(invalid).unwrap();
    assert!(
        sing_box_config_for_protocol(binding, &settings, LocalProxyProtocol::AuthenticatedMixed)
            .is_err()
    );
}
