use orangespace_core::{
    Binding, NodeId, SandboxId, TransferTarget, UserId,
    routing::{RouteError, Router},
    tunnel::{TunnelSettings, sing_box_config},
};
use serde_json::json;

fn setup(router: &mut Router, user: UserId, node: NodeId) -> Binding {
    let sandbox = SandboxId::new();
    router.create(user, sandbox).unwrap();
    let b = router.begin_tunnel(user, sandbox, node).unwrap();
    router.transport_connected(b).unwrap();
    b
}

#[test]
fn same_stream_and_udp_numbers_do_not_cross_nodes_or_users() {
    let mut router = Router::default();
    let user_a = UserId::new();
    let shenzhen = NodeId::new();
    let a = setup(&mut router, user_a, shenzhen);
    let b = setup(&mut router, user_a, NodeId::new());
    let c = setup(&mut router, UserId::new(), shenzhen);
    for (binding, socket) in [(a, 100), (b, 200), (c, 300)] {
        router.register_tcp(binding, 4, socket).unwrap();
        assert_eq!(router.udp_association(binding, socket).unwrap(), 0);
    }
    for (binding, socket) in [(a, 100), (b, 200), (c, 300)] {
        assert_eq!(router.resolve_tcp(binding, 4).unwrap(), socket);
        assert_eq!(router.resolve_udp(binding, 0).unwrap(), socket);
    }
    let forged = Binding {
        node_id: b.node_id,
        ..a
    };
    assert_eq!(router.resolve_tcp(forged, 4), Err(RouteError::Offline));
    let forged = Binding {
        user_id: c.user_id,
        ..a
    };
    assert_eq!(router.resolve_udp(forged, 0), Err(RouteError::Offline));
}

#[test]
fn rebinding_drops_old_flows_and_does_not_move_file_tasks() {
    let mut router = Router::default();
    let old = setup(&mut router, UserId::new(), NodeId::new());
    let task = TransferTarget::from_binding(old);
    router.register_tcp(old, 4, 100).unwrap();
    router.udp_association(old, 100).unwrap();
    let new = router
        .begin_tunnel(old.user_id, old.sandbox_id, NodeId::new())
        .unwrap();
    assert!(new.generation > old.generation);
    assert_ne!(new.tunnel_id, old.tunnel_id);
    assert_eq!(router.resolve_tcp(old, 4), Err(RouteError::Offline));
    assert_eq!(router.transport_connected(old), Err(RouteError::Offline));
    assert_eq!(router.register_tcp(new, 4, 200), Err(RouteError::Offline));
    router.transport_connected(new).unwrap();
    router.register_tcp(new, 4, 200).unwrap();
    assert_eq!(router.disconnect(old), Err(RouteError::Offline));
    assert_eq!(router.resolve_tcp(new, 4).unwrap(), 200);
    assert_eq!(task.node_id(), old.node_id);
}

#[test]
fn loss_disconnect_never_falls_back_and_same_node_is_still_separate() {
    let mut router = Router::default();
    let user = UserId::new();
    let node = NodeId::new();
    let a = setup(&mut router, user, node);
    let b = setup(&mut router, user, node);
    assert_ne!(a.tunnel_id, b.tunnel_id);
    router.register_tcp(a, 4, 100).unwrap();
    router.register_tcp(b, 4, 200).unwrap();
    router.disconnect(a).unwrap();
    assert_eq!(router.resolve_tcp(a, 4), Err(RouteError::Offline));
    assert_eq!(router.transport_connected(a), Err(RouteError::Offline));
    assert_eq!(router.resolve_tcp(b, 4).unwrap(), 200);
}

#[test]
fn closed_tcp_stream_id_cannot_be_reused_in_the_same_tunnel() {
    let mut router = Router::default();
    let b = setup(&mut router, UserId::new(), NodeId::new());
    router.register_tcp(b, 4, 100).unwrap();
    router.remove_tcp(b, 4).unwrap();
    assert_eq!(
        router.register_tcp(b, 4, 200),
        Err(RouteError::DuplicateFlow)
    );
    assert_eq!(router.resolve_tcp(b, 4), Err(RouteError::Offline));
}

#[test]
fn udp_association_is_per_original_socket_and_not_reused_after_close() {
    let mut router = Router::default();
    let b = setup(&mut router, UserId::new(), NodeId::new());
    assert_eq!(router.udp_association(b, 100).unwrap(), 0);
    assert_eq!(router.udp_association(b, 100).unwrap(), 0);
    router.remove_udp(b, 100).unwrap();
    assert_eq!(router.udp_association(b, 200).unwrap(), 1);
    assert_eq!(router.resolve_udp(b, 0), Err(RouteError::Offline));
}

#[test]
fn another_user_cannot_bind_close_or_delete_a_sandbox() {
    let mut router = Router::default();
    let b = setup(&mut router, UserId::new(), NodeId::new());
    let attacker = UserId::new();
    assert_eq!(
        router.begin_tunnel(attacker, b.sandbox_id, b.node_id),
        Err(RouteError::NotFound)
    );
    assert_eq!(
        router.close(attacker, b.sandbox_id),
        Err(RouteError::NotFound)
    );
    assert_eq!(
        router.delete(attacker, b.sandbox_id),
        Err(RouteError::NotFound)
    );
}

#[test]
fn config_has_native_udp_tls_validation_local_auth_and_no_direct_outbound() {
    let mut router = Router::default();
    let b = setup(&mut router, UserId::new(), NodeId::new());
    let value = json!({ "node_id": b.node_id, "endpoint_ip": "203.0.113.10", "endpoint_port": 443,
        "tls_server_name": "sz.example.test", "tuic_uuid": uuid::Uuid::new_v4(),
        "tuic_password": "secret-secret-secret", "socks_port": 19080,
        "socks_username": "broker", "socks_password": "local-secret-secret" });
    let settings: TunnelSettings = serde_json::from_value(value.clone()).unwrap();
    assert!(!format!("{settings:?}").contains("secret-secret-secret"));
    let config = sing_box_config(b, &settings).unwrap();
    assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(config["outbounds"][0]["udp_relay_mode"], "native");
    assert_eq!(config["outbounds"][0]["tls"]["insecure"], false);
    assert_eq!(config["outbounds"].as_array().unwrap().len(), 1);
    assert_eq!(config["route"]["final"], config["outbounds"][0]["tag"]);
    let mut invalid = value;
    invalid["endpoint_ip"] = json!("node.example.test");
    assert!(serde_json::from_value::<TunnelSettings>(invalid).is_err());
}

#[test]
fn tunnel_settings_cannot_be_used_for_a_different_bound_node() {
    let mut router = Router::default();
    let b = setup(&mut router, UserId::new(), NodeId::new());
    let settings: TunnelSettings = serde_json::from_value(json!({
        "node_id": NodeId::new(), "endpoint_ip": "203.0.113.20", "endpoint_port": 443,
        "tls_server_name": "gz.example.test", "tuic_uuid": uuid::Uuid::new_v4(),
        "tuic_password": "secret-secret-secret", "socks_port": 19080,
        "socks_username": "broker", "socks_password": "local-secret-secret"
    }))
    .unwrap();
    assert_eq!(
        sing_box_config(b, &settings),
        Err(orangespace_core::tunnel::ConfigError::NodeMismatch)
    );
}
