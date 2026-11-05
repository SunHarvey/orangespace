// Included in tests.rs to reuse the real, archive-verified Go/TUIC fixtures.
#[test]
fn renewal_wall_clock_rollback_or_same_expiry_cannot_gain_extra_time() {
    let active = Active {
        expires_at: 100,
        deadline: 5000,
    };
    let value = json!({"clock":CLOCK,"request_started_ms":1000,"remaining_ttl_ms":30000,"deadline_ms":31000});
    let budget: Budget = serde_json::from_value(value).unwrap();
    assert_eq!(renew_deadline(&active, 100, &budget, 1000).unwrap(), 5000);
    assert_eq!(renew_deadline(&active, 105, &budget, 1000).unwrap(), 10000);
    assert!(renew_deadline(&active, 99, &budget, 1000).is_err());
    assert!(renew_deadline(&active, 105, &budget, 5000).is_err());
    assert!(renew_deadline(&active, MAX_EXACT, &budget, 1000).is_err());
}
#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real private lease renewal"]
fn real_renew_extends_only_live_exact_binding_past_initial_expiry() {
    use std::{path::PathBuf, time::Duration};
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("verified runtime required"),
    );
    let b = binding();
    let probes = probe_server(b, false);
    let mut value = lease(b);
    value["probe_port"] = json!(probes.port);
    let node = real_node(&binary, &mut value);
    let initial = now_secs().unwrap() + 4;
    value["expires_at"] = json!(initial);
    value["remaining_ttl_ms"] = json!(4000);
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let started = runtime.dispatch(&start_request(b, value)).unwrap();
    assert_eq!(started["forwarding_verified"], true);
    let request = |binding: Binding, expires_at: u64| {
        serde_json::to_vec(&json!({"schema":2,"op":"renew","binding":binding,"expires_at":expires_at,"budget":budget(30000)}))
            .unwrap()
    };
    let renewed = runtime
        .dispatch(&request(b, now_secs().unwrap() + 30))
        .expect("live lease renewal must be supported");
    assert_eq!(renewed["ok"], true);
    let deadline = runtime.active[&b].deadline;
    let expiry = runtime.active[&b].expires_at;
    assert!(
        runtime
            .dispatch(&request(Binding { generation: 2, ..b }, expiry))
            .is_err()
    );
    assert!(runtime.dispatch(&request(b, expiry - 1)).is_err());
    assert_eq!(runtime.active[&b].deadline, deadline);
    while now_secs().unwrap() <= initial {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap()["exited"],
        json!([])
    );
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
    runtime
        .dispatch(&serde_json::to_vec(&json!({"schema":2,"op":"close","binding":b})).unwrap())
        .unwrap();
    assert!(
        runtime
            .dispatch(&request(b, now_secs().unwrap() + 30))
            .is_err()
    );
}

#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real expired renewal rejection"]
fn real_renew_never_revives_expired_binding_even_before_poll() {
    use std::{path::PathBuf, time::Duration};
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("verified runtime required"),
    );
    let b = binding();
    let probes = probe_server(b, false);
    let mut value = lease(b);
    value["probe_port"] = json!(probes.port);
    let node = real_node(&binary, &mut value);
    value["remaining_ttl_ms"] = json!(1500);
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    assert_eq!(
        runtime.dispatch(&start_request(b, value)).unwrap()["running"],
        true
    );
    let original_deadline = runtime.active[&b].deadline;
    std::thread::sleep(Duration::from_millis(
        original_deadline.saturating_sub(clock_ms().unwrap()) + 1,
    ));
    let renew =
        serde_json::to_vec(&json!({"schema":2,"op":"renew","binding":b,"expires_at":now_secs().unwrap()+30,"budget":budget(30000)}))
            .unwrap();
    assert!(runtime.dispatch(&renew).is_err());
    assert_eq!(
        runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap()["exited"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(runtime.dispatch(&renew).is_err());
}
