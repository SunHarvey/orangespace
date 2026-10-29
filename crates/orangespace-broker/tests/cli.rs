use serde_json::Value;
use std::process::{Command, Output};
use uuid::Uuid;

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orangespace-broker"))
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
}
fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn manager_protocol_is_json_and_no_command_can_open_browser() {
    let dir = tempfile::tempdir().unwrap();
    let user = Uuid::new_v4().to_string();
    let node = Uuid::new_v4().to_string();
    let created = run(
        dir.path(),
        &["create", "--user", &user, "--name", "深圳工作区"],
    );
    assert!(created.status.success());
    let id = json(&created)["sandbox"]["id"].as_str().unwrap().to_owned();
    let bound = run(
        dir.path(),
        &["bind", "--user", &user, "--sandbox", &id, "--node", &node],
    );
    assert!(bound.status.success());
    let status = run(dir.path(), &["status", "--user", &user]);
    let status = json(&status);
    assert_eq!(status["schema_version"], 1);
    assert_eq!(status["browsing_allowed"], false);
    assert_eq!(status["sandboxes"][0]["node_id"], node);
    let opened = run(dir.path(), &["open", "--user", &user, "--sandbox", &id]);
    assert!(!opened.status.success());
    assert_eq!(json(&opened)["error"]["code"], "guard_unavailable");
    let listed = run(dir.path(), &["list", "--user", &Uuid::new_v4().to_string()]);
    assert!(json(&listed)["sandboxes"].as_array().unwrap().is_empty());
}

#[cfg(not(windows))]
#[test]
fn mismatched_node_config_is_rejected_before_creating_an_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let user = Uuid::new_v4().to_string();
    let node = Uuid::new_v4().to_string();
    let created = run(dir.path(), &["create", "--user", &user, "--name", "深圳"]);
    let id = json(&created)["sandbox"]["id"].as_str().unwrap().to_owned();
    assert!(
        run(
            dir.path(),
            &["bind", "--user", &user, "--sandbox", &id, "--node", &node]
        )
        .status
        .success()
    );
    let settings = dir.path().join("settings.json");
    let artifact = dir.path().join("tuic.json");
    std::fs::write(
        &settings,
        serde_json::to_vec(&serde_json::json!({
            "node_id": Uuid::new_v4(), "endpoint_ip": "203.0.113.20", "endpoint_port": 443,
            "tls_server_name": "gz.example.test", "tuic_uuid": Uuid::new_v4(),
            "tuic_password": "never-log-this-secret", "socks_port": 19080,
            "socks_username": "broker", "socks_password": "never-log-local-secret"
        }))
        .unwrap(),
    )
    .unwrap();
    let output = run(
        dir.path(),
        &[
            "tunnel-config",
            "--user",
            &user,
            "--sandbox",
            &id,
            "--settings-file",
            settings.to_str().unwrap(),
            "--output",
            artifact.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(!artifact.exists());
    assert!(
        json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("node_id does not match")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("never-log"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("never-log"));
}
