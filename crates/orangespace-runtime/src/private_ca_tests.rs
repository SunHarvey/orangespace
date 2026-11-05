// Production constructors and ABI, no test_certificate override.
#[test]
fn private_ca_constructor_bounds_and_snapshot() {
    let path = std::env::current_exe().unwrap();
    let path = path.to_str().unwrap();
    for ca in [
        vec![],
        vec![b'x'; 65537],
        vec![0],
        vec![255],
        b"not PEM".to_vec(),
    ] {
        assert!(
            unsafe {
                os_runtime_new_with_ca_v1(path.as_ptr(), path.len(), 100, ca.as_ptr(), ca.len())
            }
            .is_null()
        );
    }
    let mut ca = b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n".to_vec();
    let h =
        unsafe { os_runtime_new_with_ca_v1(path.as_ptr(), path.len(), 100, ca.as_ptr(), ca.len()) };
    assert!(!h.is_null());
    ca.fill(b'x');
    os_runtime_free(h);
}

#[test]
#[ignore = "requires approved sing-box; production ABI real TUIC private CA matrix"]
fn production_abi_private_ca_real_tuic_matrix() {
    use std::sync::atomic::Ordering;
    let binary = std::env::var("ORANGESPACE_TEST_SING_BOX").unwrap();
    for case in ["good", "wrong_ca", "no_ca", "wrong_name"] {
        let b = binding();
        let probe = probe_server(b, false);
        let mut l = lease(b);
        l["probe_port"] = json!(probe.port);
        let node = real_node(std::path::Path::new(&binary), &mut l);
        let mut unused = lease(binding());
        let wrong_node = real_node(std::path::Path::new(&binary), &mut unused);
        let mut ca = std::fs::read(if case == "wrong_ca" {
            &wrong_node.cert
        } else {
            &node.cert
        })
        .unwrap();
        if case == "wrong_name" {
            l["tls_server_name"] = json!("wrong.example.test");
        }
        let h = unsafe {
            if case == "no_ca" {
                os_runtime_new(binary.as_ptr(), binary.len(), 1500)
            } else {
                os_runtime_new_with_ca_v1(
                    binary.as_ptr(),
                    binary.len(),
                    1500,
                    ca.as_ptr(),
                    ca.len(),
                )
            }
        };
        assert!(!h.is_null());
        struct Handle(*mut std::ffi::c_void);
        impl Drop for Handle {
            fn drop(&mut self) {
                os_runtime_free(self.0);
            }
        }
        let guard = Handle(h);
        ca.fill(b'x'); // constructor must own the snapshot
        let request = start_request(b, l);
        let mut out = vec![0; 65536];
        let n = unsafe {
            os_runtime_call(
                h,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert!(n > 0, "{case}: ABI failed {n}");
        let reply: Value = serde_json::from_slice(&out[..n as usize]).unwrap();
        let good = case == "good";
        assert_eq!(reply["running"], good, "{case}");
        assert_eq!(reply["forwarding_verified"], good, "{case}");
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            usize::from(good),
            "{case}"
        );
        let pid = reply["pid"].as_u64().unwrap();
        let port = reply["socks_port"].as_u64().unwrap() as u16;
        // Free synchronously reaps the exact successful root too.
        drop(guard);
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "{case}: root survived"
        );
        assert!(
            TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_err(),
            "{case}: listener survived"
        );
    }
}
