//! Link/export regression only; HTTPS network behavior belongs to its own tests.
#[test]
fn single_runtime_archive_exports_the_borrowed_https_abi() {
    let mut body = vec![0xa5; 1048576];
    let mut status = 1234;
    let mut length = 4321;
    let result = unsafe {
        orangespace_runtime::os_https_request_v1(
            std::ptr::null(),
            body.as_mut_ptr(),
            body.len(),
            &mut status,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(status, 1234);
    assert_eq!(length, 4321);
    assert!(body.iter().all(|v| *v == 0xa5));
}
