use std::fs;

#[test]
fn test_cert() {
    let crt = fs::read("certs/example.org.pem").unwrap();
    let key = fs::read("certs/example.org-key.pem").unwrap();
    tokio_native_tls::native_tls::Identity::from_pkcs8(&crt, &key).unwrap();
}
