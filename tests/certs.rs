use std::fs;

#[test]
fn test_pkcs12() {
    let der = fs::read("certs/example.org.p12").unwrap();
    tokio_native_tls::native_tls::Identity::from_pkcs12(&der, "changeit").unwrap();
}
