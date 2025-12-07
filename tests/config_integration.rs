use h3llo::config::Config;

#[test]
fn load_valid_configuration() {
    let yaml = r#"
local:
  id: node-aaa01
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
    secret: node-aaa01-secret
    admin:
      name: admin-username
      pass: admin-password
  tun:
    addrs:
      - 192.168.180.1
peers:
- id: node-aaa02
  h3:
    secret: node-aaa02-secret
    endpoints:
      - https://peer.example.com:443/path
  tun:
    allowedIPs:
      - 192.168.180.2/32
"#;

    let cfg = Config::load_from_str(yaml).expect("config should load");
    assert_eq!(cfg.local.id, "node-aaa01");
    assert_eq!(cfg.peers.len(), 1);
    assert!(cfg.peers[0].h3.is_some());
    assert!(cfg.peers[0].bare.is_none());
}

#[test]
fn reject_invalid_configuration() {
    let yaml = r#"
local:
  id: short
  tun:
    addrs: []
peers: []
"#;

    let result = Config::load_from_str(yaml);
    assert!(result.is_err(), "invalid config should fail validation");
}
