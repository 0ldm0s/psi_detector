//! 协议核心模块测试

use psi_detector::core::protocol::*;
use serde_json;

#[test]
fn test_protocol_type_display() {
    assert_eq!(ProtocolType::HTTP2.to_string(), "HTTP/2");
    assert_eq!(ProtocolType::GRPC.to_string(), "gRPC");
}

#[test]
fn test_protocol_properties() {
    assert!(ProtocolType::HTTP2.is_http_based());
    assert!(ProtocolType::HTTP2.supports_upgrade());
    assert!(ProtocolType::HTTP2.is_encrypted());
    assert_eq!(ProtocolType::HTTP2.default_port(), Some(443));
}

#[test]
fn test_protocol_info() {
    let mut info = ProtocolInfo::new(ProtocolType::HTTP2, 0.95);
    info.add_feature("server-push");
    info.add_metadata("server", "nginx");
    
    assert!(info.is_confident(0.9));
    assert!(info.has_feature("server-push"));
    assert_eq!(info.metadata.get("server"), Some(&"nginx".to_string()));
}

#[test]
fn test_upgrade_path() {
    let path = UpgradePath::new(
        ProtocolType::HTTP1_1,
        ProtocolType::HTTP2,
        UpgradeMethod::HttpUpgrade,
    );
    
    assert_eq!(path.from, ProtocolType::HTTP1_1);
    assert_eq!(path.to, ProtocolType::HTTP2);
}

#[test]
fn test_protocol_family() {
    assert_eq!(ProtocolType::HTTP2.protocol_family(), ProtocolFamily::HTTP);
    assert_eq!(ProtocolType::GRPC.protocol_family(), ProtocolFamily::RPC);
}

#[test]
fn test_serialization() {
    let protocol = ProtocolType::HTTP2;
    let json = serde_json::to_string(&protocol).unwrap();
    let deserialized: ProtocolType = serde_json::from_str(&json).unwrap();
    assert_eq!(protocol, deserialized);
}