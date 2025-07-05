//! 错误处理模块测试

use psi_detector::error::DetectorError;

#[test]
fn test_error_creation() {
    let err = DetectorError::detection_failed("test reason");
    assert!(matches!(err, DetectorError::DetectionFailed { .. }));
    assert!(err.is_recoverable());
}

#[test]
fn test_error_codes() {
    let err = DetectorError::NeedMoreData(100);
    assert_eq!(err.error_code(), 1001);
    
    let err = DetectorError::detection_failed("test");
    assert_eq!(err.error_code(), 1005);
}

#[test]
fn test_error_display() {
    let err = DetectorError::NeedMoreData(100);
    let display = format!("{}", err);
    assert!(display.contains("100 bytes"));
}

#[test]
fn test_error_classification() {
    let recoverable = DetectorError::NeedMoreData(100);
    assert!(recoverable.is_recoverable());
    
    let config_err = DetectorError::config_error("test");
    assert!(config_err.is_config_error());
    assert!(!config_err.is_recoverable());
}

#[test]
fn test_error_constructors() {
    let detection_err = DetectorError::detection_failed("failed to detect");
    assert!(matches!(detection_err, DetectorError::DetectionFailed { .. }));
    
    let unsupported_err = DetectorError::unsupported_protocol("HTTP/3");
    assert!(matches!(unsupported_err, DetectorError::UnsupportedProtocol { .. }));
    
    let upgrade_err = DetectorError::upgrade_failed("HTTP/1.1", "HTTP/2", "negotiation failed");
    assert!(matches!(upgrade_err, DetectorError::UpgradeFailed { .. }));
    
    let config_err = DetectorError::config_error("invalid configuration");
    assert!(matches!(config_err, DetectorError::ConfigError { .. }));
    
    let network_err = DetectorError::network_error("connection refused");
    assert!(matches!(network_err, DetectorError::NetworkError { .. }));
    
    let timeout_err = DetectorError::timeout(5000);
    assert!(matches!(timeout_err, DetectorError::Timeout { .. }));
    
    let buffer_err = DetectorError::buffer_error("buffer overflow");
    assert!(matches!(buffer_err, DetectorError::BufferError { .. }));
    
    let internal_err = DetectorError::internal_error("unexpected error");
    assert!(matches!(internal_err, DetectorError::InternalError { .. }));
}

#[test]
fn test_error_recovery_classification() {
    // 可恢复错误
    assert!(DetectorError::NeedMoreData(100).is_recoverable());
    assert!(DetectorError::detection_failed("test").is_recoverable());
    assert!(DetectorError::timeout(1000).is_recoverable());
    assert!(DetectorError::network_error("test").is_recoverable());
    
    // 不可恢复错误
    assert!(!DetectorError::config_error("test").is_recoverable());
    assert!(!DetectorError::unsupported_protocol("test").is_recoverable());
    assert!(!DetectorError::internal_error("test").is_recoverable());
}

#[test]
fn test_config_error_classification() {
    assert!(DetectorError::config_error("test").is_config_error());
    assert!(DetectorError::unsupported_protocol("test").is_config_error());
    
    assert!(!DetectorError::NeedMoreData(100).is_config_error());
    assert!(!DetectorError::detection_failed("test").is_config_error());
}