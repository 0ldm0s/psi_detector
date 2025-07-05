//! 核心探测器模块测试

use psi_detector::core::detector::*;
use psi_detector::core::protocol::{ProtocolType, ProtocolInfo};
use std::time::Duration;

#[test]
fn test_detection_result() {
    let protocol_info = ProtocolInfo::new(ProtocolType::HTTP2, 0.95);
    let result = DetectionResult::new(
        protocol_info,
        Duration::from_millis(10),
        DetectionMethod::Passive,
        "test_detector".to_string(),
    );
    
    assert_eq!(result.protocol_type(), ProtocolType::HTTP2);
    assert_eq!(result.confidence(), 0.95);
    assert!(result.is_high_confidence());
    assert!(result.is_acceptable(0.8));
}

#[test]
fn test_detection_config() {
    let config = DetectionConfig::new()
        .with_min_confidence(0.8)
        .with_timeout(Duration::from_millis(500))
        .enable_heuristic()
        .disable_active_probing();
    
    assert_eq!(config.min_confidence, 0.8);
    assert_eq!(config.timeout, Duration::from_millis(500));
    assert!(config.enable_heuristic);
    assert!(!config.enable_active_probing);
}

#[test]
fn test_detection_stats() {
    let mut stats = DetectionStats::new();
    
    stats.record_success(ProtocolType::HTTP2, Duration::from_millis(10));
    stats.record_success(ProtocolType::HTTP2, Duration::from_millis(20));
    stats.record_failure(Duration::from_millis(5));
    
    assert_eq!(stats.total_detections, 3);
    assert_eq!(stats.successful_detections, 2);
    assert_eq!(stats.failed_detections, 1);
    assert!((stats.success_rate() - 0.6666666666666666).abs() < f64::EPSILON);
    assert_eq!(stats.most_common_protocol(), Some(ProtocolType::HTTP2));
}

#[test]
fn test_detection_config_builder() {
    let config = DetectionConfig::new()
        .with_min_confidence(0.9)
        .with_timeout(Duration::from_secs(1))
        .with_max_probe_size(4096)
        .enable_simd()
        .enable_heuristic()
        .enable_active_probing();
    
    assert_eq!(config.min_confidence, 0.9);
    assert_eq!(config.timeout, Duration::from_secs(1));
    assert_eq!(config.max_probe_size, 4096);
    assert!(config.enable_simd);
    assert!(config.enable_heuristic);
    assert!(config.enable_active_probing);
}

#[test]
fn test_detection_stats_empty() {
    let stats = DetectionStats::new();
    
    assert_eq!(stats.total_detections, 0);
    assert_eq!(stats.successful_detections, 0);
    assert_eq!(stats.failed_detections, 0);
    assert_eq!(stats.success_rate(), 0.0);
    assert_eq!(stats.most_common_protocol(), None);
}

#[test]
fn test_detection_stats_single_success() {
    let mut stats = DetectionStats::new();
    stats.record_success(ProtocolType::TLS, Duration::from_millis(15));
    
    assert_eq!(stats.total_detections, 1);
    assert_eq!(stats.successful_detections, 1);
    assert_eq!(stats.failed_detections, 0);
    assert_eq!(stats.success_rate(), 1.0);
    assert_eq!(stats.most_common_protocol(), Some(ProtocolType::TLS));
}

#[test]
fn test_detection_stats_single_failure() {
    let mut stats = DetectionStats::new();
    stats.record_failure(Duration::from_millis(5));
    
    assert_eq!(stats.total_detections, 1);
    assert_eq!(stats.successful_detections, 0);
    assert_eq!(stats.failed_detections, 1);
    assert_eq!(stats.success_rate(), 0.0);
    assert_eq!(stats.most_common_protocol(), None);
}