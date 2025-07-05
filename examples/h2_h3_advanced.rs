//! HTTP/2 和 HTTP/3 高级协议探测示例
//!
//! 演示如何使用 PSI-Detector 进行 HTTP/2 和 HTTP/3 的高级协议探测和升级

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 PSI-Detector HTTP/2 & HTTP/3 高级协议探测示例");
    
    // 创建支持现代HTTP协议的探测器
    let detector = DetectorBuilder::new()
        .enable_http()      // HTTP/1.x
        .enable_http2()     // HTTP/2
        .enable_http3()     // HTTP/3
        .enable_tls()       // TLS (HTTPS)
        .enable_quic()      // QUIC (HTTP/3基础)
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(300))
        .with_min_confidence(0.7)
        .with_min_probe_size(16)  // HTTP/2和HTTP/3需要更多数据
        .build()?;
    
    // 高级测试场景
    let advanced_scenarios = vec![
        AdvancedScenario {
            name: "HTTP/1.1 到 HTTP/2 升级 (h2c)",
            description: "明文HTTP/2升级请求",
            data: create_h2c_upgrade_request(),
            expected_protocol: ProtocolType::HTTP1_1,
            upgrade_target: Some(ProtocolType::HTTP2),
        },
        AdvancedScenario {
            name: "HTTP/2 连接前言 + SETTINGS帧",
            description: "标准HTTP/2连接建立",
            data: create_http2_connection_preface(),
            expected_protocol: ProtocolType::HTTP2,
            upgrade_target: None,
        },
        AdvancedScenario {
            name: "HTTP/2 HEADERS帧",
            description: "HTTP/2请求头帧",
            data: create_http2_headers_frame(),
            expected_protocol: ProtocolType::HTTP2,
            upgrade_target: None,
        },
        AdvancedScenario {
            name: "HTTP/3 over QUIC (h3)",
            description: "HTTP/3 over QUIC连接",
            data: create_http3_quic_packet(),
            expected_protocol: ProtocolType::HTTP3,
            upgrade_target: None,
        },
        AdvancedScenario {
            name: "HTTP/3 SETTINGS帧",
            description: "HTTP/3设置帧",
            data: create_http3_settings_frame(),
            expected_protocol: ProtocolType::HTTP3,
            upgrade_target: None,
        },
        AdvancedScenario {
            name: "TLS with ALPN (h2)",
            description: "TLS握手包含HTTP/2 ALPN",
            data: create_tls_with_h2_alpn(),
            expected_protocol: ProtocolType::TLS,
            upgrade_target: Some(ProtocolType::HTTP2),
        },
    ];
    
    println!("\n🧪 开始高级协议探测测试...");
    
    for scenario in &advanced_scenarios {
        println!("\n📋 测试场景: {}", scenario.name);
        println!("   描述: {}", scenario.description);
        println!("   数据长度: {} 字节", scenario.data.len());
        
        // 探测协议
        match detector.detect(&scenario.data) {
            Ok(result) => {
                println!("   ✅ 探测成功!");
                println!("   🎯 协议类型: {:?}", result.protocol_type());
                println!("   📊 置信度: {:.2}%", result.confidence() * 100.0);
                println!("   ⏱️  处理时间: {:?}", result.detection_time);
                println!("   🔧 探测方法: {:?}", result.detection_method);
                
                // 检查协议识别是否正确
                if result.protocol_type() == scenario.expected_protocol {
                    println!("   ✅ 协议识别正确!");
                } else {
                    println!("   ⚠️  协议识别不匹配，期望: {:?}", scenario.expected_protocol);
                }
                
                // 检查升级目标
                if let Some(target) = scenario.upgrade_target {
                    println!("   🔄 支持升级到: {:?}", target);
                    
                    // 分析升级可能性
                    analyze_upgrade_possibility(&scenario.data, target);
                }
                
                // 高置信度检查
                if result.is_high_confidence() {
                    println!("   🌟 高置信度探测结果");
                }
            }
            Err(e) => {
                println!("   ❌ 探测失败: {}", e);
            }
        }
    }
    
    // 性能测试
    println!("\n⚡ 性能测试...");
    performance_test(&detector)?;
    
    println!("\n🎉 HTTP/2 & HTTP/3 高级协议探测示例完成!");
    Ok(())
}

#[derive(Debug)]
struct AdvancedScenario {
    name: &'static str,
    description: &'static str,
    data: Vec<u8>,
    expected_protocol: ProtocolType,
    upgrade_target: Option<ProtocolType>,
}

/// 创建HTTP/1.1到HTTP/2升级请求
fn create_h2c_upgrade_request() -> Vec<u8> {
    b"GET / HTTP/1.1\r\n\
      Host: example.com\r\n\
      Connection: Upgrade, HTTP2-Settings\r\n\
      Upgrade: h2c\r\n\
      HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
      User-Agent: PSI-Detector/1.0\r\n\r\n".to_vec()
}

/// 创建HTTP/2连接前言
fn create_http2_connection_preface() -> Vec<u8> {
    let mut data = Vec::new();
    // HTTP/2连接前言
    data.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // SETTINGS帧
    data.extend_from_slice(&[
        0x00, 0x00, 0x12, // 长度: 18字节
        0x04,             // 类型: SETTINGS
        0x00,             // 标志: 无
        0x00, 0x00, 0x00, 0x00, // 流ID: 0
        // SETTINGS参数
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE: 4096
        0x00, 0x02, 0x00, 0x00, 0x00, 0x01, // ENABLE_PUSH: 1
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS: 100
    ]);
    data
}

/// 创建HTTP/2 HEADERS帧
fn create_http2_headers_frame() -> Vec<u8> {
    let mut data = Vec::new();
    // HTTP/2连接前言（必需）
    data.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // HEADERS帧
    data.extend_from_slice(&[
        0x00, 0x00, 0x20, // 长度: 32字节
        0x01,             // 类型: HEADERS
        0x05,             // 标志: END_HEADERS | END_STREAM
        0x00, 0x00, 0x00, 0x01, // 流ID: 1
        // 简化的HPACK编码头部
        0x82, 0x86, 0x84, 0x41, 0x8a, 0xa0, 0xe4, 0x1d,
        0x13, 0x9d, 0x09, 0xb8, 0xf0, 0x1e, 0x07, 0x35,
        0x83, 0x35, 0x42, 0x50, 0x9f, 0x11, 0x12, 0x1d,
        0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x4d,
    ]);
    data
}

/// 创建HTTP/3 over QUIC数据包
fn create_http3_quic_packet() -> Vec<u8> {
    vec![
        // QUIC长包头
        0x80,                   // 标志: 长包头
        0x00, 0x00, 0x00, 0x01, // 版本: QUIC v1
        0x08,                   // 目标连接ID长度
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // 目标连接ID
        0x00,                   // 源连接ID长度
        0x40, 0x74,             // 令牌长度: 116
        // ALPN扩展 (简化)
        0x00, 0x10,             // 扩展类型: ALPN
        0x00, 0x05,             // 扩展长度
        0x00, 0x03,             // ALPN列表长度
        0x02, 0x68, 0x33,       // "h3"
        // 更多QUIC数据
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ]
}

/// 创建HTTP/3 SETTINGS帧
fn create_http3_settings_frame() -> Vec<u8> {
    let mut data = create_http3_quic_packet();
    // 添加HTTP/3 SETTINGS帧
    data.extend_from_slice(&[
        0x04,       // 帧类型: SETTINGS
        0x08,       // 长度: 8字节
        // SETTINGS参数
        0x01, 0x40, 0x00, 0x64, // QPACK_MAX_TABLE_CAPACITY: 100
        0x06, 0x40, 0x00, 0x64, // QPACK_BLOCKED_STREAMS: 100
    ]);
    data
}

/// 创建包含HTTP/2 ALPN的TLS握手
fn create_tls_with_h2_alpn() -> Vec<u8> {
    vec![
        // TLS记录头
        0x16, 0x03, 0x01, 0x00, 0x80, // TLS 1.0, 长度128
        // ClientHello
        0x01, 0x00, 0x00, 0x7c, // 握手类型和长度
        0x03, 0x03,             // TLS版本
        // 随机数 (32字节)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x00,       // 会话ID长度
        0x00, 0x02, // 密码套件长度
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x01, 0x00, // 压缩方法
        // 扩展
        0x00, 0x30, // 扩展总长度
        // ALPN扩展
        0x00, 0x10, // 扩展类型: ALPN
        0x00, 0x07, // 扩展长度
        0x00, 0x05, // ALPN列表长度
        0x02, 0x68, 0x32, // "h2"
        0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // "http/1.1"
        // 其他扩展数据
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03,
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
    ]
}

/// 分析协议升级可能性
fn analyze_upgrade_possibility(data: &[u8], target: ProtocolType) {
    let data_str = String::from_utf8_lossy(data);
    
    match target {
        ProtocolType::HTTP2 => {
            if data_str.contains("h2c") {
                println!("   🔄 检测到HTTP/2明文升级标识 (h2c)");
            }
            if data_str.contains("h2") {
                println!("   🔄 检测到HTTP/2 ALPN标识 (h2)");
            }
            if data_str.contains("HTTP2-Settings") {
                println!("   🔄 检测到HTTP/2设置头");
            }
        }
        ProtocolType::HTTP3 => {
            if data_str.contains("h3") {
                println!("   🔄 检测到HTTP/3 ALPN标识 (h3)");
            }
        }
        _ => {}
    }
}

/// 性能测试
fn performance_test(detector: &dyn ProtocolDetector) -> Result<(), Box<dyn std::error::Error>> {
    let test_data = create_http2_connection_preface();
    let iterations = 1000;
    
    let start = std::time::Instant::now();
    
    for _ in 0..iterations {
        let _ = detector.detect(&test_data)?;
    }
    
    let duration = start.elapsed();
    let avg_time = duration / iterations;
    
    println!("   📊 性能统计:");
    println!("      - 总时间: {:?}", duration);
    println!("      - 平均时间: {:?}", avg_time);
    println!("      - 吞吐量: {:.0} 检测/秒", 1_000_000_000.0 / avg_time.as_nanos() as f64);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_http2_detection() {
        let detector = DetectorBuilder::new()
            .enable_http2()
            .build()
            .expect("Failed to build detector");
        
        let http2_data = create_http2_connection_preface();
        let result = detector.detect(&http2_data).expect("Detection failed");
        
        assert_eq!(result.protocol_type(), ProtocolType::HTTP2);
        assert!(result.confidence() > 0.8);
    }
    
    #[test]
    fn test_http3_detection() {
        let detector = DetectorBuilder::new()
            .enable_http3()
            .build()
            .expect("Failed to build detector");
        
        let http3_data = create_http3_quic_packet();
        let result = detector.detect(&http3_data).expect("Detection failed");
        
        // HTTP/3检测可能返回QUIC或HTTP3
        assert!(matches!(result.protocol_type(), ProtocolType::HTTP3 | ProtocolType::QUIC));
        assert!(result.confidence() > 0.6);
    }
    
    #[test]
    fn test_h2c_upgrade_detection() {
        let detector = DetectorBuilder::new()
            .enable_http()
            .build()
            .expect("Failed to build detector");
        
        let h2c_data = create_h2c_upgrade_request();
        let result = detector.detect(&h2c_data).expect("Detection failed");
        
        assert_eq!(result.protocol_type(), ProtocolType::HTTP1_1);
        
        // 检查升级头是否存在
        let data_str = String::from_utf8_lossy(&h2c_data);
        assert!(data_str.contains("Upgrade: h2c"));
    }
}