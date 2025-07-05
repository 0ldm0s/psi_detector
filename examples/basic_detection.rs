//! 基础协议探测示例
//!
//! 演示如何使用 PSI-Detector 进行基本的协议探测

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy
};
use psi_detector::core::detector::DetectionResult;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 PSI-Detector 基础协议探测示例");
    
    // 创建探测器
    let detector = DetectorBuilder::new()
        .enable_http()
        .enable_http2()
        .enable_http3()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(100))
        .with_min_confidence(0.8)
        .with_min_probe_size(8)  // 设置最小8字节，适合小测试数据
        .build()?;
    
    // 测试数据集
    let test_cases = vec![
        (
            "HTTP/1.1 请求",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n".as_slice(),
        ),
        (
            "HTTP/2 连接前言",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
        ),
        (
            "HTTP/3 over QUIC",
            &[
                // QUIC长包头 + HTTP/3 ALPN标识
                0x80, 0x00, 0x00, 0x01, // QUIC版本1
                0x08, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // 连接ID
                0x68, 0x33, 0x2d, 0x32, 0x39, // "h3-29" ALPN
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ],
        ),
        (
            "TLS ClientHello",
            &[
                0x16, 0x03, 0x01, 0x00, 0x2f, // TLS Record Header
                0x01, 0x00, 0x00, 0x2b, // Handshake Header
                0x03, 0x03, // Version
                // Random (32 bytes)
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                0x00, // Session ID Length
                0x00, 0x02, // Cipher Suites Length
                0x00, 0x35, // Cipher Suite
                0x01, 0x00, // Compression Methods
            ],
        ),
        (
            "SSH 协议标识",
            b"SSH-2.0-OpenSSH_8.0\r\n",
        ),
        (
            "未知协议",
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        ),
    ];
    
    println!("\n开始协议探测...");
    
    for (name, data) in test_cases {
        println!("\n📦 测试: {}", name);
        println!("   数据长度: {} 字节", data.len());
        
        match detector.detect(data) {
            Ok(result) => {
                println!("   ✅ 探测成功!");
                println!("   🎯 协议类型: {:?}", result.protocol_type());
                println!("   📊 置信度: {:.2}%", result.confidence() * 100.0);
                println!("   ⏱️  处理时间: {:?}", result.detection_time);
                println!("   🔧 探测方法: {:?}", result.detection_method);
                
                // 检查是否为高置信度结果
                if result.is_high_confidence() {
                    println!("   🌟 高置信度探测结果");
                }
            }
            Err(e) => {
                println!("   ❌ 探测失败: {}", e);
            }
        }
    }
    
    println!("\n🎉 基础协议探测示例完成!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_detection() {
        let detector = DetectorBuilder::new()
            .enable_http()
            .enable_tls()
            .build()
            .expect("Failed to build detector");
        
        let http_data = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n";
        let result = detector.detect(http_data).expect("Detection failed");
        
        assert_eq!(result.protocol_type(), ProtocolType::HTTP1_1);
        assert!(result.confidence() > 0.8);
    }
}