//! 自定义配置示例
//!
//! 演示如何使用 PSI-Detector 进行高级配置和自定义探测器设置

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚙️  PSI-Detector 自定义配置示例");
    
    // 1. 基础配置示例
    println!("\n🔧 1. 基础配置示例");
    demonstrate_basic_configuration()?;
    
    // 2. 高级策略配置
    println!("\n🎯 2. 高级策略配置");
    demonstrate_advanced_strategies()?;
    
    // 3. 性能调优配置
    println!("\n⚡ 3. 性能调优配置");
    demonstrate_performance_tuning()?;
    
    println!("\n🎉 自定义配置示例完成!");
    Ok(())
}

fn demonstrate_basic_configuration() -> Result<(), Box<dyn std::error::Error>> {
    println!("   📝 创建基础配置");
    
    // 最小配置
    let minimal_detector = DetectorBuilder::new()
        .enable_http()
        .build()?;
    
    println!("   ✅ 最小配置探测器创建成功");
    
    // 完整配置
    let full_detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(100))
        .with_buffer_size(8192)
        .with_min_confidence(0.8)
        .build()?;
    
    println!("   ✅ 完整配置探测器创建成功");
    
    // 测试配置
    let test_data = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    
    let minimal_result = minimal_detector.detect(test_data)?;
    let full_result = full_detector.detect(test_data)?;
    
    println!("   📊 配置对比:");
    println!("      最小配置 - 协议: {:?}, 置信度: {:.1}%", 
        minimal_result.protocol_type(), minimal_result.confidence() * 100.0);
    println!("      完整配置 - 协议: {:?}, 置信度: {:.1}%", 
        full_result.protocol_type(), full_result.confidence() * 100.0);
    
    Ok(())
}

fn demonstrate_advanced_strategies() -> Result<(), Box<dyn std::error::Error>> {
    println!("   🎯 测试不同探测策略");
    
    let test_data = b"SSH-2.0-OpenSSH_8.0\r\n";
    
    let strategies = vec![
        (ProbeStrategy::Passive, "被动探测"),
        (ProbeStrategy::Active, "主动探测"),
    ];
    
    for (strategy, name) in strategies {
        let detector = DetectorBuilder::new()
            .enable_ssh()
            .with_strategy(strategy)
            .with_timeout(Duration::from_millis(50))
            .build()?;
        
        let start_time = std::time::Instant::now();
        let result = detector.detect(test_data)?;
        let detection_time = start_time.elapsed();
        
        println!("   📈 {} 策略:", name);
        println!("      协议: {:?}", result.protocol_type());
        println!("      置信度: {:.1}%", result.confidence() * 100.0);
        println!("      检测时间: {:?}", detection_time);
        println!("      检测方法: {:?}", result.detection_method);
        println!();
    }
    
    Ok(())
}

fn demonstrate_performance_tuning() -> Result<(), Box<dyn std::error::Error>> {
    println!("   ⚡ 性能调优配置");
    
    // 高性能配置（适用于高吞吐量场景）
    let high_performance = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(10))
        .with_buffer_size(4096)
        .with_min_confidence(0.6)
        .build()?;
    
    // 高精度配置（适用于准确性要求高的场景）
    let high_accuracy = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Active)
        .with_timeout(Duration::from_millis(500))
        .with_buffer_size(16384)
        .with_min_confidence(0.9)
        .build()?;
    
    // 平衡配置（性能和准确性的平衡）
    let balanced = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(100))
        .with_buffer_size(8192)
        .with_min_confidence(0.75)
        .build()?;
    
    // 测试数据
    let tls_data = create_tls_client_hello();
    let test_scenarios = vec![
        ("HTTP", b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice()),
        ("TLS", tls_data.as_slice()),
        ("SSH", b"SSH-2.0-OpenSSH_8.0\r\n"),
    ];
    
    /// 创建完整的 TLS ClientHello 数据包
    /// 
    /// 这是一个标准的 TLS 1.2 ClientHello 握手包，包含：
    /// - TLS Record Header (5 bytes)
    /// - Handshake Header (4 bytes) 
    /// - Client Hello 内容 (版本、随机数、密码套件等)
    fn create_tls_client_hello() -> Vec<u8> {
        vec![
            // TLS Record Header (5 bytes)
            0x16,       // Content Type: Handshake (22)
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x40, // Length: 64 bytes
            
            // Handshake Header (4 bytes)
            0x01,       // Handshake Type: Client Hello (1)
            0x00, 0x00, 0x3C, // Length: 60 bytes
            
            // Client Hello Payload
            0x03, 0x03, // Protocol Version: TLS 1.2
            
            // Random (32 bytes) - 客户端随机数
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            
            // Session ID Length (1 byte)
            0x00,       // 无会话 ID
            
            // Cipher Suites Length (2 bytes)
            0x00, 0x02, // 2 字节长度
            
            // Cipher Suites (2 bytes)
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            
            // Compression Methods Length (1 byte)
            0x01,       // 1 个压缩方法
            
            // Compression Methods (1 byte)
            0x00,       // 无压缩
            
            // Extensions Length (2 bytes)
            0x00, 0x00, // 无扩展
        ]
    }
    
    let configurations = vec![
        (&high_performance, "高性能"),
        (&high_accuracy, "高精度"),
        (&balanced, "平衡"),
    ];
    
    println!("   📊 性能对比测试:");
    println!("   ┌─────────────┬──────────┬──────────────┬──────────────┬──────────────┐");
    println!("   │    配置     │   协议   │   检测时间   │   置信度     │   准确性     │");
    println!("   ├─────────────┼──────────┼──────────────┼──────────────┼──────────────┤");
    
    for (detector, config_name) in &configurations {
        for (protocol_name, test_data) in &test_scenarios {
            let start_time = std::time::Instant::now();
            let result = detector.detect(test_data);
            let detection_time = start_time.elapsed();
            
            match result {
                Ok(detection_result) => {
                    let accuracy = if detection_result.is_high_confidence() { "高" } else { "中" };
                    println!("   │ {:>9}   │ {:>6}   │ {:>10.2?} │ {:>9.1}%  │ {:>10}   │",
                        config_name,
                        protocol_name,
                        detection_time,
                        detection_result.confidence() * 100.0,
                        accuracy
                    );
                }
                Err(_) => {
                    println!("   │ {:>9}   │ {:>6}   │ {:>10.2?} │ {:>9}   │ {:>10}   │",
                        config_name,
                        protocol_name,
                        detection_time,
                        "失败",
                        "低"
                    );
                }
            }
        }
    }
    
    println!("   └─────────────┴──────────┴──────────────┴──────────────┴──────────────┘");
    
    Ok(())
}











#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_configuration() {
        let detector = DetectorBuilder::new()
            .enable_http()
            .with_timeout(Duration::from_millis(100))
            .build()
            .expect("Failed to build detector");
        
        let test_data = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n";
        let result = detector.detect(test_data)
            .expect("Detection failed");
        
        assert_eq!(result.protocol_type(), ProtocolType::HTTP1_1);
    }
    
    #[test]
    fn test_strategy_comparison() {
        let strategies = vec![
            ProbeStrategy::Passive,
            ProbeStrategy::Active,
        ];
        
        let test_data = b"SSH-2.0-OpenSSH_8.0\r\n";
        
        for strategy in strategies {
            let detector = DetectorBuilder::new()
                .enable_ssh()
                .with_strategy(strategy)
                .build()
                .expect("Failed to build detector");
            
            let result = detector.detect(test_data)
                .expect("Detection failed");
            
            assert_eq!(result.protocol_type(), ProtocolType::SSH);
        }
    }
}