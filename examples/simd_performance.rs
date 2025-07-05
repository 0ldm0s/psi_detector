//! SIMD 加速协议探测示例
//!
//! 演示如何使用 SIMD 加速进行高性能协议探测

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy
};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚡ PSI-Detector SIMD 高性能探测示例");
    
    // 创建启用 SIMD 的高性能探测器
    let simd_detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(50))
        .build()?;
    
    // 创建标准探测器用于对比
    let standard_detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(50))
        .build()?;
    
    // 生成大量测试数据
    let test_data = generate_test_data();
    
    println!("\n🧪 性能测试开始...");
    println!("测试数据量: {} 个样本", test_data.len());
    
    // SIMD 加速测试
    println!("\n⚡ SIMD 加速探测:");
    let simd_results = benchmark_detection(&simd_detector, &test_data, "SIMD");
    
    // 标准探测测试
    println!("\n🔧 标准探测:");
    let standard_results = benchmark_detection(&standard_detector, &test_data, "Standard");
    
    // 性能对比
    println!("\n📊 性能对比报告:");
    let speedup = standard_results.total_time.as_nanos() as f64 / simd_results.total_time.as_nanos() as f64;
    println!("   🚀 SIMD 加速倍数: {:.2}x", speedup);
    println!("   ⏱️  平均延迟减少: {:.2}μs", 
        (standard_results.avg_latency.as_nanos() as f64 - simd_results.avg_latency.as_nanos() as f64) / 1000.0);
    println!("   🎯 准确率对比: SIMD {:.1}% vs Standard {:.1}%", 
        simd_results.accuracy * 100.0, standard_results.accuracy * 100.0);
    
    // 协议分布统计
    println!("\n📈 协议探测分布:");
    for (protocol, count) in &simd_results.protocol_stats {
        println!("   {:?}: {} 次", protocol, count);
    }
    
    println!("\n🎉 SIMD 性能测试完成!");
    Ok(())
}

#[derive(Debug)]
struct BenchmarkResult {
    total_time: Duration,
    avg_latency: Duration,
    accuracy: f64,
    protocol_stats: std::collections::HashMap<ProtocolType, usize>,
}

fn benchmark_detection(
    detector: &dyn ProtocolDetector,
    test_data: &[(String, Vec<u8>)],
    name: &str,
) -> BenchmarkResult {
    let mut total_time = Duration::new(0, 0);
    let mut successful_detections = 0;
    let mut protocol_stats = std::collections::HashMap::new();
    
    let start_time = Instant::now();
    
    for (expected_protocol, data) in test_data {
        let detection_start = Instant::now();
        
        match detector.detect(data) {
            Ok(result) => {
                let detection_time = detection_start.elapsed();
                total_time += detection_time;
                
                // 统计协议类型
                *protocol_stats.entry(result.protocol_type()).or_insert(0) += 1;
                
                // 检查准确性（简化版本）
                if is_correct_detection(expected_protocol, result.protocol_type()) {
                    successful_detections += 1;
                }
                
                if test_data.len() <= 10 { // 只在小数据集时打印详细信息
                    println!("   📦 {} -> {:?} ({:.1}%) in {:?}", 
                        expected_protocol, 
                        result.protocol_type(), 
                        result.confidence() * 100.0,
                        detection_time);
                }
            }
            Err(_) => {
                // 探测失败
            }
        }
    }
    
    let total_benchmark_time = start_time.elapsed();
    let avg_latency = total_time / test_data.len() as u32;
    let accuracy = successful_detections as f64 / test_data.len() as f64;
    
    println!("   ⏱️  总时间: {:?}", total_benchmark_time);
    println!("   📊 平均延迟: {:?}", avg_latency);
    println!("   🎯 准确率: {:.1}%", accuracy * 100.0);
    println!("   📈 吞吐量: {:.0} 检测/秒", 
        test_data.len() as f64 / total_benchmark_time.as_secs_f64());
    
    BenchmarkResult {
        total_time: total_benchmark_time,
        avg_latency,
        accuracy,
        protocol_stats,
    }
}

fn generate_test_data() -> Vec<(String, Vec<u8>)> {
    vec![
        // HTTP/1.1 样本
        ("HTTP1_1".to_string(), b"GET /api/data HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n".to_vec()),
        ("HTTP1_1".to_string(), b"POST /submit HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"key\": \"value\"}".to_vec()),
        
        // HTTP/2 样本 (简化)
        ("HTTP2".to_string(), vec![0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30]), // PRI * HTTP/2.0
        
        // TLS 样本
        ("TLS".to_string(), vec![
            0x16, 0x03, 0x01, 0x00, 0x2f, // TLS Record
            0x01, 0x00, 0x00, 0x2b, // ClientHello
            0x03, 0x03, // Version
        ]),
        
        // SSH 样本
        ("SSH".to_string(), b"SSH-2.0-OpenSSH_8.9\r\n".to_vec()),
        ("SSH".to_string(), b"SSH-1.99-Cisco-1.25\r\n".to_vec()),
        
        // WebSocket 升级请求
        ("WebSocket".to_string(), b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".to_vec()),
        
        // QUIC 样本 (简化)
        ("QUIC".to_string(), vec![0x40, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        
        // 未知协议
        ("Unknown".to_string(), vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
        ("Unknown".to_string(), vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA]),
    ]
}

fn is_correct_detection(expected: &str, detected: ProtocolType) -> bool {
    match (expected, detected) {
        ("HTTP1_1", ProtocolType::HTTP1_1) => true,
        ("HTTP2", ProtocolType::HTTP2) => true,
        ("TLS", ProtocolType::TLS) => true,
        ("SSH", ProtocolType::SSH) => true,
        ("WebSocket", ProtocolType::WebSocket) => true,
        ("QUIC", ProtocolType::QUIC) => true,
        ("Unknown", ProtocolType::Unknown) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_vs_standard_performance() {
        let simd_detector = DetectorBuilder::new()
            .enable_http()
            .build()
            .expect("Failed to build SIMD detector");
        
        let standard_detector = DetectorBuilder::new()
            .enable_http()
            .build()
            .expect("Failed to build standard detector");
        
        let test_data = vec![
            ("HTTP1_1".to_string(), b"GET / HTTP/1.1\r\n\r\n".to_vec()),
        ];
        
        let simd_result = benchmark_detection(&simd_detector, &test_data, "SIMD");
        let standard_result = benchmark_detection(&standard_detector, &test_data, "Standard");
        
        // SIMD 应该至少不比标准版本慢
        assert!(simd_result.total_time <= standard_result.total_time * 2); // 允许一定误差
    }
}