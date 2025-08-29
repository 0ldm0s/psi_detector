//! 魔法包特征检测性能测试
//! 
//! 验证前几个字节启发式判断的超高速性能

use psi_detector::{DetectorBuilder, ProtocolDetector, ProtocolType};
use psi_detector::core::magic::{MagicDetector, CustomSignatureBuilder};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧙‍♂️ PSI-Detector 魔法包特征检测性能测试");
    println!("{}", "=".repeat(65));
    
    // 创建标准检测器
    let standard_detector = DetectorBuilder::new()
        .enable_http()
        .build()?;
    
    // 创建独立的魔法包检测器
    let mut magic_detector = MagicDetector::new();
    
    // 添加自定义协议特征
    let custom_sig = CustomSignatureBuilder::new(ProtocolType::Custom, "Custom Protocol v1.0")
        .with_magic_string("MYPROT")
        .with_confidence(0.98)
        .build();
    magic_detector.add_signature(custom_sig);
    
    // 测试数据集
    let test_cases = vec![
        ("HTTP GET", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()),
        ("HTTP POST", b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n".to_vec()),
        ("HTTP/2 Preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()),
        ("TLS Handshake", vec![0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b]),
        ("QUIC Long Header", vec![0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        ("SSH Protocol", b"SSH-2.0-OpenSSH_7.4\r\n".to_vec()),
        ("FTP Welcome", b"220 Welcome to FTP server\r\n".to_vec()),
        ("Custom Protocol", b"MYPROT v1.0 init\r\n".to_vec()),
        ("Redis Command", b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n".to_vec()),
        ("Random Data", vec![0x42; 64]),
    ];
    
    println!("🔬 测试数据集：{} 个样本\n", test_cases.len());
    
    // 性能对比测试
    let iterations = 10000;
    
    // 1. 魔法包快速检测
    println!("🚀 魔法包快速检测性能测试:");
    let start = Instant::now();
    let mut magic_success = 0;
    
    for _ in 0..iterations {
        for (_, data) in &test_cases {
            if let Some(_) = magic_detector.quick_detect(data) {
                magic_success += 1;
            }
        }
    }
    
    let magic_time = start.elapsed();
    let magic_avg = magic_time.as_nanos() / (iterations * test_cases.len()) as u128;
    
    println!("   ⏱️  总时间: {:?}", magic_time);
    println!("   📊 平均每次: {} ns", magic_avg);
    println!("   🎯 检测成功: {}/{}", magic_success, iterations * test_cases.len());
    println!("   📈 吞吐量: {:.0} 检测/秒\\n", (iterations * test_cases.len()) as f64 / magic_time.as_secs_f64());
    
    // 2. 标准协议检测
    println!("🔧 标准协议检测性能测试:");
    let start = Instant::now();
    let mut standard_success = 0;
    
    for _ in 0..iterations {
        for (_, data) in &test_cases {
            if let Ok(_) = standard_detector.detect(data) {
                standard_success += 1;
            }
        }
    }
    
    let standard_time = start.elapsed();
    let standard_avg = standard_time.as_nanos() / (iterations * test_cases.len()) as u128;
    
    println!("   ⏱️  总时间: {:?}", standard_time);
    println!("   📊 平均每次: {} ns", standard_avg);
    println!("   🎯 检测成功: {}/{}", standard_success, iterations * test_cases.len());
    println!("   📈 吞吐量: {:.0} 检测/秒\\n", (iterations * test_cases.len()) as f64 / standard_time.as_secs_f64());
    
    // 3. 性能对比分析
    let speedup = standard_avg as f64 / magic_avg as f64;
    let time_saved = (standard_avg as i128 - magic_avg as i128) as f64;
    
    println!("📊 性能对比分析:");
    println!("   🚀 魔法包加速倍数: {:.2}x", speedup);
    println!("   ⏱️  平均延迟减少: {:.0} ns", time_saved);
    println!("   🎯 魔法包准确率: {:.1}%", (magic_success as f64 / (iterations * test_cases.len()) as f64) * 100.0);
    println!("   🎯 标准检测准确率: {:.1}%\\n", (standard_success as f64 / (iterations * test_cases.len()) as f64) * 100.0);
    
    // 4. 魔法包详细分析
    println!("🔍 魔法包检测详细分析:");
    for (name, data) in &test_cases {
        print!("   {} ... ", name);
        
        let start = Instant::now();
        if let Some(result) = magic_detector.quick_detect(data) {
            let time = start.elapsed().as_nanos();
            println!("✅ {} ({:.1}%) - {} ns", result.protocol_type, result.confidence * 100.0, time);
        } else {
            let time = start.elapsed().as_nanos();
            println!("❌ 未检测到 - {} ns", time);
        }
    }
    
    // 5. 深度魔法包检测对比
    println!("\\n🔍 深度魔法包检测对比:");
    let test_data = &test_cases[0].1; // 使用HTTP GET数据
    
    let start = Instant::now();
    let quick_result = magic_detector.quick_detect(test_data);
    let quick_time = start.elapsed();
    
    let start = Instant::now();
    let deep_results = magic_detector.deep_detect(test_data);
    let deep_time = start.elapsed();
    
    println!("   快速检测: {:?} ({:?})", quick_result.map(|r| r.protocol_type), quick_time);
    println!("   深度检测: {} 个结果 ({:?})", deep_results.len(), deep_time);
    for result in deep_results.iter().take(3) {
        println!("      - {} ({:.1}%)", result.protocol_type, result.confidence * 100.0);
    }
    
    // 6. 自定义协议验证
    println!("\\n🎨 自定义协议特征验证:");
    let custom_data = b"MYPROT v1.0 hello world";
    if let Some(result) = magic_detector.quick_detect(custom_data) {
        println!("   ✅ 检测到自定义协议: {} ({:.1}%)", result.protocol_type, result.confidence * 100.0);
        
        // 验证元数据
        if let Some(method) = result.metadata.get("detection_method") {
            println!("   📋 检测方法: {}", method);
        }
        if let Some(desc) = result.metadata.get("signature_desc") {
            println!("   📝 特征描述: {}", desc);
        }
    }
    
    println!("\\n🎉 魔法包性能测试完成!");
    println!("💡 魔法包检测为协议识别带来了 {:.1}x 的性能提升!", speedup);
    
    Ok(())
}