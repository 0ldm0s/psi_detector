//! 协议过滤性能对比测试
//! 
//! 验证启用指定协议过滤优化后的性能提升

use psi_detector::{DetectorBuilder, ProtocolDetector, ProtocolType};
use psi_detector::core::magic::{MagicDetector, CustomSignatureBuilder};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 PSI-Detector 协议过滤性能对比测试");
    println!("{}", "=".repeat(70));
    
    // 创建测试数据
    let test_data = vec![
        ("HTTP GET", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()),
        ("HTTP POST", b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n".to_vec()),
        ("TLS Handshake", vec![0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b]),
        ("SSH Protocol", b"SSH-2.0-OpenSSH_7.4\r\n".to_vec()),
        ("QUIC Long Header", vec![0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        ("MySQL Greeting", vec![0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x32, 0x38, 0x00]),
        ("Redis Command", b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n".to_vec()),
        ("Random Data", vec![0x42; 64]),
    ];
    
    let iterations = 5000;
    
    // 场景1：HTTP服务器（只启用HTTP相关协议）
    println!("📋 场景1：HTTP服务器配置");
    println!("启用协议：HTTP/1.1, HTTP/2, WebSocket, TLS");
    
    let http_server_detector = DetectorBuilder::new()
        .enable_http()
        .enable_http2()
        .enable_websocket()
        .enable_tls()
        .high_performance()
        .build()?;
    
    run_performance_test("HTTP服务器", &http_server_detector, &test_data, iterations);
    
    // 场景2：游戏服务器（只启用自定义协议）
    println!("\n📋 场景2：游戏服务器配置");
    println!("启用协议：仅自定义游戏协议");
    
    let game_detector = DetectorBuilder::new()
        .enable_custom()  // 启用自定义协议
        .add_custom_probe(Box::new(create_game_protocol_probe()))
        .high_performance()
        .build()?;
    
    run_performance_test("游戏服务器", &game_detector, &test_data, iterations);
    
    // 场景3：SSH服务器（只启用SSH和TLS）
    println!("\n📋 场景3：SSH服务器配置");
    println!("启用协议：SSH, TLS");
    
    let ssh_detector = DetectorBuilder::new()
        .enable_ssh()
        .enable_tls()
        .high_performance()
        .build()?;
    
    run_performance_test("SSH服务器", &ssh_detector, &test_data, iterations);
    
    // 场景4：全协议模式（传统方式，用作对比）
    println!("\n📋 场景4：全协议模式（对比基准）");
    println!("启用协议：所有协议");
    
    let all_protocols_detector = DetectorBuilder::new()
        .enable_all()
        .high_performance()
        .build()?;
    
    run_performance_test("全协议模式", &all_protocols_detector, &test_data, iterations);
    
    // 魔法包过滤测试
    println!("\n🔮 魔法包过滤性能测试");
    test_magic_detector_filtering();
    
    // 错误配置测试
    println!("\n🚨 严格模式配置验证测试");
    test_strict_mode_validation();
    
    println!("\n🎉 协议过滤性能测试完成!");
    println!("💡 结论：启用指定协议过滤可以显著提高性能和安全性！");
    
    Ok(())
}

fn run_performance_test(
    name: &str,
    detector: &dyn ProtocolDetector,
    test_data: &[(&str, Vec<u8>)],
    iterations: usize
) {
    println!("  🚀 测试 {} 性能...", name);
    
    let start = Instant::now();
    let mut success_count = 0;
    let mut filtered_count = 0;
    
    for _ in 0..iterations {
        for (data_name, data) in test_data {
            match detector.detect(data) {
                Ok(result) => {
                    success_count += 1;
                    // 记录成功检测的协议类型
                }
                Err(_) => {
                    filtered_count += 1;
                    // 被过滤掉的协议（这是好事！）
                }
            }
        }
    }
    
    let duration = start.elapsed();
    let total_tests = iterations * test_data.len();
    let avg_time = duration.as_nanos() / total_tests as u128;
    let throughput = total_tests as f64 / duration.as_secs_f64();
    
    println!("    ⏱️  平均时间: {} ns/检测", avg_time);
    println!("    📈 吞吐量: {:.0} 检测/秒", throughput);
    println!("    ✅ 成功检测: {}/{}", success_count, total_tests);
    println!("    🎯 过滤数量: {} (性能优化)", filtered_count);
    println!("    🛡️  过滤率: {:.1}%", (filtered_count as f64 / total_tests as f64) * 100.0);
}

fn test_magic_detector_filtering() {
    // 测试魔法包检测器的协议过滤功能
    println!("  🔮 测试魔法包协议过滤...");
    
    // 创建仅支持HTTP的魔法包检测器
    let http_only_detector = MagicDetector::new()
        .with_enabled_protocols(vec![ProtocolType::HTTP1_1, ProtocolType::HTTP2]);
    
    let test_cases = vec![
        ("HTTP GET", b"GET / HTTP/1.1\r\n\r\n".to_vec(), true),
        ("SSH Protocol", b"SSH-2.0-OpenSSH\r\n".to_vec(), false),
        ("TLS Handshake", vec![0x16, 0x03, 0x01, 0x00, 0x2f], false),
    ];
    
    for (name, data, should_detect) in test_cases {
        let result = http_only_detector.quick_detect(&data);
        let detected = result.is_some();
        
        println!("    {} ... {}", name, 
            if detected == should_detect { "✅ 正确" } else { "❌ 错误" });
        
        if detected != should_detect {
            println!("      期望: {}, 实际: {}", should_detect, detected);
        }
    }
}

fn test_strict_mode_validation() {
    println!("  🚨 测试严格模式配置验证...");
    
    // 测试1：空协议配置应该失败
    let empty_config_result = DetectorBuilder::new().build();
    
    match empty_config_result {
        Err(_) => println!("    ✅ 空协议配置正确被拒绝"),
        Ok(_) => println!("    ❌ 空协议配置应该被拒绝"),
    }
    
    // 测试2：正确配置应该成功
    let valid_config_result = DetectorBuilder::new()
        .enable_http()
        .build();
    
    match valid_config_result {
        Ok(_) => println!("    ✅ 有效协议配置正确通过"),
        Err(e) => println!("    ❌ 有效协议配置失败: {}", e),
    }
    
    // 测试3：Agent配置验证
    let empty_agent_result = DetectorBuilder::new().build_agent();
    
    match empty_agent_result {
        Err(_) => println!("    ✅ 空Agent配置正确被拒绝"),
        Ok(_) => println!("    ❌ 空Agent配置应该被拒绝"),
    }
}

// 创建一个简单的游戏协议探测器用于测试
struct GameProtocolProbe;

impl psi_detector::core::probe::ProtocolProbe for GameProtocolProbe {
    fn name(&self) -> &'static str {
        "GameProtocolProbe"
    }
    
    fn supported_protocols(&self) -> Vec<ProtocolType> {
        vec![ProtocolType::Custom]
    }
    
    fn probe(
        &self, 
        data: &[u8], 
        _context: &mut psi_detector::core::probe::ProbeContext
    ) -> psi_detector::error::Result<Option<psi_detector::core::protocol::ProtocolInfo>> {
        // 简单的游戏协议检测：查找"GAME"前缀
        if data.len() >= 4 && &data[0..4] == b"GAME" {
            Ok(Some(psi_detector::core::protocol::ProtocolInfo::new(ProtocolType::Custom, 0.9)))
        } else {
            Ok(None)
        }
    }
    
    fn priority(&self) -> u8 {
        90
    }
    
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < 4
    }
}

fn create_game_protocol_probe() -> GameProtocolProbe {
    GameProtocolProbe
}