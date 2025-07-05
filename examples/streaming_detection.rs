//! 流式协议探测示例
//!
//! 演示如何使用 PSI-Detector 处理分块数据和实时协议探测

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy
};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌊 PSI-Detector 流式协议探测示例");
    
    // 创建探测器
    let detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(100))
        .build()?;
    
    println!("\n🔧 探测器配置:");
    println!("   支持协议: HTTP, TLS, SSH");
    println!("   探测策略: Passive");
    println!("   超时时间: 100ms");
    
    // 模拟分块数据流
    let stream_scenarios = vec![
        StreamScenario {
            name: "HTTP 请求流",
            expected_protocol: ProtocolType::HTTP1_1,
            data_chunks: vec![
                b"GET /api/users".to_vec(),
                b" HTTP/1.1\r\nHost: api.example.com\r\n".to_vec(),
                b"Authorization: Bearer token123\r\n".to_vec(),
                b"Content-Type: application/json\r\n\r\n".to_vec(),
            ],
        },
        StreamScenario {
            name: "TLS 握手流",
            expected_protocol: ProtocolType::TLS,
            data_chunks: vec![
                vec![0x16, 0x03, 0x01], // TLS Record start
                vec![0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b], // Record length + ClientHello start
                vec![0x03, 0x03], // TLS version
                // Random bytes (simplified)
                (0..32).collect::<Vec<u8>>(),
            ],
        },
        StreamScenario {
            name: "SSH 连接流",
            expected_protocol: ProtocolType::SSH,
            data_chunks: vec![
                b"SSH-2.0-".to_vec(),
                b"OpenSSH_8.0".to_vec(),
                b"\r\n".to_vec(),
            ],
        },
    ];
    
    println!("\n🚀 开始分块数据处理...");
    
    // 处理每个流场景
    for scenario in &stream_scenarios {
        println!("\n📡 处理流: {}", scenario.name);
        
        // 逐块处理数据
        let mut accumulated_data = Vec::new();
        let mut total_processed = 0;
        let start_time = Instant::now();
        
        for (chunk_idx, chunk) in scenario.data_chunks.iter().enumerate() {
            println!("   📦 处理数据块 {} ({} 字节)", chunk_idx + 1, chunk.len());
            
            // 累积数据
            accumulated_data.extend_from_slice(chunk);
            total_processed += chunk.len();
            
            // 尝试协议探测
            if accumulated_data.len() >= 16 { // 最小探测数据量
                match detector.detect(&accumulated_data) {
                    Ok(result) => {
                        println!("   🎯 探测结果: {:?} (置信度: {:.1}%)", 
                            result.protocol_info.protocol_type, result.confidence() * 100.0);
                        
                        if result.confidence() > 0.8 {
                            println!("   ✅ 高置信度探测，可以提前确定协议");
                            break; // 提前退出，节省资源
                        }
                    }
                    Err(_) => {
                        println!("   ⏳ 数据不足，继续收集...");
                    }
                }
            }
            
            // 模拟网络延迟
            std::thread::sleep(Duration::from_millis(10));
        }
        
        let processing_time = start_time.elapsed();
        
        // 最终探测结果
        match detector.detect(&accumulated_data) {
            Ok(result) => {
                println!("   🏁 最终探测结果:");
                println!("      协议: {:?}", result.protocol_info.protocol_type);
                println!("      置信度: {:.1}%", result.confidence() * 100.0);
                println!("      探测方法: {:?}", result.detection_method);
                println!("      处理时间: {:?}", processing_time);
                println!("      数据量: {} 字节", total_processed);
                println!("      吞吐量: {:.1} KB/s", 
                    total_processed as f64 / processing_time.as_secs_f64() / 1024.0);
                
                if result.protocol_info.protocol_type == scenario.expected_protocol {
                    println!("      ✅ 协议识别正确!");
                } else {
                    println!("      ⚠️  协议识别不匹配，期望: {:?}", scenario.expected_protocol);
                }
            }
            Err(e) => {
                println!("   ❌ 最终探测失败: {}", e);
            }
        }
    }
    
    println!("\n🎉 分块数据协议探测示例完成!");
    Ok(())
}

#[derive(Debug, Clone)]
struct StreamScenario {
    name: &'static str,
    expected_protocol: ProtocolType,
    data_chunks: Vec<Vec<u8>>,
}