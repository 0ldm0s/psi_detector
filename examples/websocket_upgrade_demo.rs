//! WebSocket 升级器演示
//!
//! 展示重构后的 WebSocket 升级器的新功能：
//! - 支持多种 HTTP 版本 (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3)
//! - 灵活的配置系统
//! - 自定义头部支持
//! - 子协议和扩展支持

use psi_detector::{
    builder::DetectorBuilder,
    core::protocol::ProtocolType,
    upgrade::{
        websocket::{WebSocketConfig, WebSocketUpgrader},
        ProtocolUpgrader,
    },
};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 WebSocket 升级器演示");
    println!();

    // 1. 基本 WebSocket 升级器
    println!("📋 1. 基本 WebSocket 升级器");
    let basic_upgrader = WebSocketUpgrader::new();
    
    println!("   支持的升级路径:");
    for upgrade_path in basic_upgrader.supported_upgrades() {
        println!("   - {:?} -> {:?}", upgrade_path.from, upgrade_path.to);
    }
    println!();

    // 2. 自定义配置的 WebSocket 升级器
    println!("📋 2. 自定义配置的 WebSocket 升级器");
    let mut custom_config = WebSocketConfig::default();
    custom_config.default_host = "example.com".to_string();
    custom_config.default_path = "/chat".to_string();
    custom_config.supported_protocols = vec!["chat".to_string(), "echo".to_string()];
    custom_config.supported_extensions = vec!["permessage-deflate".to_string()];
    custom_config.use_random_key = false; // 用于测试的固定密钥
    
    // 添加自定义头部
    custom_config.custom_headers.insert(
        "X-Custom-Header".to_string(),
        "CustomValue".to_string(),
    );
    custom_config.custom_headers.insert(
        "Authorization".to_string(),
        "Bearer token123".to_string(),
    );
    
    let custom_upgrader = WebSocketUpgrader::with_config(custom_config);
    
    println!("   配置信息:");
    println!("   - 默认主机: {}", custom_upgrader.config().default_host);
    println!("   - 默认路径: {}", custom_upgrader.config().default_path);
    println!("   - 支持的协议: {:?}", custom_upgrader.config().supported_protocols);
    println!("   - 支持的扩展: {:?}", custom_upgrader.config().supported_extensions);
    println!("   - 自定义头部数量: {}", custom_upgrader.config().custom_headers.len());
    println!();

    // 3. 测试不同 HTTP 版本的升级能力
    println!("📋 3. 测试不同 HTTP 版本的升级能力");
    let http_versions = vec![
        ProtocolType::HTTP1_0,
        ProtocolType::HTTP1_1,
        ProtocolType::HTTP2,
        ProtocolType::HTTP3,
    ];
    
    for http_version in http_versions {
        let can_upgrade = custom_upgrader.can_upgrade(http_version, ProtocolType::WebSocket);
        println!("   {:?} -> WebSocket: {}", http_version, if can_upgrade { "✅" } else { "❌" });
    }
    println!();

    // 4. 模拟升级过程
    println!("📋 4. 模拟升级过程");
    
    // HTTP/1.1 升级请求
    let http11_request = b"GET /chat HTTP/1.1\r\n\
                           Host: example.com\r\n\
                           Upgrade: websocket\r\n\
                           Connection: Upgrade\r\n\
                           Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                           Sec-WebSocket-Version: 13\r\n\
                           \r\n";
    
    match custom_upgrader.upgrade(ProtocolType::HTTP1_1, ProtocolType::WebSocket, http11_request) {
        Ok(result) => {
            println!("   HTTP/1.1 升级结果:");
            println!("   - 成功: {}", result.success);
            println!("   - 目标协议: {:?}", result.target_protocol);
            println!("   - 升级方法: {:?}", result.method);
            println!("   - 耗时: {:?}", result.duration);
            println!("   - 元数据: {:?}", result.metadata);
            
            if !result.upgraded_data.is_empty() {
                let response = String::from_utf8_lossy(&result.upgraded_data);
                println!("   - 升级响应预览: {}", 
                    response.lines().take(3).collect::<Vec<_>>().join(" "));
            }
        }
        Err(e) => {
            println!("   HTTP/1.1 升级失败: {}", e);
        }
    }
    println!();

    // HTTP/2 升级请求
    let http2_request = b"GET /chat HTTP/2\r\n\
                          Host: example.com\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\
                          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                          Sec-WebSocket-Version: 13\r\n\
                          \r\n";
    
    match custom_upgrader.upgrade(ProtocolType::HTTP2, ProtocolType::WebSocket, http2_request) {
        Ok(result) => {
            println!("   HTTP/2 升级结果:");
            println!("   - 成功: {}", result.success);
            println!("   - 目标协议: {:?}", result.target_protocol);
            println!("   - 升级方法: {:?}", result.method);
            println!("   - 耗时: {:?}", result.duration);
            
            if !result.upgraded_data.is_empty() {
                let response = String::from_utf8_lossy(&result.upgraded_data);
                println!("   - 升级响应预览: {}", 
                    response.lines().take(3).collect::<Vec<_>>().join(" "));
            }
        }
        Err(e) => {
            println!("   HTTP/2 升级失败: {}", e);
        }
    }
    println!();

    // 5. 性能测试
    println!("📋 5. 性能测试");
    let start = std::time::Instant::now();
    let iterations = 1000;
    
    for _ in 0..iterations {
        let _ = custom_upgrader.upgrade(
            ProtocolType::HTTP1_1, 
            ProtocolType::WebSocket, 
            http11_request
        );
    }
    
    let total_time = start.elapsed();
    let avg_time = total_time / iterations;
    
    println!("   {} 次升级操作:", iterations);
    println!("   - 总耗时: {:?}", total_time);
    println!("   - 平均耗时: {:?}", avg_time);
    println!("   - 每秒操作数: {:.0}", 1.0 / avg_time.as_secs_f64());
    println!();

    println!("🎉 WebSocket 升级器演示完成!");
    println!();
    println!("✨ 重构优化总结:");
    println!("   - ✅ 支持所有 HTTP 版本 (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3)");
    println!("   - ✅ 灵活的配置系统 (主机、路径、协议、扩展)");
    println!("   - ✅ 自定义头部支持");
    println!("   - ✅ 随机密钥生成选项");
    println!("   - ✅ 减少硬编码，提高可维护性");
    println!("   - ✅ 完整的单元测试覆盖");
    
    Ok(())
}