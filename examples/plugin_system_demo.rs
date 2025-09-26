//! 插件系统演示示例
//!
//! 演示如何使用 PSI-Detector 的插件系统创建自定义协议探测器
//! 本示例展示了一个 DNS 协议探测插件的实现和使用

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::{ProbeStrategy, ProbeContext, ProtocolProbe, ProtocolInfo},
    error::{DetectorError, Result},
};
use std::time::{Duration, Instant};

fn main() -> Result<()> {
    println!("🔌 PSI-Detector 插件系统演示");
    
    // 1. 演示自定义 DNS 探测器插件
    println!("\n📡 1. DNS 协议探测插件演示");
    demonstrate_dns_plugin()?;
    
    // 2. 演示多插件集成
    println!("\n🔧 2. 多插件集成演示");
    demonstrate_multi_plugin_integration()?;
    
    // 3. 演示插件优先级
    println!("\n⚡ 3. 插件优先级演示");
    demonstrate_plugin_priority()?;
    
    println!("\n🎉 插件系统演示完成!");
    Ok(())
}

/// DNS 协议探测器插件
/// 
/// 实现 ProtocolProbe trait 来创建自定义协议探测器
#[derive(Debug)]
struct DnsProbe {
    name: &'static str,
    priority: u8,
    min_packet_size: usize,
}

impl DnsProbe {
    /// 创建新的 DNS 探测器
    pub fn new() -> Self {
        Self {
            name: "DNS-UDP-Probe",
            priority: 60, // 高于默认优先级
            min_packet_size: 12, // DNS 头部最小长度
        }
    }
    
    /// 验证 DNS 头部格式
    fn validate_dns_header(&self, data: &[u8]) -> bool {
        if data.len() < self.min_packet_size {
            return false;
        }
        
        // DNS 头部结构验证
        // 0-1: Transaction ID
        // 2-3: Flags
        // 4-5: Questions count
        // 6-7: Answer RRs
        // 8-9: Authority RRs  
        // 10-11: Additional RRs
        
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let questions = u16::from_be_bytes([data[4], data[5]]);
        
        // 检查 DNS 标志位的合理性
        let qr = (flags >> 15) & 1; // Query/Response flag
        let opcode = (flags >> 11) & 0xF; // Operation code
        let rcode = flags & 0xF; // Response code
        
        // 基本合理性检查
        if opcode > 5 { // 标准操作码范围 0-5
            return false;
        }
        
        if qr == 0 && rcode != 0 { // 查询包的响应码应该为0
            return false;
        }
        
        if questions == 0 && qr == 0 { // 查询包至少要有一个问题
            return false;
        }
        
        if questions > 100 { // 问题数量不应该过多
            return false;
        }
        
        true
    }
    
    /// 计算 DNS 探测置信度
    fn calculate_confidence(&self, data: &[u8]) -> f32 {
        let mut confidence: f32 = 0.0;
        
        if data.len() < self.min_packet_size {
            return 0.0;
        }
        
        // 基础头部验证
        if self.validate_dns_header(data) {
            confidence += 0.6;
        } else {
            return 0.0;
        }
        
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let questions = u16::from_be_bytes([data[4], data[5]]);
        
        // 检查是否为标准查询
        let opcode = (flags >> 11) & 0xF;
        if opcode == 0 { // 标准查询
            confidence += 0.2;
        }
        
        // 检查问题数量的合理性
        if questions >= 1 && questions <= 10 {
            confidence += 0.1;
        }
        
        // 如果有足够数据，检查查询名称格式
        if data.len() > 12 {
            if self.validate_domain_name(&data[12..]) {
                confidence += 0.1;
            }
        }
        
        confidence.min(1.0)
    }
    
    /// 验证域名格式
    fn validate_domain_name(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        
        let mut pos = 0;
        let mut labels = 0;
        
        while pos < data.len() && labels < 63 { // RFC 限制标签数量
            let len = data[pos] as usize;
            
            if len == 0 {
                // 域名结束
                return labels > 0;
            }
            
            if len > 63 {
                // 标签长度超限
                return false;
            }
            
            if pos + 1 + len >= data.len() {
                // 数据不足
                return false;
            }
            
            // 检查标签字符的合理性
            for i in 1..=len {
                let c = data[pos + i];
                if !c.is_ascii_alphanumeric() && c != b'-' && c != b'_' {
                    return false;
                }
            }
            
            pos += 1 + len;
            labels += 1;
        }
        
        false
    }
}

impl ProtocolProbe for DnsProbe {
    fn name(&self) -> &'static str {
        self.name
    }
    
    fn supported_protocols(&self) -> Vec<ProtocolType> {
        vec![ProtocolType::Custom] // 使用Custom类型表示自定义协议
    }
    
    fn probe(&self, data: &[u8], context: &mut ProbeContext) -> Result<Option<ProtocolInfo>> {
        let start_time = Instant::now();
        
        if data.len() < self.min_packet_size {
            return Ok(None);
        }
        
        let confidence = self.calculate_confidence(data);
        
        if confidence > 0.5 {
            let mut protocol_info = ProtocolInfo::new(ProtocolType::Custom, confidence);
            protocol_info.add_feature("DNS-UDP");
            protocol_info.add_feature(format!("confidence-{:.1}%", confidence * 100.0));
            protocol_info.add_metadata("transport", "UDP");
            protocol_info.add_metadata("protocol_name", "DNS"); // 标识具体的协议名称
            protocol_info.add_metadata("details", format!("DNS packet detected (UDP), confidence: {:.1}%", confidence * 100.0));
            
            context.add_candidate(protocol_info.clone());
            Ok(Some(protocol_info))
        } else {
            Ok(None)
        }
    }
    
    fn priority(&self) -> u8 {
        self.priority
    }
    
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < self.min_packet_size
    }
}

/// MQTT 协议探测器插件（演示多插件）
#[derive(Debug)]
struct MqttProbe {
    name: &'static str,
    priority: u8,
}

impl MqttProbe {
    pub fn new() -> Self {
        Self {
            name: "MQTT-TCP-Probe",
            priority: 55,
        }
    }
    
    fn is_mqtt_connect(&self, data: &[u8]) -> bool {
        if data.len() < 10 {
            return false;
        }
        
        // MQTT CONNECT 包格式检查
        // 第一个字节应该是 0x10 (CONNECT)
        if data[0] != 0x10 {
            return false;
        }
        
        // 检查协议名称 "MQTT" 或 "MQIsdp"
        if data.len() > 8 {
            let protocol_name_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if protocol_name_len == 4 && data.len() > 6 + protocol_name_len {
                let protocol_name = &data[4..8];
                return protocol_name == b"MQTT";
            }
        }
        
        false
    }
}

impl ProtocolProbe for MqttProbe {
    fn name(&self) -> &'static str {
        self.name
    }
    
    fn supported_protocols(&self) -> Vec<ProtocolType> {
        vec![ProtocolType::Custom] // 使用Custom类型表示自定义协议
    }

    fn probe(&self, data: &[u8], context: &mut ProbeContext) -> Result<Option<ProtocolInfo>> {
        if self.is_mqtt_connect(data) {
            let mut protocol_info = ProtocolInfo::new(ProtocolType::Custom, 0.9);
            protocol_info.add_feature("MQTT-CONNECT");
            protocol_info.add_metadata("transport", "TCP");
            protocol_info.add_metadata("protocol_name", "MQTT"); // 标识具体的协议名称
            protocol_info.add_metadata("details", "MQTT CONNECT packet detected");

            context.add_candidate(protocol_info.clone());
            Ok(Some(protocol_info))
        } else {
            Ok(None)
        }
    }
    
    fn priority(&self) -> u8 {
        self.priority
    }
    
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < 10
    }
}

/// 演示 DNS 插件功能
fn demonstrate_dns_plugin() -> Result<()> {
    println!("   🔍 创建带有 DNS 插件的探测器");
    
    // 创建自定义 DNS 探测器
    let dns_probe = DnsProbe::new();
    
    // 使用 DetectorBuilder 注册自定义探测器
    let detector = DetectorBuilder::new()
        .enable_http() // 保留基础协议支持
        .enable_tls()
        .enable_custom() // 启用自定义协议支持
        .add_custom_probe(Box::new(dns_probe)) // 添加自定义 DNS 探测器
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(100))
        .build()?;
    
    // 测试 DNS 查询包
    let dns_query = create_dns_query_packet();
    println!("   📦 测试 DNS 查询包 ({} bytes)", dns_query.len());
    
    let result = detector.detect(&dns_query)?;
    println!("   ✅ DNS 探测结果:");
    println!("      协议类型: {:?}", result.protocol_type());
    println!("      置信度: {:.1}%", result.confidence() * 100.0);
    if let Some(details) = result.protocol_info.metadata.get("details") {
        println!("      详情: {}", details);
    }
    println!("      探测时间: {:?}", result.detection_time);
    
    // 测试非 DNS 数据
    let http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    println!("\n   📦 测试 HTTP 数据包 ({} bytes)", http_data.len());
    
    let result = detector.detect(http_data)?;
    println!("   ✅ HTTP 探测结果:");
    println!("      协议类型: {:?}", result.protocol_type());
    println!("      置信度: {:.1}%", result.confidence() * 100.0);
    
    Ok(())
}

/// 演示多插件集成
fn demonstrate_multi_plugin_integration() -> Result<()> {
    println!("   🔧 创建多插件集成探测器");
    
    let detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .enable_ssh()
        .enable_custom()
        .add_custom_probe(Box::new(DnsProbe::new()))
        .add_custom_probe(Box::new(MqttProbe::new()))
        .with_strategy(ProbeStrategy::Passive)
        .build()?;
    
    let test_cases = vec![
        ("DNS 查询", create_dns_query_packet()),
        ("MQTT 连接", create_mqtt_connect_packet()),
        ("HTTP 请求", b"GET /api HTTP/1.1\r\nHost: test.com\r\n\r\n".to_vec()),
        ("SSH 握手", b"SSH-2.0-OpenSSH_8.0\r\n".to_vec()),
    ];
    
    for (name, data) in test_cases {
        println!("\n   📦 测试 {} ({} bytes)", name, data.len());
        
        match detector.detect(&data) {
            Ok(result) => {
                println!("   ✅ 探测成功:");
                println!("      协议: {:?}", result.protocol_type());
                println!("      置信度: {:.1}%", result.confidence() * 100.0);
                println!("      探测器: {}", result.detector_name);
                if let Some(details) = result.protocol_info.metadata.get("details") {
                    println!("      详情: {}", details);
                }
            }
            Err(e) => {
                println!("   ❌ 探测失败: {}", e);
            }
        }
    }
    
    Ok(())
}

/// 演示插件优先级
fn demonstrate_plugin_priority() -> Result<()> {
    println!("   ⚡ 测试插件优先级机制");
    
    // 创建高优先级 DNS 探测器
    let high_priority_dns = DnsProbe {
        name: "High-Priority-DNS",
        priority: 90,
        min_packet_size: 12,
    };
    
    // 创建低优先级 DNS 探测器
    let low_priority_dns = DnsProbe {
        name: "Low-Priority-DNS",
        priority: 30,
        min_packet_size: 12,
    };
    
    let detector = DetectorBuilder::new()
        .enable_http() // 启用基础协议
        .enable_custom() // 启用自定义协议
        .add_custom_probe(Box::new(low_priority_dns))
        .add_custom_probe(Box::new(high_priority_dns))
        .build()?;
    
    let dns_data = create_dns_query_packet();
    let result = detector.detect(&dns_data)?;
    
    println!("   📊 优先级测试结果:");
    println!("      使用的探测器: {}", result.detector_name);
    println!("      协议类型: {:?}", result.protocol_type());
    println!("      置信度: {:.1}%", result.confidence() * 100.0);
    
    Ok(())
}

/// 创建 DNS 查询包
fn create_dns_query_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // DNS 头部 (12 bytes)
    packet.extend_from_slice(&[0x12, 0x34]); // Transaction ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0
    
    // 查询部分: example.com
    packet.push(7); // 长度
    packet.extend_from_slice(b"example");
    packet.push(3); // 长度
    packet.extend_from_slice(b"com");
    packet.push(0); // 结束
    
    // 查询类型和类别
    packet.extend_from_slice(&[0x00, 0x01]); // Type: A
    packet.extend_from_slice(&[0x00, 0x01]); // Class: IN
    
    packet
}

/// 创建 MQTT 连接包
fn create_mqtt_connect_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // MQTT 固定头部
    packet.push(0x10); // Message Type: CONNECT
    packet.push(0x10); // Remaining Length
    
    // 可变头部
    packet.extend_from_slice(&[0x00, 0x04]); // Protocol Name Length
    packet.extend_from_slice(b"MQTT"); // Protocol Name
    packet.push(0x04); // Protocol Level
    packet.push(0x02); // Connect Flags
    packet.extend_from_slice(&[0x00, 0x3C]); // Keep Alive
    
    // 载荷
    packet.extend_from_slice(&[0x00, 0x04]); // Client ID Length
    packet.extend_from_slice(b"test"); // Client ID
    
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dns_probe_creation() {
        let probe = DnsProbe::new();
        assert_eq!(probe.name(), "DNS-UDP-Probe");
        assert_eq!(probe.priority(), 60);
    }
    
    #[test]
    fn test_dns_packet_validation() {
        let probe = DnsProbe::new();
        let dns_packet = create_dns_query_packet();
        
        assert!(probe.validate_dns_header(&dns_packet));
        assert!(probe.calculate_confidence(&dns_packet) > 0.5);
    }
    
    #[test]
    fn test_mqtt_probe_creation() {
        let probe = MqttProbe::new();
        assert_eq!(probe.name(), "MQTT-TCP-Probe");
        assert_eq!(probe.priority(), 55);
    }
    
    #[test]
    fn test_mqtt_packet_detection() {
        let probe = MqttProbe::new();
        let mqtt_packet = create_mqtt_connect_packet();
        
        assert!(probe.is_mqtt_connect(&mqtt_packet));
    }
}