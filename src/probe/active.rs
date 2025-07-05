//! 主动探测模块
//!
//! 通过发送特定数据包来主动探测协议类型。

use crate::core::{ProtocolType, DetectionResult, ProtocolInfo};
use crate::core::detector::DetectionMethod;
use crate::error::{Result, DetectorError};
use super::{ProbeEngine, ProbeType};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 主动探测器
pub struct ActiveProbe {
    /// 探测超时时间
    timeout: Duration,
    /// 最大重试次数
    max_retries: u32,
    /// 是否启用激进模式
    aggressive_mode: bool,
}

impl ActiveProbe {
    /// 创建新的主动探测器
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            max_retries: 3,
            aggressive_mode: false,
        }
    }
    
    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// 设置最大重试次数
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
    
    /// 启用激进模式
    pub fn with_aggressive_mode(mut self, enabled: bool) -> Self {
        self.aggressive_mode = enabled;
        self
    }
    
    /// 生成HTTP/1.1探测数据
    fn generate_http1_probe(&self) -> Vec<u8> {
        b"GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n".to_vec()
    }
    
    /// 生成HTTP/2探测数据
    fn generate_http2_probe(&self) -> Vec<u8> {
        // HTTP/2连接前言
        let mut probe = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        
        // 添加SETTINGS帧
        let settings_frame = [
            0x00, 0x00, 0x00, // 长度: 0
            0x04,             // 类型: SETTINGS
            0x00,             // 标志: 0
            0x00, 0x00, 0x00, 0x00, // 流ID: 0
        ];
        probe.extend_from_slice(&settings_frame);
        
        probe
    }
    
    /// 生成QUIC探测数据
    fn generate_quic_probe(&self) -> Vec<u8> {
        // QUIC Initial包
        let mut probe = Vec::new();
        
        // 长包头标志 + 版本
        probe.push(0xc0); // 长包头 + Initial包类型
        probe.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
        
        // 目标连接ID长度和ID
        probe.push(0x08); // 8字节连接ID
        probe.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        
        // 源连接ID长度
        probe.push(0x00); // 0字节源连接ID
        
        // Token长度
        probe.push(0x00); // 0字节token
        
        // 包长度（变长整数）
        probe.extend_from_slice(&[0x40, 0x10]); // 16字节
        
        // 包号
        probe.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        // 填充数据
        probe.extend_from_slice(&[0x00; 12]);
        
        probe
    }
    
    /// 生成WebSocket探测数据
    fn generate_websocket_probe(&self) -> Vec<u8> {
        let probe = format!(
            "GET /ws HTTP/1.1\r\n\
             Host: probe\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        probe.into_bytes()
    }
    
    /// 分析探测响应
    fn analyze_response(&self, probe_type: ProtocolType, response: &[u8]) -> Option<f32> {
        match probe_type {
            ProtocolType::HTTP1_1 => self.analyze_http1_response(response),
            ProtocolType::HTTP2 => self.analyze_http2_response(response),
            ProtocolType::QUIC => self.analyze_quic_response(response),
            ProtocolType::WebSocket => self.analyze_websocket_response(response),
            _ => None,
        }
    }
    
    /// 分析HTTP/1.1响应
    fn analyze_http1_response(&self, response: &[u8]) -> Option<f32> {
        if response.is_empty() {
            return None;
        }
        
        let response_str = String::from_utf8_lossy(response);
        
        // 检查HTTP/1.1响应格式
        if response_str.starts_with("HTTP/1.1") {
            return Some(0.95);
        }
        
        if response_str.starts_with("HTTP/1.0") {
            return Some(0.9);
        }
        
        None
    }
    
    /// 分析HTTP/2响应
    fn analyze_http2_response(&self, response: &[u8]) -> Option<f32> {
        if response.len() < 9 {
            return None;
        }
        
        // 检查SETTINGS帧响应
        if response.len() >= 9 {
            let frame_type = response[3];
            if frame_type == 0x04 { // SETTINGS帧
                return Some(0.9);
            }
        }
        
        // 检查连接错误
        if response.len() >= 9 {
            let frame_type = response[3];
            if frame_type == 0x07 { // GOAWAY帧
                return Some(0.7); // 可能是HTTP/2但拒绝连接
            }
        }
        
        None
    }
    
    /// 分析QUIC响应
    fn analyze_quic_response(&self, response: &[u8]) -> Option<f32> {
        if response.is_empty() {
            return None;
        }
        
        let first_byte = response[0];
        
        // 检查QUIC包格式
        if (first_byte & 0x80) != 0 { // 长包头
            return Some(0.8);
        }
        
        // 检查版本协商包
        if response.len() >= 5 {
            let version = u32::from_be_bytes([
                response[1], response[2], response[3], response[4]
            ]);
            if version == 0 {
                return Some(0.9); // 版本协商响应
            }
        }
        
        None
    }
    
    /// 分析WebSocket响应
    fn analyze_websocket_response(&self, response: &[u8]) -> Option<f32> {
        let response_str = String::from_utf8_lossy(response);
        
        // 检查WebSocket升级响应
        if response_str.contains("HTTP/1.1 101 Switching Protocols") &&
           response_str.contains("Upgrade: websocket") {
            return Some(0.95);
        }
        
        // 检查WebSocket错误响应
        if response_str.contains("HTTP/1.1 400 Bad Request") &&
           response_str.contains("websocket") {
            return Some(0.7);
        }
        
        None
    }
    
    /// 执行单个协议探测
    fn probe_protocol(&self, protocol: ProtocolType, _target_data: &[u8]) -> Result<f32> {
        // 注意：这里是模拟实现，实际应用中需要真实的网络交互
        // 在真实环境中，这里会：
        // 1. 生成探测数据包
        // 2. 发送到目标
        // 3. 等待响应
        // 4. 分析响应
        
        let probe_data = match protocol {
            ProtocolType::HTTP1_1 => self.generate_http1_probe(),
            ProtocolType::HTTP2 => self.generate_http2_probe(),
            ProtocolType::QUIC => self.generate_quic_probe(),
            ProtocolType::WebSocket => self.generate_websocket_probe(),
            _ => return Err(DetectorError::unsupported_protocol(format!("{:?}", protocol))),
        };
        
        // 模拟网络延迟
        std::thread::sleep(Duration::from_millis(10));
        
        // 模拟响应分析（实际实现中这里会是真实的网络响应）
        let simulated_confidence = match protocol {
            ProtocolType::HTTP1_1 => 0.8,
            ProtocolType::HTTP2 => 0.7,
            ProtocolType::QUIC => 0.6,
            ProtocolType::WebSocket => 0.75,
            _ => 0.0,
        };
        
        // 在激进模式下提高置信度
        let confidence = if self.aggressive_mode {
            simulated_confidence * 1.2
        } else {
            simulated_confidence
        };
        
        Ok(confidence.min(1.0))
    }
}

impl ProbeEngine for ActiveProbe {
    fn probe(&self, data: &[u8]) -> Result<DetectionResult> {
        let start_time = Instant::now();
        
        // 要探测的协议列表
        let protocols = [
            ProtocolType::HTTP1_1,
            ProtocolType::HTTP2,
            ProtocolType::QUIC,
            ProtocolType::WebSocket,
        ];
        
        let mut best_protocol = ProtocolType::Unknown;
        let mut best_confidence = 0.0;
        let mut metadata = HashMap::new();
        
        for protocol in &protocols {
            // 检查超时
            if start_time.elapsed() > self.timeout {
                metadata.insert("timeout".to_string(), "true".to_string());
                break;
            }
            
            // 执行探测
            match self.probe_protocol(*protocol, data) {
                Ok(confidence) => {
                    if confidence > best_confidence {
                        best_confidence = confidence;
                        best_protocol = *protocol;
                    }
                    
                    metadata.insert(
                        format!("{:?}_confidence", protocol),
                        confidence.to_string()
                    );
                }
                Err(e) => {
                    metadata.insert(
                        format!("{:?}_error", protocol),
                        e.to_string()
                    );
                }
            }
        }
        
        metadata.insert("probe_duration_ms".to_string(), 
                       start_time.elapsed().as_millis().to_string());
        metadata.insert("aggressive_mode".to_string(), 
                       self.aggressive_mode.to_string());
        
        if best_confidence < 0.5 {
            return Err(DetectorError::detection_failed(
                "Active probe confidence too low"
            ));
        }
        
        let protocol_info = ProtocolInfo::new(best_protocol, best_confidence);
        
        Ok(DetectionResult::new(
            protocol_info,
            start_time.elapsed(),
            DetectionMethod::Active,
            "ActiveProbe".to_string(),
        ))
    }
    
    fn probe_type(&self) -> ProbeType {
        ProbeType::Active
    }
    
    fn needs_more_data(&self, _data: &[u8]) -> bool {
        false // 主动探测不依赖输入数据
    }
}

impl Default for ActiveProbe {
    fn default() -> Self {
        Self::new()
    }
}