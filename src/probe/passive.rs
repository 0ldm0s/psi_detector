//! 被动探测模块
//!
//! 通过分析数据包特征进行协议识别，不发送额外数据。

use crate::core::{ProtocolType, DetectionResult, ProtocolInfo};
use crate::core::detector::DetectionMethod;
use crate::core::probe::{ProtocolProbe, ProbeContext};
use crate::error::{Result, DetectorError};
use super::{ProbeEngine, ProbeType};

/// 被动探测器
pub struct PassiveProbe {
    /// 最小数据要求
    min_data_size: usize,
    /// 置信度阈值
    confidence_threshold: f32,
}

impl PassiveProbe {
    /// 创建新的被动探测器
    pub fn new() -> Self {
        Self {
            min_data_size: 16,
            confidence_threshold: 0.7,
        }
    }
    
    /// 设置最小数据要求
    pub fn with_min_data_size(mut self, size: usize) -> Self {
        self.min_data_size = size;
        self
    }
    
    /// 设置置信度阈值
    pub fn with_confidence_threshold(mut self, threshold: f32) -> Self {
        self.confidence_threshold = threshold;
        self
    }
    
    /// 检测HTTP/1.1协议
    fn detect_http1(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 8 {
            return None;
        }
        
        // 检查HTTP方法
        let methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE"];
        for method in &methods {
            if data.starts_with(*method) {
                return Some(0.9);
            }
        }
        
        // 检查HTTP响应
        if data.starts_with(b"HTTP/1.") {
            return Some(0.95);
        }
        
        None
    }
    
    /// 检测HTTP/2协议
    fn detect_http2(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 24 {
            return None;
        }
        
        // HTTP/2连接前言
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if data.starts_with(HTTP2_PREFACE) {
            return Some(1.0);
        }
        
        // 检查HTTP/2帧格式
        if data.len() >= 9 {
            let frame_type = data[3];
            // SETTINGS帧 (0x4) 或 HEADERS帧 (0x1)
            if frame_type == 0x4 || frame_type == 0x1 {
                return Some(0.8);
            }
        }
        
        None
    }
    
    /// 检测QUIC协议
    fn detect_quic(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 16 {
            return None;
        }
        
        // QUIC长包头格式检查
        let first_byte = data[0];
        if (first_byte & 0x80) != 0 { // 长包头标志
            let version = u32::from_be_bytes([
                data[1], data[2], data[3], data[4]
            ]);
            
            // 检查已知的QUIC版本
            match version {
                0x00000001 => return Some(0.95), // QUIC v1
                0xff00001d => return Some(0.9),  // Draft-29
                0 => return Some(0.7),           // 版本协商
                _ => {}
            }
        }
        
        None
    }
    
    /// 检测HTTP/3协议
    fn detect_http3(&self, data: &[u8]) -> Option<f32> {
        // HTTP/3基于QUIC，先检查QUIC
        if let Some(quic_confidence) = self.detect_quic(data) {
            if quic_confidence > 0.7 {
                // 检查HTTP/3特有的ALPN或帧类型
                // HTTP/3使用特定的ALPN标识符 "h3" 或 "h3-XX"
                let data_str = String::from_utf8_lossy(data);
                if data_str.contains("h3") || data_str.contains("h3-") {
                    return Some(0.9);
                }
                
                // 检查HTTP/3帧类型（简化检测）
                if data.len() >= 20 {
                    // 查找可能的HTTP/3帧类型标识
                    for i in 0..data.len().saturating_sub(4) {
                        let frame_type = data[i];
                        // HTTP/3帧类型：DATA(0x0), HEADERS(0x1), SETTINGS(0x4)
                        if matches!(frame_type, 0x0 | 0x1 | 0x4) {
                            return Some(quic_confidence * 0.85);
                        }
                    }
                }
                
                // 如果是QUIC但没有明确的HTTP/3标识，给较低置信度
                return Some(quic_confidence * 0.6);
            }
        }
        
        None
    }
    
    /// 检测gRPC协议
    fn detect_grpc(&self, data: &[u8]) -> Option<f32> {
        // gRPC基于HTTP/2，先检查HTTP/2
        if let Some(h2_confidence) = self.detect_http2(data) {
            if h2_confidence > 0.7 {
                // 检查gRPC特有的头部
                // 这里简化处理，实际需要解析HTTP/2帧
                return Some(h2_confidence * 0.8);
            }
        }
        
        None
    }
    
    /// 检测WebSocket协议
    fn detect_websocket(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 20 {
            return None;
        }
        
        let data_str = String::from_utf8_lossy(data);
        
        // WebSocket握手请求
        if data_str.contains("Upgrade: websocket") {
            return Some(0.95);
        }
        
        // WebSocket握手响应
        if data_str.contains("HTTP/1.1 101 Switching Protocols") &&
           data_str.contains("Upgrade: websocket") {
            return Some(0.98);
        }
        
        None
    }
    
    /// 检测TLS协议
    fn detect_tls(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 5 {
            return None;
        }
        
        let content_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];
        
        // TLS内容类型检查
        let valid_content_type = matches!(content_type, 0x14 | 0x15 | 0x16 | 0x17);
        
        // TLS版本检查
        let valid_version = match (version_major, version_minor) {
            (0x03, 0x00) => true, // SSL 3.0
            (0x03, 0x01) => true, // TLS 1.0
            (0x03, 0x02) => true, // TLS 1.1
            (0x03, 0x03) => true, // TLS 1.2
            (0x03, 0x04) => true, // TLS 1.3
            _ => false,
        };
        
        if valid_content_type && valid_version {
            // ClientHello (0x16) 有最高置信度
            if content_type == 0x16 {
                Some(0.95)
            } else {
                Some(0.8)
            }
        } else {
            None
        }
    }
    
    /// 检测SSH协议
    fn detect_ssh(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 8 {
            return None;
        }
        
        // SSH协议标识字符串
        if data.starts_with(b"SSH-2.0") {
            return Some(0.98);
        }
        
        if data.starts_with(b"SSH-1.") {
            return Some(0.95);
        }
        
        // 检查是否包含SSH标识
        let data_str = String::from_utf8_lossy(data);
        if data_str.starts_with("SSH-") {
            return Some(0.9);
        }
        
        None
    }
}

impl ProbeEngine for PassiveProbe {
    fn probe(&self, data: &[u8]) -> Result<DetectionResult> {
        if data.len() < self.min_data_size {
            return Err(DetectorError::NeedMoreData(self.min_data_size));
        }
        
        let mut best_protocol = ProtocolType::Unknown;
        let mut best_confidence = 0.0;
        
        // 尝试各种协议检测
        let detections = [
            (ProtocolType::HTTP1_1, self.detect_http1(data)),
            (ProtocolType::HTTP2, self.detect_http2(data)),
            (ProtocolType::HTTP3, self.detect_http3(data)),
            (ProtocolType::QUIC, self.detect_quic(data)),
            (ProtocolType::GRPC, self.detect_grpc(data)),
            (ProtocolType::WebSocket, self.detect_websocket(data)),
            (ProtocolType::TLS, self.detect_tls(data)),
            (ProtocolType::SSH, self.detect_ssh(data)),
        ];
        
        for (protocol, confidence_opt) in detections {
            if let Some(confidence) = confidence_opt {
                if confidence > best_confidence {
                    best_confidence = confidence;
                    best_protocol = protocol;
                }
            }
        }
        
        if best_confidence < self.confidence_threshold {
            return Err(DetectorError::detection_failed(
                format!("Confidence {} below threshold {}", 
                       best_confidence, self.confidence_threshold)
            ));
        }
        
        let protocol_info = ProtocolInfo::new(best_protocol, best_confidence);
        
        Ok(DetectionResult::new(
            protocol_info,
            std::time::Duration::from_millis(0), // 被动探测时间很短
            DetectionMethod::Passive,
            "PassiveProbe".to_string(),
        ))
    }
    
    fn probe_type(&self) -> ProbeType {
        ProbeType::Passive
    }
    
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < self.min_data_size
    }
}

impl Default for PassiveProbe {
    fn default() -> Self {
        Self::new()
    }
}

// 实现 ProtocolProbe trait
impl ProtocolProbe for PassiveProbe {
    fn name(&self) -> &'static str {
        "PassiveProbe"
    }
    
    fn supported_protocols(&self) -> Vec<ProtocolType> {
        vec![
            ProtocolType::HTTP1_1,
            ProtocolType::HTTP2,
            ProtocolType::HTTP3,
            ProtocolType::QUIC,
            ProtocolType::GRPC,
            ProtocolType::WebSocket,
            ProtocolType::TLS,
            ProtocolType::SSH,
        ]
    }
    
    fn probe(&self, data: &[u8], context: &mut ProbeContext) -> Result<Option<ProtocolInfo>> {
        if data.len() < self.min_data_size {
            return Ok(None);
        }
        
        let mut best_protocol = ProtocolType::Unknown;
        let mut best_confidence = 0.0;
        
        // 尝试各种协议检测
        let detections = [
            (ProtocolType::HTTP1_1, self.detect_http1(data)),
            (ProtocolType::HTTP2, self.detect_http2(data)),
            (ProtocolType::QUIC, self.detect_quic(data)),
            (ProtocolType::GRPC, self.detect_grpc(data)),
            (ProtocolType::WebSocket, self.detect_websocket(data)),
            (ProtocolType::TLS, self.detect_tls(data)),
            (ProtocolType::SSH, self.detect_ssh(data)),
        ];
        
        for (protocol, confidence_opt) in detections {
            if let Some(confidence) = confidence_opt {
                if confidence > best_confidence {
                    best_confidence = confidence;
                    best_protocol = protocol;
                }
            }
        }
        
        if best_confidence >= self.confidence_threshold {
            let protocol_info = ProtocolInfo::new(best_protocol, best_confidence);
            context.add_candidate(protocol_info.clone());
            Ok(Some(protocol_info))
        } else {
            Ok(None)
        }
    }
    
    fn priority(&self) -> u8 {
        80 // 被动探测器有较高优先级
    }
    
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < self.min_data_size
    }
}