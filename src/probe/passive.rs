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
    
    /// 检测HTTP/3协议 (优化版)
    fn detect_http3(&self, data: &[u8]) -> Option<f32> {
        // HTTP/3基于QUIC，先检查QUIC
        if let Some(quic_confidence) = self.detect_quic(data) {
            if quic_confidence > 0.7 {
                let mut http3_confidence = 0.0;
                
                // 快速检查HTTP/3特有的ALPN标识符
                if self.fast_search(data, b"h3") || self.fast_search(data, b"h3-") {
                    http3_confidence += 0.5;
                }
                
                // 检查HTTP/3帧类型（扩展检测范围）
                if data.len() >= 20 {
                    // 扩展检查位置，包括更多可能的帧位置
                    let check_positions = [16, 20, 24, 28, 32, 36, 40, 44, 48, 52];
                    for &pos in &check_positions {
                        if pos < data.len() {
                            let frame_type = data[pos];
                            // HTTP/3帧类型：DATA(0x0), HEADERS(0x1), SETTINGS(0x4), PUSH_PROMISE(0x5)
                            // GOAWAY(0x7), MAX_PUSH_ID(0xd), DUPLICATE_PUSH(0xe)
                            if matches!(frame_type, 0x0 | 0x1 | 0x4 | 0x5 | 0x7 | 0xd | 0xe) {
                                http3_confidence += 0.4;
                                break;
                            }
                        }
                    }
                }
                
                // 检查QPACK相关的设置参数（HTTP/3特有）
                if self.fast_search(data, &[0x01, 0x40]) || // QPACK_MAX_TABLE_CAPACITY
                   self.fast_search(data, &[0x06, 0x40]) {   // QPACK_BLOCKED_STREAMS
                    http3_confidence += 0.3;
                }
                
                // 如果有明确的HTTP/3特征，返回高置信度
                if http3_confidence >= 0.4 {
                    return Some((quic_confidence + http3_confidence).min(0.95));
                }
                
                // 如果是QUIC但没有明确的HTTP/3标识，仍然可能是HTTP/3
                return Some(quic_confidence * 0.6);
            }
        }
        
        None
    }
    
    /// 检测gRPC协议 (优化版)
    fn detect_grpc(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 16 {
            return None;
        }
        
        let mut confidence: f32 = 0.0;
        
        // 快速检查 HTTP/2 连接前言 (只检查开头)
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if data.len() >= 24 && data.starts_with(HTTP2_PREFACE) {
            confidence += 0.4;
        }
        
        // 使用 memmem 风格的快速搜索 application/grpc
        if self.fast_search(data, b"application/grpc") {
            confidence += 0.5;
        }
        
        // 优化的 HTTP/2 帧检测 - 只检查前几个可能的位置
        if data.len() >= 9 {
            let check_positions = [
                0,  // 开头
                24, // HTTP/2 前言之后
                33, // 可能的第二帧位置
            ];
            
            for &pos in &check_positions {
                if pos + 9 <= data.len() {
                    let frame_type = data[pos + 3];
                    // 检查常见的 HTTP/2 帧类型
                    if matches!(frame_type, 0x00..=0x08) {
                        confidence += 0.3;
                        break;
                    }
                }
            }
        }
        
        // 如果同时具备多个特征，给予高置信度
        if confidence >= 0.8 {
            confidence = confidence.max(0.9);
        }
        
        if confidence > 0.5 {
            Some(confidence)
        } else {
            None
        }
    }
    
    /// 快速字节序列搜索 (Boyer-Moore 简化版)
    #[inline]
    fn fast_search(&self, haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        
        // 对于短模式，直接使用简单搜索
        if needle.len() <= 4 {
            return haystack.windows(needle.len()).any(|window| window == needle);
        }
        
        // 使用最后一个字节作为快速跳过的依据
        let last_byte = needle[needle.len() - 1];
        let mut i = needle.len() - 1;
        let max_iterations = haystack.len() * 2;
        let mut iteration_count = 0;
        
        while i < haystack.len() && iteration_count < max_iterations {
            iteration_count += 1;
            
            if haystack[i] == last_byte {
                // 检查完整匹配
                let start = i + 1 - needle.len();
                if start <= i && haystack[start..=i] == *needle {
                    return true;
                }
            }
            i += 1;
        }
        
        false
    }
    
    /// 检测WebSocket协议 (优化版)
    fn detect_websocket(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 20 {
            return None;
        }
        
        // 首先检查是否明确是 HTTP 请求/响应
        let is_http_like = self.fast_search(data, b"HTTP/") || 
                          self.fast_search(data, b"GET ") ||
                          self.fast_search(data, b"POST ");
        
        if is_http_like {
            // 快速检查 WebSocket 升级头部
            let has_upgrade_websocket = self.fast_search(data, b"Upgrade: websocket") ||
                                       self.fast_search(data, b"upgrade: websocket");
            
            if has_upgrade_websocket {
                // 检查是否是握手响应
                if self.fast_search(data, b"HTTP/1.1 101") {
                    return Some(0.98);
                }
                // 普通握手请求应该优先识别为 HTTP1_1，降低 WebSocket 置信度
                return Some(0.75);
            }
            
            // 如果是 HTTP 但没有 WebSocket 升级，不是 WebSocket
            return None;
        }
        
        // 检查 WebSocket 帧格式 (数据帧) - 更严格的检查
        if data.len() >= 2 {
            let first_byte = data[0];
            let second_byte = data[1];
            
            // WebSocket 帧的 FIN 位和操作码检查
            let opcode = first_byte & 0x0F;
            let masked = (second_byte & 0x80) != 0;
            let payload_len = second_byte & 0x7F;
            
            // 检查有效的操作码和合理的载荷长度
            if matches!(opcode, 0x0..=0x2 | 0x8..=0xA) && payload_len <= 125 {
                // 进一步验证帧结构
                let expected_header_len = if masked { 6 } else { 2 };
                if data.len() >= expected_header_len {
                    return Some(0.6); // 降低置信度，避免误判
                }
            }
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
    
    /// 检测SSH协议 (优化版)
    fn detect_ssh(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 4 {
            return None;
        }
        
        // SSH协议标识字符串 - 直接字节比较
        if data.starts_with(b"SSH-2.0") {
            return Some(0.98);
        }
        
        if data.starts_with(b"SSH-1.") {
            return Some(0.95);
        }
        
        // 检查通用 SSH 标识
        if data.starts_with(b"SSH-") {
            return Some(0.9);
        }
        
        // 检查可能的 SSH 二进制协议包
        if data.len() >= 6 {
            // SSH 二进制包通常以包长度开始
            let packet_length = u32::from_be_bytes([
                data[0], data[1], data[2], data[3]
            ]);
            
            // 合理的包长度范围 (避免误判)
            if packet_length > 0 && packet_length < 65536 && 
               packet_length as usize <= data.len() - 4 {
                // 检查填充长度字节
                let padding_length = data[4];
                if padding_length < 255 {
                    return Some(0.6);
                }
            }
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
        
        // 尝试各种协议检测 (按优先级排序)
        // 使用栈分配的数组来减少堆分配
        let mut detections = [(ProtocolType::Unknown, 0.0); 8];
        let mut detection_count = 0;
        
        // 按优先级检测协议
        if let Some(confidence) = self.detect_http3(data) {
            detections[detection_count] = (ProtocolType::HTTP3, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_quic(data) {
            detections[detection_count] = (ProtocolType::QUIC, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_http2(data) {
            detections[detection_count] = (ProtocolType::HTTP2, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_grpc(data) {
            detections[detection_count] = (ProtocolType::GRPC, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_http1(data) {
            detections[detection_count] = (ProtocolType::HTTP1_1, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_tls(data) {
            detections[detection_count] = (ProtocolType::TLS, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_ssh(data) {
            detections[detection_count] = (ProtocolType::SSH, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_websocket(data) {
            detections[detection_count] = (ProtocolType::WebSocket, confidence);
            detection_count += 1;
        }
        
        // 找到最佳匹配
        for i in 0..detection_count {
            let (protocol, confidence) = detections[i];
            if confidence > best_confidence {
                best_confidence = confidence;
                best_protocol = protocol;
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
            ProtocolType::UDP,
        ]
    }
    
    fn probe(&self, data: &[u8], context: &mut ProbeContext) -> Result<Option<ProtocolInfo>> {
        if data.len() < self.min_data_size {
            return Ok(None);
        }
        
        let mut best_protocol = ProtocolType::Unknown;
        let mut best_confidence = 0.0;
        
        // 尝试各种协议检测 (按优先级排序)
        // 使用栈分配的数组来减少堆分配
        let mut detections = [(ProtocolType::Unknown, 0.0); 8];
        let mut detection_count = 0;
        
        // 按优先级检测协议
        if let Some(confidence) = self.detect_http3(data) {
            detections[detection_count] = (ProtocolType::HTTP3, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_quic(data) {
            detections[detection_count] = (ProtocolType::QUIC, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_http2(data) {
            detections[detection_count] = (ProtocolType::HTTP2, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_grpc(data) {
            detections[detection_count] = (ProtocolType::GRPC, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_http1(data) {
            detections[detection_count] = (ProtocolType::HTTP1_1, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_tls(data) {
            detections[detection_count] = (ProtocolType::TLS, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_ssh(data) {
            detections[detection_count] = (ProtocolType::SSH, confidence);
            detection_count += 1;
        }
        if let Some(confidence) = self.detect_websocket(data) {
            detections[detection_count] = (ProtocolType::WebSocket, confidence);
            detection_count += 1;
        }
        
        // 找到最佳匹配
        for i in 0..detection_count {
            let (protocol, confidence) = detections[i];
            if confidence > best_confidence {
                best_confidence = confidence;
                best_protocol = protocol;
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