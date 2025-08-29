//! SIMD探测器实现
//!
//! 提供基于SIMD指令的高性能协议探测实现。

use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};
use crate::simd::{SimdDetectionResult, SimdDetector, SimdInstructionSet};
use std::time::Instant;

/// 通用SIMD探测器（回退实现）
pub struct GenericSimdDetector {
    instruction_set: SimdInstructionSet,
}

impl GenericSimdDetector {
    /// 创建新的通用SIMD探测器
    pub fn new() -> Self {
        Self {
            instruction_set: SimdInstructionSet::None,
        }
    }
}

impl SimdDetector for GenericSimdDetector {
    fn detect_http2(&self, data: &[u8]) -> Result<SimdDetectionResult> {
        let start = Instant::now();
        
        // HTTP/2 连接前言
        let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        
        if data.len() >= http2_preface.len() && data.starts_with(http2_preface) {
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::HTTP2,
                confidence: 1.0,
                match_positions: vec![0],
                instruction_set: self.instruction_set,
            });
        }
        
        // 检查HTTP/2帧头
        if data.len() >= 9 {
            // HTTP/2帧格式：3字节长度 + 1字节类型 + 1字节标志 + 4字节流ID
            let frame_type = data[3];
            
            // 常见的HTTP/2帧类型
            match frame_type {
                0x0 => { // DATA帧
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::HTTP2,
                        confidence: 0.8,
                        match_positions: vec![3],
                        instruction_set: self.instruction_set,
                    });
                }
                0x1 => { // HEADERS帧
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::HTTP2,
                        confidence: 0.9,
                        match_positions: vec![3],
                        instruction_set: self.instruction_set,
                    });
                }
                0x4 => { // SETTINGS帧
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::HTTP2,
                        confidence: 0.95,
                        match_positions: vec![3],
                        instruction_set: self.instruction_set,
                    });
                }
                _ => {}
            }
        }
        
        Err(DetectorError::detection_failed("No HTTP/2 patterns found"))
    }
    
    fn detect_quic(&self, data: &[u8]) -> Result<SimdDetectionResult> {
        if data.is_empty() {
            return Err(DetectorError::detection_failed("Empty data"));
        }
        
        let first_byte = data[0];
        
        // QUIC长头部格式检查
        if (first_byte & 0x80) != 0 {
            // 这是一个长头部包
            if data.len() >= 5 {
                // 检查版本字段
                let version = u32::from_be_bytes([
                    data[1], data[2], data[3], data[4]
                ]);
                
                // QUIC版本1 (RFC 9000)
                if version == 0x00000001 {
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::QUIC,
                        confidence: 0.95,
                        match_positions: vec![0],
                        instruction_set: self.instruction_set,
                    });
                }
                
                // 版本协商包
                if version == 0x00000000 {
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::QUIC,
                        confidence: 0.9,
                        match_positions: vec![0],
                        instruction_set: self.instruction_set,
                    });
                }
            }
        } else {
            // 短头部包（1-RTT包）
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::QUIC,
                confidence: 0.7,
                match_positions: vec![0],
                instruction_set: self.instruction_set,
            });
        }
        
        Err(DetectorError::detection_failed("No QUIC patterns found"))
    }
    
    fn detect_grpc(&self, data: &[u8]) -> Result<SimdDetectionResult> {
        // gRPC通常基于HTTP/2，先检查是否有gRPC特征
        let grpc_content_type = b"application/grpc";
        
        // 在数据中搜索gRPC内容类型
        if let Some(pos) = find_pattern(data, grpc_content_type) {
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::GRPC,
                confidence: 0.9,
                match_positions: vec![pos],
                instruction_set: self.instruction_set,
            });
        }
        
        // 检查gRPC-Web
        let grpc_web = b"application/grpc-web";
        if let Some(pos) = find_pattern(data, grpc_web) {
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::GRPC,
                confidence: 0.85,
                match_positions: vec![pos],
                instruction_set: self.instruction_set,
            });
        }
        
        // 检查gRPC帧格式（压缩标志 + 4字节长度 + 消息）
        if data.len() >= 5 {
            let compression_flag = data[0];
            if compression_flag <= 1 { // 0或1是有效的压缩标志
                let message_length = u32::from_be_bytes([
                    data[1], data[2], data[3], data[4]
                ]) as usize;
                
                if message_length > 0 && data.len() >= 5 + message_length {
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::GRPC,
                        confidence: 0.7,
                        match_positions: vec![0],
                        instruction_set: self.instruction_set,
                    });
                }
            }
        }
        
        Err(DetectorError::detection_failed("No gRPC patterns found"))
    }
    
    fn detect_websocket(&self, data: &[u8]) -> Result<SimdDetectionResult> {
        let mut positions = Vec::new();
        let mut confidence = 0.0;
        
        // WebSocket升级请求特征
        let upgrade_header = b"Upgrade: websocket";
        if let Some(pos) = find_pattern_case_insensitive(data, upgrade_header) {
            positions.push(pos);
            confidence += 0.4;
        }
        
        let connection_header = b"Connection: Upgrade";
        if let Some(pos) = find_pattern_case_insensitive(data, connection_header) {
            positions.push(pos);
            confidence += 0.3;
        }
        
        let websocket_key = b"Sec-WebSocket-Key:";
        if let Some(pos) = find_pattern_case_insensitive(data, websocket_key) {
            positions.push(pos);
            confidence += 0.3;
        }
        
        // WebSocket帧格式检查
        if data.len() >= 2 {
            let first_byte = data[0];
            let second_byte = data[1];
            
            // 检查FIN位和操作码
            let fin = (first_byte & 0x80) != 0;
            let opcode = first_byte & 0x0F;
            let masked = (second_byte & 0x80) != 0;
            
            // 有效的WebSocket操作码
            if matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA) {
                confidence += 0.2;
                if positions.is_empty() {
                    positions.push(0);
                }
            }
        }
        
        if confidence > 0.5 {
            Ok(SimdDetectionResult {
                protocol: ProtocolType::WebSocket,
                confidence,
                match_positions: positions,
                instruction_set: self.instruction_set,
            })
        } else {
            Err(DetectorError::detection_failed("No WebSocket patterns found"))
        }
    }
    
    fn detect_tls(&self, data: &[u8]) -> Result<SimdDetectionResult> {
        if data.len() < 5 {
            return Err(DetectorError::detection_failed("Data too short for TLS"));
        }
        
        let content_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];
        
        // TLS内容类型
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
            let length = u16::from_be_bytes([data[3], data[4]]) as usize;
            
            // 检查长度是否合理
            if length > 0 && length <= 16384 && data.len() >= 5 + length {
                let confidence = match content_type {
                    0x16 => 0.95, // Handshake
                    0x17 => 0.9,  // Application Data
                    0x15 => 0.85, // Alert
                    0x14 => 0.8,  // Change Cipher Spec
                    _ => 0.7,
                };
                
                return Ok(SimdDetectionResult {
                    protocol: ProtocolType::TLS,
                    confidence,
                    match_positions: vec![0],
                    instruction_set: self.instruction_set,
                });
            }
        }
        
        Err(DetectorError::detection_failed("No TLS patterns found"))
    }
    
    fn detect_multiple(&self, data: &[u8], protocols: &[ProtocolType]) -> Result<Vec<SimdDetectionResult>> {
        let mut results = Vec::new();
        
        for &protocol in protocols {
            let result = match protocol {
                ProtocolType::HTTP2 => self.detect_http2(data),
                ProtocolType::QUIC => self.detect_quic(data),
                ProtocolType::GRPC => self.detect_grpc(data),
                ProtocolType::WebSocket => self.detect_websocket(data),
                ProtocolType::TLS => self.detect_tls(data),
                _ => continue,
            };
            
            if let Ok(detection) = result {
                results.push(detection);
            }
        }
        
        // 按置信度排序
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(results)
    }
    
    fn instruction_set(&self) -> SimdInstructionSet {
        self.instruction_set
    }
    
    fn supports_protocol(&self, protocol: ProtocolType) -> bool {
        matches!(
            protocol,
            ProtocolType::HTTP2
                | ProtocolType::QUIC
                | ProtocolType::GRPC
                | ProtocolType::WebSocket
                | ProtocolType::TLS
                | ProtocolType::UDP
        )
    }
}

/// 在数据中查找模式 - 优化版本
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    
    // 使用更高效的Boyer-Moore风格算法的简化版
    let needle_len = needle.len();
    let haystack_len = haystack.len();
    
    // 对于短模式，使用简单搜索
    if needle_len <= 4 {
        return haystack.windows(needle_len).position(|window| window == needle);
    }
    
    // 对于长模式，使用更高效的搜索
    let first_byte = needle[0];
    let last_byte = needle[needle_len - 1];
    
    let mut i = 0;
    while i <= haystack_len - needle_len {
        // 快速检查首尾字节
        if haystack[i] == first_byte && haystack[i + needle_len - 1] == last_byte {
            // 检查完整匹配
            if &haystack[i..i + needle_len] == needle {
                return Some(i);
            }
        }
        i += 1;
    }
    
    None
}

/// 不区分大小写的模式查找 - 优化版本
fn find_pattern_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    
    let needle_len = needle.len();
    let haystack_len = haystack.len();
    
    // 预计算needle的小写版本以避免重复转换
    let needle_lower: Vec<u8> = needle.iter().map(|&b| b.to_ascii_lowercase()).collect();
    let first_lower = needle_lower[0];
    let last_lower = needle_lower[needle_len - 1];
    
    let mut i = 0;
    while i <= haystack_len - needle_len {
        // 快速检查首尾字节（小写）
        let first_match = haystack[i].to_ascii_lowercase() == first_lower;
        let last_match = haystack[i + needle_len - 1].to_ascii_lowercase() == last_lower;
        
        if first_match && last_match {
            // 检查完整匹配
            let mut all_match = true;
            for j in 0..needle_len {
                if haystack[i + j].to_ascii_lowercase() != needle_lower[j] {
                    all_match = false;
                    break;
                }
            }
            if all_match {
                return Some(i);
            }
        }
        i += 1;
    }
    
    None
}