//! AArch64 SIMD优化实现
//!
//! 利用NEON指令集加速协议探测。

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;
use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};
use crate::simd::{SimdDetectionResult, SimdDetector, SimdInstructionSet};
use std::time::Instant;

/// AArch64 SIMD探测器
pub struct AArch64SimdDetector {
    instruction_set: SimdInstructionSet,
    has_neon: bool,
}

impl AArch64SimdDetector {
    /// 创建新的AArch64 SIMD探测器
    pub fn new() -> Self {
        let has_neon = detect_neon_support();
        
        let instruction_set = if has_neon {
            SimdInstructionSet::NEON
        } else {
            SimdInstructionSet::None
        };
        
        Self {
            instruction_set,
            has_neon,
        }
    }
    
    /// 使用NEON进行快速模式匹配
    #[cfg(target_arch = "aarch64")]
    unsafe fn neon_pattern_match(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if !self.has_neon || needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        
        if needle.len() == 1 {
            return self.neon_find_byte(haystack, needle[0]);
        }
        
        // 对于较长的模式，使用滑动窗口
        let first_byte = needle[0];
        let mut pos = 0;
        
        while pos <= haystack.len() - needle.len() {
            if let Some(candidate) = self.neon_find_byte(&haystack[pos..], first_byte) {
                let actual_pos = pos + candidate;
                if actual_pos + needle.len() <= haystack.len() {
                    if haystack[actual_pos..actual_pos + needle.len()] == *needle {
                        return Some(actual_pos);
                    }
                }
                pos = actual_pos + 1;
            } else {
                break;
            }
        }
        
        None
    }
    
    /// 使用NEON查找单个字节
    #[cfg(target_arch = "aarch64")]
    unsafe fn neon_find_byte(&self, data: &[u8], byte: u8) -> Option<usize> {
        if !self.has_neon || data.is_empty() {
            return None;
        }
        
        let needle = vdupq_n_u8(byte);
        let mut pos = 0;
        
        // 处理16字节对齐的块
        while pos + 16 <= data.len() {
            let chunk = vld1q_u8(data.as_ptr().add(pos));
            let cmp = vceqq_u8(chunk, needle);
            
            // 检查是否有匹配
            let mask = vget_lane_u64(vreinterpret_u64_u8(vorr_u8(
                vget_low_u8(cmp),
                vget_high_u8(cmp)
            )), 0);
            
            if mask != 0 {
                // 找到匹配，需要确定具体位置
                for i in 0..16 {
                    if pos + i < data.len() && data[pos + i] == byte {
                        return Some(pos + i);
                    }
                }
            }
            
            pos += 16;
        }
        
        // 处理剩余字节
        for i in pos..data.len() {
            if data[i] == byte {
                return Some(i);
            }
        }
        
        None
    }
    
    /// 快速模式匹配（根据可用指令集选择最佳实现）
    fn fast_pattern_match(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            if self.has_neon {
                return self.neon_pattern_match(haystack, needle);
            }
        }
        
        // 回退到标准实现
        self.fallback_pattern_match(haystack, needle)
    }
    
    /// 回退模式匹配实现
    fn fallback_pattern_match(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        
        for i in 0..=haystack.len() - needle.len() {
            if haystack[i..i + needle.len()] == *needle {
                return Some(i);
            }
        }
        
        None
    }
    
    /// 使用NEON进行字节计数
    #[cfg(target_arch = "aarch64")]
    unsafe fn neon_count_bytes(&self, data: &[u8], byte: u8) -> usize {
        if !self.has_neon || data.is_empty() {
            return data.iter().filter(|&&b| b == byte).count();
        }
        
        let needle = vdupq_n_u8(byte);
        let mut count = 0;
        let mut pos = 0;
        
        // 处理16字节对齐的块
        while pos + 16 <= data.len() {
            let chunk = vld1q_u8(data.as_ptr().add(pos));
            let cmp = vceqq_u8(chunk, needle);
            
            // 计算匹配的字节数
            // 使用更高效的方法来计算匹配数
            let mask = vget_lane_u64(vreinterpret_u64_u8(vorr_u8(
                vget_low_u8(cmp),
                vget_high_u8(cmp)
            )), 0);
            
            if mask != 0 {
                // 逐字节检查匹配
                for i in 0..16 {
                    if pos + i < data.len() && data[pos + i] == byte {
                        count += 1;
                    }
                }
            }
            
            pos += 16;
        }
        
        // 处理剩余字节
        for i in pos..data.len() {
            if data[i] == byte {
                count += 1;
            }
        }
        
        count
    }
}

impl SimdDetector for AArch64SimdDetector {
    fn detect_http2(&self, data: &[u8]) -> Result<SimdDetectionResult> {
        let start = Instant::now();
        
        // HTTP/2 连接前言
        let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        
        if let Some(_) = self.fast_pattern_match(data, http2_preface) {
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::HTTP2,
                confidence: 1.0,
                match_positions: vec![0],
                instruction_set: self.instruction_set,
            });
        }
        
        // 检查HTTP/2帧头
        if data.len() >= 9 {
            let frame_type = data[3];
            
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
            if data.len() >= 5 {
                let version = u32::from_be_bytes([
                    data[1], data[2], data[3], data[4]
                ]);
                
                if version == 0x00000001 {
                    return Ok(SimdDetectionResult {
                        protocol: ProtocolType::QUIC,
                        confidence: 0.95,
                        match_positions: vec![0],
                        instruction_set: self.instruction_set,
                    });
                }
                
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
        let grpc_content_type = b"application/grpc";
        
        if let Some(pos) = self.fast_pattern_match(data, grpc_content_type) {
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::GRPC,
                confidence: 0.9,
                match_positions: vec![pos],
                instruction_set: self.instruction_set,
            });
        }
        
        let grpc_web = b"application/grpc-web";
        if let Some(pos) = self.fast_pattern_match(data, grpc_web) {
            return Ok(SimdDetectionResult {
                protocol: ProtocolType::GRPC,
                confidence: 0.85,
                match_positions: vec![pos],
                instruction_set: self.instruction_set,
            });
        }
        
        // 检查gRPC帧格式
        if data.len() >= 5 {
            let compression_flag = data[0];
            if compression_flag <= 1 {
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
        
        // 使用NEON加速的模式匹配
        let upgrade_header = b"Upgrade: websocket";
        if let Some(pos) = self.fast_pattern_match(data, upgrade_header) {
            positions.push(pos);
            confidence += 0.4;
        }
        
        let connection_header = b"Connection: Upgrade";
        if let Some(pos) = self.fast_pattern_match(data, connection_header) {
            positions.push(pos);
            confidence += 0.3;
        }
        
        let websocket_key = b"Sec-WebSocket-Key:";
        if let Some(pos) = self.fast_pattern_match(data, websocket_key) {
            positions.push(pos);
            confidence += 0.3;
        }
        
        // WebSocket帧格式检查
        if data.len() >= 2 {
            let first_byte = data[0];
            let opcode = first_byte & 0x0F;
            
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
        
        let valid_content_type = matches!(content_type, 0x14 | 0x15 | 0x16 | 0x17);
        let valid_version = matches!((version_major, version_minor), 
            (0x03, 0x00) | (0x03, 0x01) | (0x03, 0x02) | (0x03, 0x03) | (0x03, 0x04));
        
        if valid_content_type && valid_version {
            let length = u16::from_be_bytes([data[3], data[4]]) as usize;
            
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
        )
    }
}

/// 检测NEON支持
fn detect_neon_support() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        // 在AArch64上，NEON是标准特性
        true
    }
    
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}



/// NeonDetector类型别名，用于向后兼容
pub type NeonDetector = AArch64SimdDetector;