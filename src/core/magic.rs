//! 魔法包特征检测模块
//!
//! 基于协议的魔法字节（Magic Bytes）实现超高速启发式协议检测

use crate::core::protocol::{ProtocolType, ProtocolInfo};
use crate::core::tls_alpn::TlsAlpnDetector;
use crate::error::{DetectorError, Result};
use std::collections::HashMap;

/// 魔法包特征结构
#[derive(Debug, Clone)]
pub struct MagicSignature {
    /// 协议类型
    pub protocol: ProtocolType,
    /// 魔法字节序列
    pub magic_bytes: Vec<u8>,
    /// 字节偏移量（从哪个位置开始匹配）
    pub offset: usize,
    /// 匹配长度（可以小于magic_bytes长度）
    pub match_length: usize,
    /// 检测置信度
    pub confidence: f32,
    /// 特征描述
    pub description: String,
    /// 是否区分大小写
    pub case_sensitive: bool,
}

impl MagicSignature {
    /// 创建新的魔法包特征
    pub fn new(
        protocol: ProtocolType,
        magic_bytes: Vec<u8>,
        offset: usize,
        confidence: f32,
        description: String,
    ) -> Self {
        let match_length = magic_bytes.len();
        Self {
            protocol,
            magic_bytes,
            offset,
            match_length,
            confidence,
            description,
            case_sensitive: true,
        }
    }
    
    /// 创建不区分大小写的特征
    pub fn case_insensitive(mut self) -> Self {
        self.case_sensitive = false;
        self
    }
    
    /// 设置部分匹配长度
    pub fn with_match_length(mut self, length: usize) -> Self {
        self.match_length = length.min(self.magic_bytes.len());
        self
    }
    
    /// 检测数据是否匹配此特征
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.offset + self.match_length {
            return false;
        }
        
        let data_slice = &data[self.offset..self.offset + self.match_length];
        let magic_slice = &self.magic_bytes[..self.match_length];
        
        if self.case_sensitive {
            data_slice == magic_slice
        } else {
            data_slice.iter().zip(magic_slice.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
        }
    }
}

/// 魔法包检测器
#[derive(Debug)]
pub struct MagicDetector {
    /// 按第一字节索引的特征表（快速查找）
    byte_indexed_signatures: HashMap<u8, Vec<MagicSignature>>,
    /// 所有特征的列表（备用）
    all_signatures: Vec<MagicSignature>,
    /// 启用的协议过滤器
    enabled_protocols: Option<Vec<ProtocolType>>,
    /// TLS ALPN检测器
    tls_alpn_detector: TlsAlpnDetector,
}

impl MagicDetector {
    /// 创建新的魔法包检测器
    pub fn new() -> Self {
        let mut detector = Self {
            byte_indexed_signatures: HashMap::new(),
            all_signatures: Vec::new(),
            enabled_protocols: None,
            tls_alpn_detector: TlsAlpnDetector::new(),
        };
        
        // 预加载常见协议的魔法包特征
        detector.load_common_signatures();
        detector
    }
    
    /// 加载常见协议的魔法包特征
    fn load_common_signatures(&mut self) {
        let signatures = vec![
            // HTTP/1.x 方法
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"GET ".to_vec(),
                0,
                0.95,
                "HTTP GET request".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"POST ".to_vec(),
                0,
                0.95,
                "HTTP POST request".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"PUT ".to_vec(),
                0,
                0.95,
                "HTTP PUT request".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"HEAD ".to_vec(),
                0,
                0.95,
                "HTTP HEAD request".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"OPTIONS ".to_vec(),
                0,
                0.95,
                "HTTP OPTIONS request".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"DELETE ".to_vec(),
                0,
                0.95,
                "HTTP DELETE request".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::HTTP1_1,
                b"HTTP/1.".to_vec(),
                0,
                0.98,
                "HTTP response".to_string(),
            ),
            
            // HTTP/2 连接前言
            MagicSignature::new(
                ProtocolType::HTTP2,
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
                0,
                1.0,
                "HTTP/2 connection preface".to_string(),
            ),
            
            // TLS 握手
            MagicSignature::new(
                ProtocolType::TLS,
                vec![0x16, 0x03], // TLS Handshake + version
                0,
                0.9,
                "TLS handshake".to_string(),
            ).with_match_length(2),
            
            // QUIC 长头部
            MagicSignature::new(
                ProtocolType::QUIC,
                vec![0x80], // QUIC long header flag
                0,
                0.7,
                "QUIC long header".to_string(),
            ).with_match_length(1),
            
            // SSH
            MagicSignature::new(
                ProtocolType::SSH,
                b"SSH-".to_vec(),
                0,
                0.99,
                "SSH protocol".to_string(),
            ),
            
            // FTP
            MagicSignature::new(
                ProtocolType::FTP,
                b"220 ".to_vec(),
                0,
                0.85,
                "FTP welcome message".to_string(),
            ),
            
            // SMTP
            MagicSignature::new(
                ProtocolType::SMTP,
                b"220 ".to_vec(),
                0,
                0.8,
                "SMTP welcome".to_string(),
            ),
            
            // WebSocket升级
            MagicSignature::new(
                ProtocolType::WebSocket,
                b"GET ".to_vec(),
                0,
                0.3, // 低置信度，需要进一步检查
                "Potential WebSocket upgrade".to_string(),
            ),
            
            // gRPC (基于HTTP/2)
            MagicSignature::new(
                ProtocolType::GRPC,
                b"application/grpc".to_vec(),
                0,
                0.95,
                "gRPC content type".to_string(),
            ),
            
            // DNS
            MagicSignature::new(
                ProtocolType::DNS,
                vec![0x00, 0x00, 0x01, 0x00], // DNS query flags
                2,
                0.8,
                "DNS query".to_string(),
            ).with_match_length(4),
            
            // MQTT
            MagicSignature::new(
                ProtocolType::MQTT,
                vec![0x10], // MQTT CONNECT packet
                0,
                0.7,
                "MQTT CONNECT".to_string(),
            ).with_match_length(1),
            
            // Redis
            MagicSignature::new(
                ProtocolType::Redis,
                b"*".to_vec(),
                0,
                0.6,
                "Redis bulk array".to_string(),
            ),
            MagicSignature::new(
                ProtocolType::Redis,
                b"+OK\r\n".to_vec(),
                0,
                0.9,
                "Redis OK response".to_string(),
            ),
            
            // MySQL
            MagicSignature::new(
                ProtocolType::MySQL,
                vec![0x0a], // MySQL protocol version 10
                4,
                0.8,
                "MySQL handshake".to_string(),
            ).with_match_length(1),
        ];
        
        for signature in signatures {
            self.add_signature(signature);
        }
    }
    
    /// 添加自定义魔法包特征
    pub fn add_signature(&mut self, signature: MagicSignature) {
        // 按第一字节建立索引以提升查找速度
        if !signature.magic_bytes.is_empty() {
            let first_byte = if signature.case_sensitive {
                signature.magic_bytes[0]
            } else {
                signature.magic_bytes[0].to_ascii_lowercase()
            };
            
            self.byte_indexed_signatures
                .entry(first_byte)
                .or_insert_with(Vec::new)
                .push(signature.clone());
                
            // 如果不区分大小写，也为大写版本建立索引
            if !signature.case_sensitive {
                let upper_byte = signature.magic_bytes[0].to_ascii_uppercase();
                if upper_byte != first_byte {
                    self.byte_indexed_signatures
                        .entry(upper_byte)
                        .or_insert_with(Vec::new)
                        .push(signature.clone());
                }
            }
        }
        
        self.all_signatures.push(signature);
    }
    
    /// 设置启用的协议过滤器
    pub fn with_enabled_protocols(mut self, protocols: Vec<ProtocolType>) -> Self {
        self.enabled_protocols = Some(protocols);
        self
    }
    
    /// 超快速魔法包检测（前几个字节启发式判断）
    pub fn quick_detect(&self, data: &[u8]) -> Option<ProtocolInfo> {
        if data.is_empty() {
            return None;
        }
        
        let first_byte = data[0];
        
        // 1. 查找按第一字节索引的特征
        if let Some(signatures) = self.byte_indexed_signatures.get(&first_byte) {
            for signature in signatures {
                // 检查协议过滤器
                if let Some(ref enabled) = self.enabled_protocols {
                    if !enabled.contains(&signature.protocol) {
                        continue;
                    }
                }
                
                if signature.matches(data) {
                    // 如果检测到TLS，尝试ALPN检测
                    if signature.protocol == ProtocolType::TLS {
                        if let Some(alpn_result) = self.tls_alpn_detector.detect_alpn(data) {
                            if let Some(alpn_info) = self.tls_alpn_detector.create_protocol_info(alpn_result) {
                                // 检查ALPN检测到的协议是否在启用列表中
                                if let Some(ref enabled) = self.enabled_protocols {
                                    if enabled.contains(&alpn_info.protocol_type) {
                                        return Some(alpn_info);
                                    }
                                } else {
                                    return Some(alpn_info);
                                }
                            }
                        }
                    }
                    
                    let mut info = ProtocolInfo::new(signature.protocol, signature.confidence);
                    info.add_metadata("detection_method", "magic_bytes");
                    info.add_metadata("signature_desc", &signature.description);
                    return Some(info);
                }
            }
        }
        
        // 2. 特殊的启发式检测（基于第一字节）
        self.heuristic_by_first_byte(data, first_byte)
    }
    
    /// 基于第一字节的启发式检测
    fn heuristic_by_first_byte(&self, data: &[u8], first_byte: u8) -> Option<ProtocolInfo> {
        let confidence = match first_byte {
            // TLS 内容类型
            0x14 | 0x15 | 0x16 | 0x17 => {
                if data.len() >= 3 && data[1] == 0x03 {
                    Some((ProtocolType::TLS, 0.85, "TLS record"))
                } else {
                    None
                }
            },
            
            // QUIC 包类型
            0x80..=0xFF => {
                if data.len() >= 5 {
                    Some((ProtocolType::QUIC, 0.6, "QUIC long header"))
                } else {
                    None
                }
            },
            
            // HTTP方法首字符
            b'G' | b'P' | b'H' | b'O' | b'D' => {
                if data.len() >= 4 {
                    Some((ProtocolType::HTTP1_1, 0.4, "HTTP method"))
                } else {
                    None
                }
            },
            
            // DNS 可能的长度字段
            0x00 => {
                if data.len() >= 12 {
                    Some((ProtocolType::DNS, 0.3, "DNS length prefix"))
                } else {
                    None
                }
            },
            
            _ => None,
        };
        
        confidence.and_then(|(protocol, conf, desc)| {
            // 🎯 检查协议过滤器
            if let Some(ref enabled) = self.enabled_protocols {
                if !enabled.contains(&protocol) {
                    return None;
                }
            }
            
            let mut info = ProtocolInfo::new(protocol, conf);
            info.add_metadata("detection_method", "heuristic");
            info.add_metadata("heuristic_desc", desc);
            Some(info)
        })
    }
    
    /// 深度魔法包检测（检查所有已知特征）
    pub fn deep_detect(&self, data: &[u8]) -> Vec<ProtocolInfo> {
        let mut results = Vec::new();
        
        for signature in &self.all_signatures {
            // 检查协议过滤器
            if let Some(ref enabled) = self.enabled_protocols {
                if !enabled.contains(&signature.protocol) {
                    continue;
                }
            }
            
            if signature.matches(data) {
                let mut info = ProtocolInfo::new(signature.protocol, signature.confidence);
                info.add_metadata("detection_method", "magic_bytes");
                info.add_metadata("signature_desc", &signature.description);
                info.add_metadata("match_offset", &signature.offset.to_string());
                results.push(info);
            }
        }
        
        // 按置信度排序
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        results
    }
    
    /// 获取所有支持的协议
    pub fn supported_protocols(&self) -> Vec<ProtocolType> {
        self.all_signatures.iter()
            .map(|sig| sig.protocol)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
    
    /// 获取特定协议的所有特征
    pub fn get_signatures_for_protocol(&self, protocol: ProtocolType) -> Vec<&MagicSignature> {
        self.all_signatures.iter()
            .filter(|sig| sig.protocol == protocol)
            .collect()
    }
}

impl Default for MagicDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// 自定义协议特征构建器
pub struct CustomSignatureBuilder {
    protocol: ProtocolType,
    magic_bytes: Vec<u8>,
    offset: usize,
    confidence: f32,
    description: String,
    case_sensitive: bool,
    match_length: Option<usize>,
}

impl CustomSignatureBuilder {
    /// 创建新的自定义特征构建器
    pub fn new(protocol: ProtocolType, description: &str) -> Self {
        Self {
            protocol,
            magic_bytes: Vec::new(),
            offset: 0,
            confidence: 0.8,
            description: description.to_string(),
            case_sensitive: true,
            match_length: None,
        }
    }
    
    /// 设置魔法字节（字符串）
    pub fn with_magic_string(mut self, magic: &str) -> Self {
        self.magic_bytes = magic.as_bytes().to_vec();
        self
    }
    
    /// 设置魔法字节（字节数组）
    pub fn with_magic_bytes(mut self, magic: Vec<u8>) -> Self {
        self.magic_bytes = magic;
        self
    }
    
    /// 设置偏移量
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }
    
    /// 设置置信度
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    /// 设置为不区分大小写
    pub fn case_insensitive(mut self) -> Self {
        self.case_sensitive = false;
        self
    }
    
    /// 设置匹配长度
    pub fn with_match_length(mut self, length: usize) -> Self {
        self.match_length = Some(length);
        self
    }
    
    /// 构建魔法包特征
    pub fn build(self) -> MagicSignature {
        let mut signature = MagicSignature::new(
            self.protocol,
            self.magic_bytes,
            self.offset,
            self.confidence,
            self.description,
        );
        
        signature.case_sensitive = self.case_sensitive;
        
        if let Some(length) = self.match_length {
            signature.match_length = length.min(signature.magic_bytes.len());
        }
        
        signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_http_magic_detection() {
        let detector = MagicDetector::new();
        
        // 测试 HTTP GET
        let http_get = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = detector.quick_detect(http_get).unwrap();
        assert_eq!(result.protocol_type, ProtocolType::HTTP1_1);
        assert!(result.confidence > 0.9);
        
        // 测试 HTTP/2 前言
        let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let result = detector.quick_detect(http2_preface).unwrap();
        assert_eq!(result.protocol_type, ProtocolType::HTTP2);
        assert_eq!(result.confidence, 1.0);
    }
    
    #[test]
    fn test_tls_magic_detection() {
        let detector = MagicDetector::new();
        
        // 测试 TLS 握手
        let tls_handshake = &[0x16, 0x03, 0x01, 0x00, 0x2f];
        let result = detector.quick_detect(tls_handshake).unwrap();
        assert_eq!(result.protocol_type, ProtocolType::TLS);
        assert!(result.confidence > 0.8);
    }
    
    #[test]
    fn test_custom_signature() {
        let mut detector = MagicDetector::new();
        
        // 添加自定义协议特征
        let custom_sig = CustomSignatureBuilder::new(ProtocolType::Custom, "My Protocol")
            .with_magic_string("MYPROT")
            .with_confidence(0.95)
            .build();
        
        detector.add_signature(custom_sig);
        
        let test_data = b"MYPROT version 1.0";
        let result = detector.quick_detect(test_data).unwrap();
        assert_eq!(result.protocol_type, ProtocolType::Custom);
        assert_eq!(result.confidence, 0.95);
    }
}