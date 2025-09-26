//! TLS ALPN (Application-Layer Protocol Negotiation) 检测模块
//!
//! 提供TLS握手消息中ALPN扩展的解析功能，用于识别HTTP/2 over TLS等协议

use crate::core::protocol::{ProtocolType, ProtocolInfo};
use crate::error::{DetectorError, Result};

/// TLS记录类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsRecordType {
    /// 改变密码规范
    ChangeCipherSpec = 0x14,
    /// 警报
    Alert = 0x15,
    /// 握手
    Handshake = 0x16,
    /// 应用数据
    ApplicationData = 0x17,
}

impl TlsRecordType {
    /// 从u8值创建TLS记录类型
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x14 => Some(TlsRecordType::ChangeCipherSpec),
            0x15 => Some(TlsRecordType::Alert),
            0x16 => Some(TlsRecordType::Handshake),
            0x17 => Some(TlsRecordType::ApplicationData),
            _ => None,
        }
    }
}

/// TLS握手类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsHandshakeType {
    /// Hello请求
    HelloRequest = 0x00,
    /// ClientHello
    ClientHello = 0x01,
    /// ServerHello
    ServerHello = 0x02,
    /// 证书
    Certificate = 0x0b,
    /// 服务器密钥交换
    ServerKeyExchange = 0x0c,
    /// 证书请求
    CertificateRequest = 0x0d,
    /// ServerHello完成
    ServerHelloDone = 0x0e,
    /// 证书验证
    CertificateVerify = 0x0f,
    /// 客户端密钥交换
    ClientKeyExchange = 0x10,
    /// 完成
    Finished = 0x14,
}

impl TlsHandshakeType {
    /// 从u8值创建TLS握手类型
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(TlsHandshakeType::HelloRequest),
            0x01 => Some(TlsHandshakeType::ClientHello),
            0x02 => Some(TlsHandshakeType::ServerHello),
            0x0b => Some(TlsHandshakeType::Certificate),
            0x0c => Some(TlsHandshakeType::ServerKeyExchange),
            0x0d => Some(TlsHandshakeType::CertificateRequest),
            0x0e => Some(TlsHandshakeType::ServerHelloDone),
            0x0f => Some(TlsHandshakeType::CertificateVerify),
            0x10 => Some(TlsHandshakeType::ClientKeyExchange),
            0x14 => Some(TlsHandshakeType::Finished),
            _ => None,
        }
    }
}

/// TLS扩展类型
#[derive(Debug, Clone, Copy)]
pub enum TlsExtensionType {
    /// 服务器名称
    ServerName = 0x0000,
    /// 最大片段长度
    MaxFragmentLength = 0x0001,
    /// 客户端证书URL
    ClientCertificateUrl = 0x0002,
    /// 可信CA密钥
    TrustedCaKeys = 0x0003,
    /// 截断HMAC
    TruncatedHmac = 0x0004,
    /// 状态请求
    StatusRequest = 0x0005,
    /// 应用层协议协商 (ALPN)
    ApplicationLayerProtocolNegotiation = 0x0010,
    /// 签名算法
    SignatureAlgorithms = 0x000d,
    /// 使用SRTP
    UseSrtp = 0x000e,
    /// 心跳
    Heartbeat = 0x000f,
    /// 填充
    Padding = 0x0015,
}

impl TlsExtensionType {
    /// 从u16值创建TLS扩展类型
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(TlsExtensionType::ServerName),
            0x0001 => Some(TlsExtensionType::MaxFragmentLength),
            0x0002 => Some(TlsExtensionType::ClientCertificateUrl),
            0x0003 => Some(TlsExtensionType::TrustedCaKeys),
            0x0004 => Some(TlsExtensionType::TruncatedHmac),
            0x0005 => Some(TlsExtensionType::StatusRequest),
            0x000d => Some(TlsExtensionType::SignatureAlgorithms),
            0x000e => Some(TlsExtensionType::UseSrtp),
            0x000f => Some(TlsExtensionType::Heartbeat),
            0x0010 => Some(TlsExtensionType::ApplicationLayerProtocolNegotiation),
            0x0015 => Some(TlsExtensionType::Padding),
            _ => None,
        }
    }
}

/// ALPN协议检测结果
#[derive(Debug, Clone)]
pub struct AlpnDetectionResult {
    /// 检测到的协议列表
    pub protocols: Vec<String>,
    /// 主要应用层协议
    pub primary_protocol: Option<ProtocolType>,
    /// 置信度
    pub confidence: f32,
}

/// TLS ALPN检测器
#[derive(Debug)]
pub struct TlsAlpnDetector {
    /// 最小检测数据长度
    min_data_size: usize,
    /// 启用的协议列表
    enabled_protocols: Vec<ProtocolType>,
}

impl TlsAlpnDetector {
    /// 创建新的TLS ALPN检测器
    pub fn new() -> Self {
        Self {
            min_data_size: 64, // TLS ClientHello最小长度
            enabled_protocols: vec![
                ProtocolType::HTTP2,
                ProtocolType::HTTP1_1,
                ProtocolType::HTTP3,
            ],
        }
    }

    /// 设置启用的协议
    pub fn with_enabled_protocols(mut self, protocols: Vec<ProtocolType>) -> Self {
        self.enabled_protocols = protocols;
        self
    }

    /// 检测TLS数据中的ALPN协议
    pub fn detect_alpn(&self, data: &[u8]) -> Option<AlpnDetectionResult> {
        if data.len() < self.min_data_size {
            return None;
        }

        // 检查是否为TLS记录
        if data.len() < 5 {
            return None;
        }

        let record_type = TlsRecordType::from_u8(data[0])?;
        if record_type != TlsRecordType::Handshake {
            return None;
        }

        // 解析TLS记录长度
        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
        
        // 如果数据不完整，尝试使用可用数据解析
        let available_data = if data.len() < 5 + record_length {
            &data[5..]
        } else {
            &data[5..5 + record_length]
        };
        
        if available_data.is_empty() {
            return None;
        }

        let handshake_type = TlsHandshakeType::from_u8(available_data[0])?;
        if handshake_type != TlsHandshakeType::ClientHello {
            return None;
        }

        // 解析ClientHello消息
        self.parse_client_hello_alpn(available_data)
    }

    /// 解析ClientHello消息中的ALPN扩展
    fn parse_client_hello_alpn(&self, handshake_data: &[u8]) -> Option<AlpnDetectionResult> {
        if handshake_data.len() < 12 {
            return None;
        }

        // 跳过握手类型(1) + 长度(3) + 版本(2) + 随机数(32)
        let mut pos = 1 + 3 + 2 + 32;
        if handshake_data.len() < pos {
            return None;
        }

        // 跳过会话ID
        let session_id_len = if handshake_data.len() > pos {
            handshake_data[pos] as usize
        } else {
            return None;
        };
        pos += 1 + session_id_len;
        if handshake_data.len() < pos {
            return None;
        }

        // 跳过密码套件
        if handshake_data.len() < pos + 2 {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([handshake_data[pos], handshake_data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if handshake_data.len() < pos {
            return None;
        }

        // 跳过压缩方法
        if handshake_data.len() < pos + 1 {
            return None;
        }
        let compression_methods_len = handshake_data[pos] as usize;
        pos += 1 + compression_methods_len;
        if handshake_data.len() < pos {
            return None;
        }

        // 解析扩展
        if handshake_data.len() < pos + 2 {
            return None;
        }
        let extensions_length = u16::from_be_bytes([handshake_data[pos], handshake_data[pos + 1]]) as usize;
        pos += 2;
        
        // 如果扩展数据不完整，使用可用的部分
        let available_extensions_length = if handshake_data.len() < pos + extensions_length {
            handshake_data.len() - pos
        } else {
            extensions_length
        };
        
        if available_extensions_length == 0 {
            return None;
        }

        let extensions_data = &handshake_data[pos..pos + available_extensions_length];
        self.parse_alpn_extensions(extensions_data)
    }

    /// 解析ALPN扩展
    fn parse_alpn_extensions(&self, extensions_data: &[u8]) -> Option<AlpnDetectionResult> {
        let mut pos = 0;
        let mut alpn_protocols = Vec::new();

        while pos + 4 <= extensions_data.len() {
            let extension_type = u16::from_be_bytes([extensions_data[pos], extensions_data[pos + 1]]);
            let extension_length = u16::from_be_bytes([extensions_data[pos + 2], extensions_data[pos + 3]]) as usize;
            pos += 4;

            if pos + extension_length > extensions_data.len() {
                break;
            }

            // 检查是否为ALPN扩展
            if extension_type == 0x0010 {
                let alpn_data = &extensions_data[pos..pos + extension_length];
                if let Some(protocols) = self.parse_alpn_list(alpn_data) {
                    alpn_protocols = protocols;
                    break;
                }
            }

            pos += extension_length;
        }

        if alpn_protocols.is_empty() {
            return None;
        }

        // 确定主要协议
        let primary_protocol = self.determine_primary_protocol(&alpn_protocols);
        let confidence = self.calculate_confidence(&alpn_protocols, primary_protocol);

        Some(AlpnDetectionResult {
            protocols: alpn_protocols,
            primary_protocol,
            confidence,
        })
    }

    /// 解析ALPN协议列表
    fn parse_alpn_list(&self, alpn_data: &[u8]) -> Option<Vec<String>> {
        if alpn_data.is_empty() {
            return None;
        }

        let mut pos = 0;
        let mut protocols = Vec::new();

        // ALPN列表长度
        if pos + 2 > alpn_data.len() {
            return None;
        }
        let alpn_list_length = u16::from_be_bytes([alpn_data[pos], alpn_data[pos + 1]]) as usize;
        pos += 2;

        if pos + alpn_list_length > alpn_data.len() {
            return None;
        }

        while pos + 1 <= alpn_data.len() {
            let protocol_name_len = alpn_data[pos] as usize;
            pos += 1;

            if pos + protocol_name_len > alpn_data.len() {
                break;
            }

            let protocol_name = String::from_utf8_lossy(&alpn_data[pos..pos + protocol_name_len]).to_string();
            protocols.push(protocol_name);
            pos += protocol_name_len;
        }

        if protocols.is_empty() {
            None
        } else {
            Some(protocols)
        }
    }

    /// 确定主要协议
    fn determine_primary_protocol(&self, protocols: &[String]) -> Option<ProtocolType> {
        for protocol in protocols {
            match protocol.as_str() {
                "h2" => return Some(ProtocolType::HTTP2),
                "h2-16" | "h2-14" => return Some(ProtocolType::HTTP2),
                "http/1.1" | "http/1.0" => return Some(ProtocolType::HTTP1_1),
                "h3" | "h3-29" | "h3-28" => return Some(ProtocolType::HTTP3),
                _ => {}
            }
        }
        None
    }

    /// 计算置信度
    fn calculate_confidence(&self, protocols: &[String], primary_protocol: Option<ProtocolType>) -> f32 {
        if primary_protocol.is_none() {
            return 0.5;
        }

        // 根据协议优先级计算置信度
        let mut confidence: f32 = 0.85; // 基础置信度

        // 如果有HTTP/2，提高置信度
        if protocols.iter().any(|p| p.starts_with("h2")) {
            confidence += 0.1;
        }

        // 如果有HTTP/3，提高置信度
        if protocols.iter().any(|p| p.starts_with("h3")) {
            confidence += 0.1;
        }

        confidence.min(0.95) // 最大置信度0.95
    }

    /// 创建协议信息
    pub fn create_protocol_info(&self, result: AlpnDetectionResult) -> Option<ProtocolInfo> {
        if let Some(primary_protocol) = result.primary_protocol {
            let mut info = ProtocolInfo::new(primary_protocol, result.confidence);
            info.add_metadata("alpn_protocols", &result.protocols.join(","));
            info.add_metadata("detection_method", "tls_alpn");
            Some(info)
        } else {
            // 如果没有确定的主要协议，返回TLS协议信息
            let mut info = ProtocolInfo::new(ProtocolType::TLS, 0.7);
            info.add_metadata("alpn_protocols", &result.protocols.join(","));
            info.add_metadata("detection_method", "tls_alpn");
            Some(info)
        }
    }
}

impl Default for TlsAlpnDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_detection() {
        let detector = TlsAlpnDetector::new();
        
        // 测试HTTP/2 ALPN数据
        let tls_h2_data = vec![
            // TLS记录头
            0x16, 0x03, 0x01, 0x00, 0x80,
            // ClientHello
            0x01, 0x00, 0x00, 0x7c,
            0x03, 0x03,
            // 随机数 (32字节)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x00, // 会话ID长度
            0x00, 0x02, // 密码套件长度
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x01, 0x00, // 压缩方法
            // 扩展
            0x00, 0x30, // 扩展总长度
            // ALPN扩展
            0x00, 0x10, // 扩展类型: ALPN
            0x00, 0x07, // 扩展长度
            0x00, 0x05, // ALPN列表长度
            0x02, 0x68, 0x32, // "h2"
            // 其他扩展
            0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03,
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        ];

        let result = detector.detect_alpn(&tls_h2_data);
        assert!(result.is_some());
        
        let detection = result.unwrap();
        assert!(detection.protocols.contains(&"h2".to_string()));
        assert_eq!(detection.primary_protocol, Some(ProtocolType::HTTP2));
        assert!(detection.confidence > 0.9);
    }

    #[test]
    fn test_no_alpn_extension() {
        let detector = TlsAlpnDetector::new();
        
        // 测试没有ALPN扩展的TLS数据
        let tls_no_alpn_data = vec![
            // TLS记录头
            0x16, 0x03, 0x01, 0x00, 0x40,
            // ClientHello
            0x01, 0x00, 0x00, 0x3c,
            0x03, 0x03,
            // 随机数 (32字节)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x00, // 会话ID长度
            0x00, 0x02, // 密码套件长度
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x01, 0x00, // 压缩方法
            // 扩展
            0x00, 0x06, // 扩展总长度
            // 非ALPN扩展
            0x00, 0x0d, 0x00, 0x02, 0x04, 0x03,
        ];

        let result = detector.detect_alpn(&tls_no_alpn_data);
        assert!(result.is_none());
    }
}