//! WebSocket协议升级器
//!
//! 处理HTTP到WebSocket的升级过程，支持多种HTTP版本和灵活配置。

use crate::core::protocol::{ProtocolType, UpgradePath, UpgradeMethod};
use crate::error::{DetectorError, Result};
use crate::upgrade::{ProtocolUpgrader, UpgradeResult};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// WebSocket升级配置
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// 默认主机名
    pub default_host: String,
    /// 默认路径
    pub default_path: String,
    /// 支持的WebSocket版本
    pub supported_versions: Vec<String>,
    /// 支持的子协议
    pub supported_protocols: Vec<String>,
    /// 支持的扩展
    pub supported_extensions: Vec<String>,
    /// 是否启用随机密钥生成
    pub use_random_key: bool,
    /// 自定义头部
    pub custom_headers: HashMap<String, String>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            default_host: "localhost".to_string(),
            default_path: "/".to_string(),
            supported_versions: vec!["13".to_string()],
            supported_protocols: vec![],
            supported_extensions: vec![],
            use_random_key: true,
            custom_headers: HashMap::new(),
        }
    }
}

/// WebSocket升级器
#[derive(Debug)]
pub struct WebSocketUpgrader {
    name: &'static str,
    config: WebSocketConfig,
}

impl WebSocketUpgrader {
    /// 创建新的WebSocket升级器
    pub fn new() -> Self {
        Self {
            name: "WebSocketUpgrader",
            config: WebSocketConfig::default(),
        }
    }
    
    /// 使用自定义配置创建WebSocket升级器
    pub fn with_config(config: WebSocketConfig) -> Self {
        Self {
            name: "WebSocketUpgrader",
            config,
        }
    }
    
    /// 获取配置的可变引用
    pub fn config_mut(&mut self) -> &mut WebSocketConfig {
        &mut self.config
    }
    
    /// 获取配置的引用
    pub fn config(&self) -> &WebSocketConfig {
        &self.config
    }
    
    /// 生成WebSocket密钥
    fn generate_websocket_key(&self) -> String {
        if self.config.use_random_key {
            // 生成16字节随机数据并进行Base64编码
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            std::time::SystemTime::now().hash(&mut hasher);
            let random_data = hasher.finish();
            
            // 简化的Base64编码（实际应用中应使用proper Base64库）
            format!("{}==", random_data)
        } else {
            // 使用固定密钥用于测试
            "dGhlIHNhbXBsZSBub25jZQ==".to_string()
        }
    }
    
    /// 计算WebSocket接受密钥
    fn calculate_accept_key(&self, key: &str) -> String {
        // WebSocket协议规定的魔法字符串
        let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{}{}", key, magic_string);
        
        // 在实际实现中，这里应该使用SHA-1哈希和Base64编码
        // 这里使用简化的实现
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        combined.hash(&mut hasher);
        let hash = hasher.finish();
        
        // 简化的Base64编码模拟
        format!("{}==", hash)
    }
    
    /// 创建WebSocket升级请求
    fn create_websocket_upgrade_request(&self, host: Option<&str>, path: Option<&str>, http_version: &str) -> Vec<u8> {
        let key = self.generate_websocket_key();
        let host = host.unwrap_or(&self.config.default_host);
        let path = path.unwrap_or(&self.config.default_path);
        let default_version = "13".to_string();
        let version = self.config.supported_versions.first().unwrap_or(&default_version);
        
        let mut request = format!(
            "GET {} {}\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: {}\r\n",
            path, http_version, host, key, version
        );
        
        // 添加子协议支持
        if !self.config.supported_protocols.is_empty() {
            request.push_str(&format!(
                "Sec-WebSocket-Protocol: {}\r\n",
                self.config.supported_protocols.join(", ")
            ));
        }
        
        // 添加扩展支持
        if !self.config.supported_extensions.is_empty() {
            request.push_str(&format!(
                "Sec-WebSocket-Extensions: {}\r\n",
                self.config.supported_extensions.join(", ")
            ));
        }
        
        // 添加自定义头部
        for (key, value) in &self.config.custom_headers {
            request.push_str(&format!("{}:{}\r\n", key, value));
        }
        
        request.push_str("\r\n");
        
        request.into_bytes()
    }
    
    /// 创建WebSocket升级响应
    fn create_websocket_upgrade_response(&self, key: &str) -> Vec<u8> {
        let accept_key = self.calculate_accept_key(key);
        
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            accept_key
        );
        
        response.into_bytes()
    }
    
    /// 解析HTTP请求中的WebSocket密钥
    fn extract_websocket_key(&self, data: &[u8]) -> Option<String> {
        let data_str = String::from_utf8_lossy(data);
        
        for line in data_str.lines() {
            if line.to_lowercase().starts_with("sec-websocket-key:") {
                if let Some(key) = line.split(':').nth(1) {
                    return Some(key.trim().to_string());
                }
            }
        }
        
        None
    }
    
    /// 验证WebSocket升级请求
    fn validate_websocket_request(&self, data: &[u8]) -> Result<()> {
        let data_str = String::from_utf8_lossy(data).to_lowercase();
        
        // 检查必需的头部
        if !data_str.contains("upgrade: websocket") {
            return Err(DetectorError::upgrade_failed(
                "HTTP".to_string(),
                "WebSocket".to_string(),
                "Missing 'Upgrade: websocket' header".to_string()
            ));
        }
        
        if !data_str.contains("connection: upgrade") {
            return Err(DetectorError::upgrade_failed(
                "HTTP".to_string(),
                "WebSocket".to_string(),
                "Missing 'Connection: Upgrade' header".to_string()
            ));
        }
        
        if !data_str.contains("sec-websocket-key:") {
            return Err(DetectorError::upgrade_failed(
                "HTTP".to_string(),
                "WebSocket".to_string(),
                "Missing 'Sec-WebSocket-Key' header".to_string()
            ));
        }
        
        if !data_str.contains("sec-websocket-version:") {
            return Err(DetectorError::upgrade_failed(
                "HTTP".to_string(),
                "WebSocket".to_string(),
                "Missing 'Sec-WebSocket-Version' header".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// 检查是否是WebSocket升级请求
    fn is_websocket_upgrade_request(&self, data: &[u8]) -> bool {
        let data_str = String::from_utf8_lossy(data).to_lowercase();
        
        data_str.contains("upgrade: websocket") &&
        data_str.contains("connection: upgrade") &&
        data_str.contains("sec-websocket-key:")
    }
    
    /// 检查是否是WebSocket升级响应
    fn is_websocket_upgrade_response(&self, data: &[u8]) -> bool {
        let data_str = String::from_utf8_lossy(data).to_lowercase();
        
        data_str.contains("101 switching protocols") &&
        data_str.contains("upgrade: websocket") &&
        data_str.contains("sec-websocket-accept:")
    }
    
    /// 创建WebSocket帧
    fn create_websocket_frame(&self, payload: &[u8], opcode: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        
        // 第一个字节：FIN=1, RSV=000, Opcode
        frame.push(0x80 | (opcode & 0x0F));
        
        // 第二个字节：MASK=0, Payload length
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else if payload.len() < 65536 {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        
        // 添加载荷
        frame.extend_from_slice(payload);
        
        frame
    }
    
    /// 解析WebSocket帧
    fn parse_websocket_frame(&self, data: &[u8]) -> Result<(u8, Vec<u8>)> {
        if data.len() < 2 {
            return Err(DetectorError::upgrade_failed(
                "WebSocket".to_string(),
                "WebSocket".to_string(),
                "WebSocket frame too short".to_string()
            ));
        }
        
        let first_byte = data[0];
        let second_byte = data[1];
        
        let opcode = first_byte & 0x0F;
        let masked = (second_byte & 0x80) != 0;
        let mut payload_len = (second_byte & 0x7F) as usize;
        let mut offset = 2;
        
        // 扩展载荷长度
        if payload_len == 126 {
            if data.len() < 4 {
                return Err(DetectorError::upgrade_failed(
                    "WebSocket".to_string(),
                    "WebSocket".to_string(),
                    "WebSocket frame header incomplete".to_string()
                ));
            }
            payload_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            offset = 4;
        } else if payload_len == 127 {
            if data.len() < 10 {
                return Err(DetectorError::upgrade_failed(
                    "WebSocket".to_string(),
                    "WebSocket".to_string(),
                    "WebSocket frame header incomplete".to_string()
                ));
            }
            payload_len = u64::from_be_bytes([
                data[2], data[3], data[4], data[5],
                data[6], data[7], data[8], data[9],
            ]) as usize;
            offset = 10;
        }
        
        // 掩码
        if masked {
            if data.len() < offset + 4 {
                return Err(DetectorError::upgrade_failed(
                    "WebSocket".to_string(),
                    "WebSocket".to_string(),
                    "WebSocket frame mask incomplete".to_string()
                ));
            }
            offset += 4; // 跳过掩码
        }
        
        // 提取载荷
        if data.len() < offset + payload_len {
            return Err(DetectorError::upgrade_failed(
                "WebSocket".to_string(),
                "WebSocket".to_string(),
                "WebSocket frame payload incomplete".to_string()
            ));
        }
        
        let payload = data[offset..offset + payload_len].to_vec();
        
        Ok((opcode, payload))
    }
}

impl Default for WebSocketUpgrader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_websocket_config_default() {
        let config = WebSocketConfig::default();
        assert_eq!(config.default_host, "localhost");
        assert_eq!(config.default_path, "/");
        assert_eq!(config.supported_versions, vec!["13"]);
        assert!(config.use_random_key);
    }
    
    #[test]
    fn test_websocket_upgrader_supports_all_http_versions() {
        let upgrader = WebSocketUpgrader::new();
        
        assert!(upgrader.can_upgrade(ProtocolType::HTTP1_0, ProtocolType::WebSocket));
        assert!(upgrader.can_upgrade(ProtocolType::HTTP1_1, ProtocolType::WebSocket));
        assert!(upgrader.can_upgrade(ProtocolType::HTTP2, ProtocolType::WebSocket));
        assert!(upgrader.can_upgrade(ProtocolType::HTTP3, ProtocolType::WebSocket));
        assert!(!upgrader.can_upgrade(ProtocolType::TCP, ProtocolType::WebSocket));
    }
    
    #[test]
    fn test_websocket_upgrader_with_custom_config() {
        let mut config = WebSocketConfig::default();
        config.default_host = "example.com".to_string();
        config.supported_protocols = vec!["chat".to_string(), "echo".to_string()];
        config.use_random_key = false;
        
        let upgrader = WebSocketUpgrader::with_config(config);
        assert_eq!(upgrader.config().default_host, "example.com");
        assert_eq!(upgrader.config().supported_protocols, vec!["chat", "echo"]);
        assert!(!upgrader.config().use_random_key);
    }
    
    #[test]
    fn test_supported_upgrades_includes_all_http_versions() {
        let upgrader = WebSocketUpgrader::new();
        let upgrades = upgrader.supported_upgrades();
        
        assert_eq!(upgrades.len(), 4);
        
        let from_protocols: Vec<_> = upgrades.iter().map(|u| u.from).collect();
        assert!(from_protocols.contains(&ProtocolType::HTTP1_0));
        assert!(from_protocols.contains(&ProtocolType::HTTP1_1));
        assert!(from_protocols.contains(&ProtocolType::HTTP2));
        assert!(from_protocols.contains(&ProtocolType::HTTP3));
    }
}

impl ProtocolUpgrader for WebSocketUpgrader {
    fn can_upgrade(&self, from: ProtocolType, to: ProtocolType) -> bool {
        match (from, to) {
            // 支持所有HTTP版本到WebSocket的升级
            (ProtocolType::HTTP1_0, ProtocolType::WebSocket) => true,
            (ProtocolType::HTTP1_1, ProtocolType::WebSocket) => true,
            (ProtocolType::HTTP2, ProtocolType::WebSocket) => true,
            (ProtocolType::HTTP3, ProtocolType::WebSocket) => true,
            _ => false,
        }
    }
    
    fn upgrade(&self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<UpgradeResult> {
        let start = Instant::now();
        
        // 检查前置条件
        self.check_prerequisites(from, to, data)?;
        
        if to != ProtocolType::WebSocket {
            return Ok(UpgradeResult::failure(
                to,
                UpgradeMethod::Negotiation,
                start.elapsed(),
                "WebSocketUpgrader only supports upgrading to WebSocket".to_string(),
            ));
        }
        
        let upgraded_data = if self.is_websocket_upgrade_request(data) {
            // 这是一个WebSocket升级请求，创建响应
            if let Some(key) = self.extract_websocket_key(data) {
                self.create_websocket_upgrade_response(&key)
            } else {
                return Ok(UpgradeResult::failure(
                    to,
                    UpgradeMethod::Negotiation,
                    start.elapsed(),
                    "Cannot extract WebSocket key from request".to_string(),
                ));
            }
        } else if self.is_websocket_upgrade_response(data) {
            // 这已经是一个WebSocket升级响应，创建一个简单的WebSocket帧
            let hello_message = b"Hello WebSocket!";
            self.create_websocket_frame(hello_message, 0x1) // 文本帧
        } else {
            // 这是一个普通的HTTP请求，创建WebSocket升级请求
            self.validate_websocket_request(data).unwrap_or_else(|_| {
                // 如果验证失败，创建一个新的升级请求
            });
            
            // 从HTTP请求中提取Host和路径
            let data_str = String::from_utf8_lossy(data);
            let mut host: Option<&str> = None;
            let mut path: Option<&str> = None;
            
            for line in data_str.lines() {
                if line.to_lowercase().starts_with("host:") {
                    if let Some(h) = line.split(':').nth(1) {
                        host = Some(h.trim());
                    }
                }
                if line.starts_with("GET ") {
                    if let Some(p) = line.split_whitespace().nth(1) {
                        path = Some(p);
                    }
                }
            }
            
            // 根据源协议类型确定HTTP版本
            let http_version = match from {
                ProtocolType::HTTP1_0 => "HTTP/1.0",
                ProtocolType::HTTP1_1 => "HTTP/1.1",
                ProtocolType::HTTP2 => "HTTP/2",
                ProtocolType::HTTP3 => "HTTP/3",
                _ => "HTTP/1.1", // 默认值
            };
            
            self.create_websocket_upgrade_request(host, path, http_version)
        };
        
        let duration = start.elapsed();
        
        let mut result = UpgradeResult::success(
            to,
            upgraded_data,
            UpgradeMethod::Negotiation,
            duration,
        );
        
        // 添加元数据
        result = result.with_metadata(
            "original_protocol".to_string(),
            format!("{:?}", from),
        );
        result = result.with_metadata(
            "websocket_version".to_string(),
            "13".to_string(),
        );
        
        Ok(result)
    }
    
    fn supported_upgrades(&self) -> Vec<UpgradePath> {
        let mut required_headers = vec![
            "Upgrade".to_string(),
            "Connection".to_string(),
            "Sec-WebSocket-Key".to_string(),
            "Sec-WebSocket-Version".to_string(),
        ];
        
        let mut optional_headers = vec![
            "Sec-WebSocket-Protocol".to_string(),
            "Sec-WebSocket-Extensions".to_string(),
        ];
        
        // 添加自定义头部到可选头部列表
        for key in self.config.custom_headers.keys() {
            optional_headers.push(key.clone());
        }
        
        // 支持所有HTTP版本到WebSocket的升级路径
        vec![
            UpgradePath {
                from: ProtocolType::HTTP1_0,
                to: ProtocolType::WebSocket,
                method: UpgradeMethod::Negotiation,
                required_headers: required_headers.clone(),
                optional_headers: optional_headers.clone(),
            },
            UpgradePath {
                from: ProtocolType::HTTP1_1,
                to: ProtocolType::WebSocket,
                method: UpgradeMethod::Negotiation,
                required_headers: required_headers.clone(),
                optional_headers: optional_headers.clone(),
            },
            UpgradePath {
                from: ProtocolType::HTTP2,
                to: ProtocolType::WebSocket,
                method: UpgradeMethod::Negotiation,
                required_headers: required_headers.clone(),
                optional_headers: optional_headers.clone(),
            },
            UpgradePath {
                from: ProtocolType::HTTP3,
                to: ProtocolType::WebSocket,
                method: UpgradeMethod::Negotiation,
                required_headers: required_headers,
                optional_headers: optional_headers,
            },
        ]
    }
    
    fn name(&self) -> &'static str {
        self.name
    }
    
    fn estimate_upgrade_time(&self, _from: ProtocolType, _to: ProtocolType) -> Duration {
        Duration::from_millis(50) // WebSocket升级通常很快
    }
}