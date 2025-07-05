//! WebSocket协议升级器
//!
//! 处理HTTP到WebSocket的升级过程。

use crate::core::protocol::{ProtocolType, UpgradePath, UpgradeMethod};
use crate::error::{DetectorError, Result};
use crate::upgrade::{ProtocolUpgrader, UpgradeResult};
use std::time::{Duration, Instant};

/// WebSocket升级器
#[derive(Debug)]
pub struct WebSocketUpgrader {
    name: &'static str,
}

impl WebSocketUpgrader {
    /// 创建新的WebSocket升级器
    pub fn new() -> Self {
        Self {
            name: "WebSocketUpgrader",
        }
    }
    
    /// 生成WebSocket密钥
    fn generate_websocket_key(&self) -> String {
        // 简化的WebSocket密钥生成（实际应用中应使用随机生成）
        "dGhlIHNhbXBsZSBub25jZQ==".to_string()
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
    fn create_websocket_upgrade_request(&self, host: &str, path: &str) -> Vec<u8> {
        let key = self.generate_websocket_key();
        
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            path, host, key
        );
        
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

impl ProtocolUpgrader for WebSocketUpgrader {
    fn can_upgrade(&self, from: ProtocolType, to: ProtocolType) -> bool {
        match (from, to) {
            (ProtocolType::HTTP1_1, ProtocolType::WebSocket) => true,
            (ProtocolType::HTTP1_0, ProtocolType::WebSocket) => true,
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
            let mut host = "localhost";
            let mut path = "/";
            
            for line in data_str.lines() {
                if line.to_lowercase().starts_with("host:") {
                    if let Some(h) = line.split(':').nth(1) {
                        host = h.trim();
                    }
                }
                if line.starts_with("GET ") {
                    if let Some(p) = line.split_whitespace().nth(1) {
                        path = p;
                    }
                }
            }
            
            self.create_websocket_upgrade_request(host, path)
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
        vec![
            UpgradePath {
                from: ProtocolType::HTTP1_1,
                to: ProtocolType::WebSocket,
                method: UpgradeMethod::Negotiation,
                required_headers: vec![
                    "Upgrade".to_string(),
                    "Connection".to_string(),
                    "Sec-WebSocket-Key".to_string(),
                    "Sec-WebSocket-Version".to_string(),
                ],
                optional_headers: vec![
                    "Sec-WebSocket-Protocol".to_string(),
                    "Sec-WebSocket-Extensions".to_string(),
                ],
            },
            UpgradePath {
                from: ProtocolType::HTTP1_0,
                to: ProtocolType::WebSocket,
                method: UpgradeMethod::Negotiation,
                required_headers: vec![
                    "Upgrade".to_string(),
                    "Connection".to_string(),
                    "Sec-WebSocket-Key".to_string(),
                    "Sec-WebSocket-Version".to_string(),
                ],
                optional_headers: vec![
                    "Sec-WebSocket-Protocol".to_string(),
                    "Sec-WebSocket-Extensions".to_string(),
                ],
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