//! HTTP协议升级器
//!
//! 处理HTTP/1.0到HTTP/1.1、HTTP/1.1到HTTP/2等升级场景。

use crate::core::protocol::{ProtocolType, UpgradePath, UpgradeMethod};
use crate::error::{DetectorError, Result};
use crate::upgrade::{ProtocolUpgrader, UpgradeResult};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// HTTP协议升级器
#[derive(Debug)]
pub struct HttpUpgrader {
    name: &'static str,
}

impl HttpUpgrader {
    /// 创建新的HTTP升级器
    pub fn new() -> Self {
        Self {
            name: "HttpUpgrader",
        }
    }
    
    /// 升级HTTP/1.0到HTTP/1.1
    fn upgrade_http10_to_http11(&self, data: &[u8]) -> Result<Vec<u8>> {
        let request_str = String::from_utf8_lossy(data);
        
        // 检查是否是有效的HTTP/1.0请求
        if !request_str.contains("HTTP/1.0") {
            return Err(DetectorError::upgrade_failed(
                "HTTP/1.0".to_string(),
                "HTTP/1.1".to_string(),
                "Not a valid HTTP/1.0 request".to_string()
            ));
        }
        
        // 将HTTP/1.0升级到HTTP/1.1
        let upgraded = request_str.replace("HTTP/1.0", "HTTP/1.1");
        
        // 添加必要的HTTP/1.1头部
        let mut lines: Vec<&str> = upgraded.lines().collect();
        let mut has_host = false;
        let mut has_connection = false;
        
        // 检查现有头部
        for line in &lines {
            if line.to_lowercase().starts_with("host:") {
                has_host = true;
            }
            if line.to_lowercase().starts_with("connection:") {
                has_connection = true;
            }
        }
        
        // 找到头部结束位置
        let mut header_end = lines.len();
        for (i, line) in lines.iter().enumerate() {
            if line.is_empty() {
                header_end = i;
                break;
            }
        }
        
        // 添加缺失的头部
        if !has_host {
            lines.insert(header_end, "Host: localhost");
            header_end += 1;
        }
        
        if !has_connection {
            lines.insert(header_end, "Connection: keep-alive");
        }
        
        Ok(lines.join("\r\n").into_bytes())
    }
    
    /// 升级HTTP/1.1到HTTP/2
    fn upgrade_http11_to_http2(&self, data: &[u8]) -> Result<Vec<u8>> {
        let request_str = String::from_utf8_lossy(data);
        
        // 检查是否是有效的HTTP/1.1请求
        if !request_str.contains("HTTP/1.1") {
            return Err(DetectorError::upgrade_failed(
                "HTTP/1.1".to_string(),
                "HTTP/2".to_string(),
                "Not a valid HTTP/1.1 request".to_string()
            ));
        }
        
        // 创建HTTP/2升级请求
        let mut lines: Vec<&str> = request_str.lines().collect();
        
        // 找到头部结束位置
        let mut header_end = lines.len();
        for (i, line) in lines.iter().enumerate() {
            if line.is_empty() {
                header_end = i;
                break;
            }
        }
        
        // 添加HTTP/2升级头部
        let upgrade_headers = vec![
            "Connection: Upgrade, HTTP2-Settings",
            "Upgrade: h2c",
            "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA", // Base64编码的HTTP/2设置
        ];
        
        for header in upgrade_headers.iter().rev() {
            lines.insert(header_end, header);
        }
        
        Ok(lines.join("\r\n").into_bytes())
    }
    
    /// 处理HTTP/2连接前言
    fn create_http2_preface(&self) -> Vec<u8> {
        // HTTP/2连接前言
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        
        // 添加SETTINGS帧
        let mut result = preface.to_vec();
        
        // SETTINGS帧：类型=0x4, 标志=0x0, 流ID=0x0, 长度=0x0
        let settings_frame = [
            0x00, 0x00, 0x00, // 长度：0
            0x04,             // 类型：SETTINGS
            0x00,             // 标志：无
            0x00, 0x00, 0x00, 0x00, // 流ID：0
        ];
        
        result.extend_from_slice(&settings_frame);
        result
    }
    
    /// 检查HTTP版本
    fn detect_http_version(&self, data: &[u8]) -> Option<ProtocolType> {
        let data_str = String::from_utf8_lossy(data);
        
        if data_str.contains("HTTP/1.0") {
            Some(ProtocolType::HTTP1_0)
        } else if data_str.contains("HTTP/1.1") {
            Some(ProtocolType::HTTP1_1)
        } else if data_str.contains("HTTP/2.0") || data.starts_with(b"PRI * HTTP/2.0") {
            Some(ProtocolType::HTTP2)
        } else if data_str.contains("HTTP/3") {
            Some(ProtocolType::HTTP3)
        } else {
            None
        }
    }
    
    /// 验证升级请求
    fn validate_upgrade_request(&self, data: &[u8], target: ProtocolType) -> Result<()> {
        let data_str = String::from_utf8_lossy(data);
        
        match target {
            ProtocolType::HTTP2 => {
                // 检查HTTP/2升级所需的头部
                if !data_str.to_lowercase().contains("upgrade:") {
                    return Err(DetectorError::upgrade_failed(
                        "HTTP/1.1".to_string(),
                        "HTTP/2".to_string(),
                        "Missing Upgrade header for HTTP/2".to_string()
                    ));
                }
                
                if !data_str.to_lowercase().contains("connection:") {
                    return Err(DetectorError::upgrade_failed(
                        "HTTP/1.1".to_string(),
                        "HTTP/2".to_string(),
                        "Missing Connection header for HTTP/2".to_string()
                    ));
                }
            }
            ProtocolType::HTTP3 => {
                // HTTP/3升级通常通过Alt-Svc头部
                if !data_str.to_lowercase().contains("alt-svc:") {
                    return Err(DetectorError::upgrade_failed(
                        "HTTP".to_string(),
                        "HTTP/3".to_string(),
                        "Missing Alt-Svc header for HTTP/3".to_string()
                    ));
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}

impl Default for HttpUpgrader {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolUpgrader for HttpUpgrader {
    fn can_upgrade(&self, from: ProtocolType, to: ProtocolType) -> bool {
        match (from, to) {
            (ProtocolType::HTTP1_0, ProtocolType::HTTP1_1) => true,
            (ProtocolType::HTTP1_1, ProtocolType::HTTP2) => true,
            (ProtocolType::HTTP2, ProtocolType::HTTP3) => true,
            (ProtocolType::HTTP1_1, ProtocolType::HTTP3) => true,
            _ => false,
        }
    }
    
    fn upgrade(&self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<UpgradeResult> {
        let start = Instant::now();
        
        // 检查前置条件
        self.check_prerequisites(from, to, data)?;
        
        // 验证当前数据确实是源协议
        if let Some(detected) = self.detect_http_version(data) {
            if detected != from {
                return Ok(UpgradeResult::failure(
                    to,
                    UpgradeMethod::Direct,
                    start.elapsed(),
                    format!("Data is {:?}, not {:?}", detected, from),
                ));
            }
        }
        
        let upgraded_data = match (from, to) {
            (ProtocolType::HTTP1_0, ProtocolType::HTTP1_1) => {
                self.upgrade_http10_to_http11(data)?
            }
            (ProtocolType::HTTP1_1, ProtocolType::HTTP2) => {
                // 验证升级请求
                if let Err(e) = self.validate_upgrade_request(data, to) {
                    // 如果没有升级头部，创建升级请求
                    self.upgrade_http11_to_http2(data)?
                } else {
                    // 已经有升级头部，创建HTTP/2连接前言
                    self.create_http2_preface()
                }
            }
            (ProtocolType::HTTP2, ProtocolType::HTTP3) => {
                // HTTP/2到HTTP/3的升级通常通过QUIC
                // 这里创建一个简单的HTTP/3指示
                let http3_indicator = b"HTTP/3 upgrade indication";
                http3_indicator.to_vec()
            }
            (ProtocolType::HTTP1_1, ProtocolType::HTTP3) => {
                // 直接从HTTP/1.1升级到HTTP/3
                let http3_upgrade = b"HTTP/1.1 to HTTP/3 upgrade";
                http3_upgrade.to_vec()
            }
            _ => {
                return Ok(UpgradeResult::failure(
                    to,
                    UpgradeMethod::Direct,
                    start.elapsed(),
                    format!("Unsupported upgrade: {:?} -> {:?}", from, to),
                ));
            }
        };
        
        let duration = start.elapsed();
        let method = match (from, to) {
            (ProtocolType::HTTP1_1, ProtocolType::HTTP2) => UpgradeMethod::Negotiation,
            _ => UpgradeMethod::Direct,
        };
        
        let mut result = UpgradeResult::success(to, upgraded_data, method.clone(), duration);
        
        // 添加元数据
        result = result.with_metadata(
            "original_protocol".to_string(),
            format!("{:?}", from),
        );
        result = result.with_metadata(
            "upgrade_method".to_string(),
            format!("{:?}", method),
        );
        
        Ok(result)
    }
    
    fn supported_upgrades(&self) -> Vec<UpgradePath> {
        vec![
            UpgradePath {
                from: ProtocolType::HTTP1_0,
                to: ProtocolType::HTTP1_1,
                method: UpgradeMethod::Direct,
                required_headers: vec![],
                optional_headers: vec!["Host".to_string(), "Connection".to_string()],
            },
            UpgradePath {
                from: ProtocolType::HTTP1_1,
                to: ProtocolType::HTTP2,
                method: UpgradeMethod::Negotiation,
                required_headers: vec![
                    "Connection".to_string(),
                    "Upgrade".to_string(),
                    "HTTP2-Settings".to_string(),
                ],
                optional_headers: vec![],
            },
            UpgradePath {
                from: ProtocolType::HTTP2,
                to: ProtocolType::HTTP3,
                method: UpgradeMethod::Negotiation,
                required_headers: vec!["Alt-Svc".to_string()],
                optional_headers: vec![],
            },
            UpgradePath {
                from: ProtocolType::HTTP1_1,
                to: ProtocolType::HTTP3,
                method: UpgradeMethod::Negotiation,
                required_headers: vec!["Alt-Svc".to_string()],
                optional_headers: vec![],
            },
        ]
    }
    
    fn name(&self) -> &'static str {
        self.name
    }
    
    fn estimate_upgrade_time(&self, from: ProtocolType, to: ProtocolType) -> Duration {
        match (from, to) {
            (ProtocolType::HTTP1_0, ProtocolType::HTTP1_1) => Duration::from_millis(10),
            (ProtocolType::HTTP1_1, ProtocolType::HTTP2) => Duration::from_millis(100),
            (ProtocolType::HTTP2, ProtocolType::HTTP3) => Duration::from_millis(200),
            (ProtocolType::HTTP1_1, ProtocolType::HTTP3) => Duration::from_millis(300),
            _ => Duration::from_millis(50),
        }
    }
}