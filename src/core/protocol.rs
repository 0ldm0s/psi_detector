//! 协议定义模块
//!
//! 定义PSI-Detector支持的协议类型和相关信息。

use serde::{Deserialize, Serialize};
use std::fmt;

/// 协议类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    /// HTTP/1.0
    HTTP1_0,
    /// HTTP/1.1
    HTTP1_1,
    /// HTTP/2
    HTTP2,
    /// HTTP/3
    HTTP3,
    /// gRPC over HTTP/2
    GRPC,
    /// WebSocket
    WebSocket,
    /// QUIC
    QUIC,
    /// MQTT
    MQTT,
    /// TCP (原始TCP流)
    TCP,
    /// TLS
    TLS,
    /// SSH
    SSH,
    /// 未知协议
    Unknown,
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HTTP1_0 => write!(f, "HTTP/1.0"),
            Self::HTTP1_1 => write!(f, "HTTP/1.1"),
            Self::HTTP2 => write!(f, "HTTP/2"),
            Self::HTTP3 => write!(f, "HTTP/3"),
            Self::GRPC => write!(f, "gRPC"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::QUIC => write!(f, "QUIC"),
            Self::MQTT => write!(f, "MQTT"),
            Self::TCP => write!(f, "TCP"),
            Self::TLS => write!(f, "TLS"),
            Self::SSH => write!(f, "SSH"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl ProtocolType {
    /// 获取协议的默认端口
    pub fn default_port(&self) -> Option<u16> {
        match self {
            Self::HTTP1_0 | Self::HTTP1_1 => Some(80),
            Self::HTTP2 | Self::HTTP3 => Some(443),
            Self::GRPC => Some(443),
            Self::WebSocket => Some(80),
            Self::QUIC => Some(443),
            Self::MQTT => Some(1883),
            Self::TLS => Some(443),
            Self::SSH => Some(22),
            Self::TCP | Self::Unknown => None,
        }
    }
    
    /// 检查协议是否基于HTTP
    pub fn is_http_based(&self) -> bool {
        matches!(
            self,
            Self::HTTP1_0
                | Self::HTTP1_1
                | Self::HTTP2
                | Self::HTTP3
                | Self::GRPC
                | Self::WebSocket
        )
    }
    
    /// 检查协议是否支持升级
    pub fn supports_upgrade(&self) -> bool {
        matches!(
            self,
            Self::HTTP1_0 | Self::HTTP1_1 | Self::HTTP2 | Self::TCP
        )
    }
    
    /// 检查协议是否加密
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            Self::HTTP2 | Self::HTTP3 | Self::GRPC | Self::QUIC | Self::TLS | Self::SSH
        )
    }
    
    /// 获取协议族
    pub fn protocol_family(&self) -> ProtocolFamily {
        match self {
            Self::HTTP1_0 | Self::HTTP1_1 | Self::HTTP2 | Self::HTTP3 => ProtocolFamily::HTTP,
            Self::GRPC => ProtocolFamily::RPC,
            Self::WebSocket => ProtocolFamily::WebSocket,
            Self::QUIC => ProtocolFamily::QUIC,
            Self::MQTT => ProtocolFamily::IoT,
            Self::TCP => ProtocolFamily::Transport,
            Self::TLS => ProtocolFamily::Security,
            Self::SSH => ProtocolFamily::Remote,
            Self::Unknown => ProtocolFamily::Unknown,
        }
    }
    
    /// 获取所有支持的协议类型
    pub fn all() -> Vec<ProtocolType> {
        vec![
            Self::HTTP1_0,
            Self::HTTP1_1,
            Self::HTTP2,
            Self::HTTP3,
            Self::GRPC,
            Self::WebSocket,
            Self::QUIC,
            Self::MQTT,
            Self::TCP,
            Self::TLS,
            Self::SSH,
        ]
    }
}

/// 协议族
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolFamily {
    /// HTTP协议族
    HTTP,
    /// RPC协议族
    RPC,
    /// WebSocket协议族
    WebSocket,
    /// QUIC协议族
    QUIC,
    /// IoT协议族
    IoT,
    /// 传输层协议族
    Transport,
    /// 安全协议族
    Security,
    /// 远程访问协议族
    Remote,
    /// 未知协议族
    Unknown,
}

/// 协议信息
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolInfo {
    /// 协议类型
    pub protocol_type: ProtocolType,
    /// 协议版本
    pub version: Option<String>,
    /// 置信度 (0.0 - 1.0)
    pub confidence: f32,
    /// 检测到的特征
    pub features: Vec<String>,
    /// 额外元数据
    pub metadata: std::collections::HashMap<String, String>,
}

impl ProtocolInfo {
    /// 创建新的协议信息
    pub fn new(protocol_type: ProtocolType, confidence: f32) -> Self {
        Self {
            protocol_type,
            version: None,
            confidence: confidence.clamp(0.0, 1.0),
            features: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// 设置版本
    pub fn with_version<S: Into<String>>(mut self, version: S) -> Self {
        self.version = Some(version.into());
        self
    }
    
    /// 添加特征
    pub fn add_feature<S: Into<String>>(&mut self, feature: S) {
        self.features.push(feature.into());
    }
    
    /// 添加元数据
    pub fn add_metadata<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.metadata.insert(key.into(), value.into());
    }
    
    /// 检查置信度是否足够高
    pub fn is_confident(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
    
    /// 检查是否包含特定特征
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

/// 协议升级路径
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpgradePath {
    /// 源协议
    pub from: ProtocolType,
    /// 目标协议
    pub to: ProtocolType,
    /// 升级方法
    pub method: UpgradeMethod,
    /// 必需的头部字段
    pub required_headers: Vec<String>,
    /// 可选的头部字段
    pub optional_headers: Vec<String>,
}

/// 升级方法
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpgradeMethod {
    /// HTTP升级头
    HttpUpgrade,
    /// ALPN协商
    ALPN,
    /// 直接升级
    Direct,
    /// 隧道升级
    Tunnel,
    /// 协商升级
    Negotiation,
    /// 自定义升级
    Custom(String),
}

impl UpgradePath {
    /// 创建新的升级路径
    pub fn new(from: ProtocolType, to: ProtocolType, method: UpgradeMethod) -> Self {
        Self { 
            from, 
            to, 
            method,
            required_headers: Vec::new(),
            optional_headers: Vec::new(),
        }
    }
    
    /// 获取常见的升级路径
    pub fn common_paths() -> Vec<UpgradePath> {
        vec![
            UpgradePath::new(
                ProtocolType::HTTP1_1,
                ProtocolType::HTTP2,
                UpgradeMethod::HttpUpgrade,
            ),
            UpgradePath::new(
                ProtocolType::HTTP2,
                ProtocolType::GRPC,
                UpgradeMethod::Direct,
            ),
            UpgradePath::new(
                ProtocolType::HTTP1_1,
                ProtocolType::WebSocket,
                UpgradeMethod::HttpUpgrade,
            ),
            UpgradePath::new(
                ProtocolType::TCP,
                ProtocolType::TLS,
                UpgradeMethod::Direct,
            ),
        ]
    }
}