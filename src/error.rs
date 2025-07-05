//! 错误处理模块
//!
//! 定义PSI-Detector框架中使用的所有错误类型。

use std::fmt;
use thiserror::Error;

/// PSI-Detector的结果类型
pub type Result<T> = std::result::Result<T, DetectorError>;

/// 探测器错误类型
#[derive(Error, Debug)]
pub enum DetectorError {
    /// 需要更多数据进行探测
    #[error("Need more data for detection, minimum required: {0} bytes")]
    NeedMoreData(usize),
    
    /// 数据不足
    #[error("Insufficient data: {0}")]
    InsufficientData(String),
    
    /// 数据过大
    #[error("Data too large: {0}")]
    DataTooLarge(String),
    
    /// 未检测到协议
    #[error("No protocol detected: {0}")]
    NoProtocolDetected(String),
    
    /// 协议探测失败
    #[error("Protocol detection failed: {reason}")]
    DetectionFailed {
        /// 失败原因
        reason: String,
    },
    
    /// 不支持的协议
    #[error("Unsupported protocol: {protocol}")]
    UnsupportedProtocol {
        /// 协议名称
        protocol: String,
    },
    
    /// 协议升级失败
    #[error("Protocol upgrade failed: {from} -> {to}, reason: {reason}")]
    UpgradeFailed {
        /// 源协议
        from: String,
        /// 目标协议
        to: String,
        /// 失败原因
        reason: String,
    },
    
    /// 配置错误
    #[error("Configuration error: {message}")]
    ConfigError {
        /// 错误消息
        message: String,
    },
    
    /// I/O错误
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// 网络错误
    #[error("Network error: {message}")]
    NetworkError {
        /// 错误消息
        message: String,
    },
    
    /// 超时错误
    #[error("Operation timed out after {timeout_ms}ms")]
    Timeout {
        /// 超时时间（毫秒）
        timeout_ms: u64,
    },
    
    /// 缓冲区错误
    #[error("Buffer error: {message}")]
    BufferError {
        /// 错误消息
        message: String,
    },
    
    /// SIMD操作错误
    #[cfg(feature = "simd-accel")]
    #[error("SIMD operation error: {message}")]
    SimdError {
        /// 错误消息
        message: String,
    },
    
    /// 内部错误
    #[error("Internal error: {message}")]
    InternalError {
        /// 错误消息
        message: String,
    },
}

impl DetectorError {
    /// 创建探测失败错误
    pub fn detection_failed<S: Into<String>>(reason: S) -> Self {
        Self::DetectionFailed {
            reason: reason.into(),
        }
    }
    
    /// 创建不支持协议错误
    pub fn unsupported_protocol<S: Into<String>>(protocol: S) -> Self {
        Self::UnsupportedProtocol {
            protocol: protocol.into(),
        }
    }
    
    /// 创建升级失败错误
    pub fn upgrade_failed<S1, S2, S3>(from: S1, to: S2, reason: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self::UpgradeFailed {
            from: from.into(),
            to: to.into(),
            reason: reason.into(),
        }
    }
    
    /// 创建配置错误
    pub fn config_error<S: Into<String>>(message: S) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }
    
    /// 创建网络错误
    pub fn network_error<S: Into<String>>(message: S) -> Self {
        Self::NetworkError {
            message: message.into(),
        }
    }
    
    /// 创建超时错误
    pub fn timeout(timeout_ms: u64) -> Self {
        Self::Timeout { timeout_ms }
    }
    
    /// 创建缓冲区错误
    pub fn buffer_error<S: Into<String>>(message: S) -> Self {
        Self::BufferError {
            message: message.into(),
        }
    }
    
    /// 创建SIMD错误
    #[cfg(feature = "simd-accel")]
    pub fn simd_error<S: Into<String>>(message: S) -> Self {
        Self::SimdError {
            message: message.into(),
        }
    }
    
    /// 创建内部错误
    pub fn internal_error<S: Into<String>>(message: S) -> Self {
        Self::InternalError {
            message: message.into(),
        }
    }
    
    /// 检查是否为可恢复错误
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::NeedMoreData(_)
                | Self::DetectionFailed { .. }
                | Self::Timeout { .. }
                | Self::NetworkError { .. }
        )
    }
    
    /// 检查是否为配置相关错误
    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            Self::ConfigError { .. } | Self::UnsupportedProtocol { .. }
        )
    }
    
    /// 获取错误代码
    pub fn error_code(&self) -> u32 {
        match self {
            Self::NeedMoreData(_) => 1001,
            Self::InsufficientData(_) => 1002,
            Self::DataTooLarge(_) => 1003,
            Self::NoProtocolDetected(_) => 1004,
            Self::DetectionFailed { .. } => 1005,
            Self::UnsupportedProtocol { .. } => 1006,
            Self::UpgradeFailed { .. } => 1007,
            Self::ConfigError { .. } => 1008,
            Self::IoError(_) => 1009,
            Self::NetworkError { .. } => 1010,
            Self::Timeout { .. } => 1011,
            Self::BufferError { .. } => 1012,
            #[cfg(feature = "simd-accel")]
            Self::SimdError { .. } => 1013,
            Self::InternalError { .. } => 1999,
        }
    }
}

/// 从anyhow::Error转换
impl From<anyhow::Error> for DetectorError {
    fn from(err: anyhow::Error) -> Self {
        Self::internal_error(err.to_string())
    }
}

/// 从serde_json::Error转换
impl From<serde_json::Error> for DetectorError {
    fn from(err: serde_json::Error) -> Self {
        Self::config_error(format!("JSON error: {}", err))
    }
}