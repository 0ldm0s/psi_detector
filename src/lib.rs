//! # PSI-Detector: 协议探测与升级框架
//!
//! 受红警尤里心灵探测器启发的高性能协议探测与升级框架。
//! 提供SIMD加速的协议探测、零拷贝协议升级和统一流抽象。
//!
//! ## 特性
//!
//! - **高效探测**: SIMD加速的多协议并行探测
//! - **无缝升级**: 零拷贝协议升级管道
//! - **统一抽象**: 跨协议的统一流接口
//! - **智能适应**: 自适应探测策略
//! - **可扩展架构**: 支持自定义协议和升级器
//!
//! ## 快速开始
//!
//! 创建探测器实例，启用需要探测的协议，然后对数据进行探测。

#![deny(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::module_inception)]

// 核心模块
pub mod core;
pub mod error;

// 工具模块
pub mod utils;

// 功能模块
#[cfg(feature = "simd-accel")]
pub mod simd;

pub mod upgrade;
pub mod stream;

// 构造器
pub mod builder;
pub mod probe;

// 重新导出核心类型
pub use crate::core::{
    detector::{
        ProtocolDetector, DetectionResult, ProtocolAgent, Agent, AgentConfig, 
        Role, LoadBalancerConfig, LoadBalanceStrategy, Transport
    },
    protocol::{ProtocolType, ProtocolInfo},
};

pub use crate::error::{DetectorError, Result};
pub use crate::builder::DetectorBuilder;
// pub use crate::stream::UnifiedStream;  // 暂时注释，等待实现
// pub use crate::upgrade::UpgradePipeline;  // 暂时注释，等待实现

// 尤里主题支持
#[cfg(feature = "redalert-theme")]
pub mod yuri {
    //! 红警尤里主题的协议类型别名和便捷函数
    
    use crate::core::protocol::ProtocolType;
    // use crate::upgrade::UpgradePipeline;  // 暂时注释，类型不存在
    use crate::builder::DetectorBuilder;
    use crate::core::detector::ProtocolDetector;
    
    /// 心灵扫描 - 协议类型别名
    pub type MindScan = ProtocolType;
    
    /// 心灵升级 - 升级管道别名 (暂时注释)
    // pub type PsychicUpgrade = UpgradePipeline;
    
    /// 创建心灵探测器
    pub fn psychic_detection() -> DetectorBuilder {
        DetectorBuilder::new().psychic_detection()
    }
    
    // 心灵控制 - 协议升级 (暂时注释)
    // pub fn mind_control() -> UpgradePipeline {
    //     UpgradePipeline::new()
    // }
}

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 库名称
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// 库描述
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
