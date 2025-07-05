//! 协议升级模块
//!
//! 提供协议升级和转换功能，支持HTTP到WebSocket、HTTP/1.1到HTTP/2等升级场景。

use crate::core::protocol::{ProtocolType, UpgradePath, UpgradeMethod};
use crate::error::{DetectorError, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub mod http;
pub mod websocket;
// pub mod http2;  // TODO: 实现 HTTP/2 升级器
// pub mod quic;   // TODO: 实现 QUIC 升级器

// 重导出主要类型
pub use http::HttpUpgrader;
pub use websocket::WebSocketUpgrader;
// pub use http2::Http2Upgrader;
// pub use quic::QuicUpgrader;

/// 协议升级器trait
pub trait ProtocolUpgrader: Send + Sync + std::fmt::Debug {
    /// 检查是否可以从源协议升级到目标协议
    fn can_upgrade(&self, from: ProtocolType, to: ProtocolType) -> bool;
    
    /// 执行协议升级
    fn upgrade(&self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<UpgradeResult>;
    
    /// 获取支持的升级路径
    fn supported_upgrades(&self) -> Vec<UpgradePath>;
    
    /// 获取升级器名称
    fn name(&self) -> &'static str;
    
    /// 估算升级所需时间
    fn estimate_upgrade_time(&self, from: ProtocolType, to: ProtocolType) -> Duration {
        Duration::from_millis(100) // 默认估算
    }
    
    /// 检查升级的前置条件
    fn check_prerequisites(&self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<()> {
        if !self.can_upgrade(from, to) {
            return Err(DetectorError::upgrade_failed(
                format!("{:?}", from),
                format!("{:?}", to),
                "Upgrade not supported"
            ));
        }
        
        if data.is_empty() {
            return Err(DetectorError::upgrade_failed(
                format!("{:?}", from),
                format!("{:?}", to),
                "Cannot upgrade with empty data"
            ));
        }
        
        Ok(())
    }
}

/// 异步协议升级器trait
#[cfg(any(feature = "runtime-tokio", feature = "runtime-async-std"))]
pub trait AsyncProtocolUpgrader {
    /// 异步执行协议升级
    async fn upgrade_async(&self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<UpgradeResult>;
    
    /// 异步检查升级前置条件
    async fn check_prerequisites_async(&self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<()>;
}

/// 升级结果
#[derive(Debug, Clone, PartialEq)]
pub struct UpgradeResult {
    /// 升级后的协议类型
    pub target_protocol: ProtocolType,
    /// 升级是否成功
    pub success: bool,
    /// 升级后的数据
    pub upgraded_data: Vec<u8>,
    /// 升级方法
    pub method: UpgradeMethod,
    /// 升级耗时
    pub duration: Duration,
    /// 额外的升级信息
    pub metadata: HashMap<String, String>,
    /// 错误信息（如果升级失败）
    pub error_message: Option<String>,
}

impl UpgradeResult {
    /// 创建成功的升级结果
    pub fn success(
        target_protocol: ProtocolType,
        upgraded_data: Vec<u8>,
        method: UpgradeMethod,
        duration: Duration,
    ) -> Self {
        Self {
            target_protocol,
            success: true,
            upgraded_data,
            method,
            duration,
            metadata: HashMap::new(),
            error_message: None,
        }
    }
    
    /// 创建失败的升级结果
    pub fn failure(
        target_protocol: ProtocolType,
        method: UpgradeMethod,
        duration: Duration,
        error: String,
    ) -> Self {
        Self {
            target_protocol,
            success: false,
            upgraded_data: Vec::new(),
            method,
            duration,
            metadata: HashMap::new(),
            error_message: Some(error),
        }
    }
    
    /// 添加元数据
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// 检查升级是否成功
    pub fn is_success(&self) -> bool {
        self.success
    }
    
    /// 获取错误信息
    pub fn error(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

/// 升级配置
#[derive(Debug, Clone)]
pub struct UpgradeConfig {
    /// 升级超时时间
    pub timeout: Duration,
    /// 是否启用自动升级
    pub auto_upgrade: bool,
    /// 最大重试次数
    pub max_retries: u32,
    /// 重试间隔
    pub retry_interval: Duration,
    /// 是否启用升级缓存
    pub enable_cache: bool,
    /// 缓存过期时间
    pub cache_ttl: Duration,
    /// 自定义升级选项
    pub custom_options: HashMap<String, String>,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            auto_upgrade: true,
            max_retries: 3,
            retry_interval: Duration::from_millis(500),
            enable_cache: true,
            cache_ttl: Duration::from_secs(300),
            custom_options: HashMap::new(),
        }
    }
}

/// 升级统计信息
#[derive(Debug, Clone, Default)]
pub struct UpgradeStats {
    /// 总升级次数
    pub total_upgrades: u64,
    /// 成功升级次数
    pub successful_upgrades: u64,
    /// 失败升级次数
    pub failed_upgrades: u64,
    /// 平均升级时间
    pub average_upgrade_time: Duration,
    /// 各协议升级次数统计
    pub protocol_upgrades: HashMap<(ProtocolType, ProtocolType), u64>,
    /// 各升级方法使用次数
    pub method_usage: HashMap<UpgradeMethod, u64>,
}

impl UpgradeStats {
    /// 创建新的统计实例
    pub fn new() -> Self {
        Self::default()
    }
    
    /// 记录升级结果
    pub fn record_upgrade(&mut self, result: &UpgradeResult, from: ProtocolType) {
        self.total_upgrades += 1;
        
        if result.success {
            self.successful_upgrades += 1;
        } else {
            self.failed_upgrades += 1;
        }
        
        // 更新平均时间
        let total_time = self.average_upgrade_time.as_nanos() as u64 * (self.total_upgrades - 1)
            + result.duration.as_nanos() as u64;
        self.average_upgrade_time = Duration::from_nanos(total_time / self.total_upgrades);
        
        // 记录协议升级统计
        let upgrade_pair = (from, result.target_protocol);
        *self.protocol_upgrades.entry(upgrade_pair).or_insert(0) += 1;
        
        // 记录方法使用统计
        *self.method_usage.entry(result.method.clone()).or_insert(0) += 1;
    }
    
    /// 获取成功率
    pub fn success_rate(&self) -> f64 {
        if self.total_upgrades == 0 {
            0.0
        } else {
            self.successful_upgrades as f64 / self.total_upgrades as f64
        }
    }
    
    /// 获取最常用的升级路径
    pub fn most_common_upgrade(&self) -> Option<(ProtocolType, ProtocolType)> {
        self.protocol_upgrades
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&upgrade_pair, _)| upgrade_pair)
    }
    
    /// 重置统计信息
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// 升级管理器
pub struct UpgradeManager {
    upgraders: Vec<Box<dyn ProtocolUpgrader + Send + Sync>>,
    config: UpgradeConfig,
    stats: UpgradeStats,
    cache: HashMap<(ProtocolType, ProtocolType), UpgradeResult>,
    cache_timestamps: HashMap<(ProtocolType, ProtocolType), Instant>,
}

impl UpgradeManager {
    /// 创建新的升级管理器
    pub fn new() -> Self {
        Self {
            upgraders: Vec::new(),
            config: UpgradeConfig::default(),
            stats: UpgradeStats::new(),
            cache: HashMap::new(),
            cache_timestamps: HashMap::new(),
        }
    }
    
    /// 使用指定配置创建升级管理器
    pub fn with_config(config: UpgradeConfig) -> Self {
        Self {
            upgraders: Vec::new(),
            config,
            stats: UpgradeStats::new(),
            cache: HashMap::new(),
            cache_timestamps: HashMap::new(),
        }
    }
    
    /// 添加升级器
    pub fn add_upgrader(&mut self, upgrader: Box<dyn ProtocolUpgrader + Send + Sync>) {
        self.upgraders.push(upgrader);
    }
    
    /// 执行协议升级
    pub fn upgrade(&mut self, from: ProtocolType, to: ProtocolType, data: &[u8]) -> Result<UpgradeResult> {
        // 检查缓存
        if self.config.enable_cache {
            if let Some(cached_result) = self.get_cached_result(from, to) {
                return Ok(cached_result);
            }
        }
        
        // 查找合适的升级器
        let upgrader = self.upgraders
            .iter()
            .find(|u| u.can_upgrade(from, to))
            .ok_or_else(|| DetectorError::upgrade_failed(
                format!("{:?}", from),
                format!("{:?}", to),
                "No upgrader found"
            ))?;
        
        let start = Instant::now();
        let mut last_error = None;
        
        // 重试逻辑
        for attempt in 0..=self.config.max_retries {
            match upgrader.upgrade(from, to, data) {
                Ok(result) => {
                    let final_result = UpgradeResult {
                        duration: start.elapsed(),
                        ..result
                    };
                    
                    // 记录统计
                    self.stats.record_upgrade(&final_result, from);
                    
                    // 缓存结果
                    if self.config.enable_cache && final_result.success {
                        self.cache_result(from, to, final_result.clone());
                    }
                    
                    return Ok(final_result);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries {
                        std::thread::sleep(self.config.retry_interval);
                    }
                }
            }
        }
        
        // 所有重试都失败了
        let error_result = UpgradeResult::failure(
            to,
            UpgradeMethod::Direct,
            start.elapsed(),
            last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown error".to_string()),
        );
        
        self.stats.record_upgrade(&error_result, from);
        Ok(error_result)
    }
    
    /// 获取所有支持的升级路径
    pub fn supported_upgrades(&self) -> Vec<UpgradePath> {
        self.upgraders
            .iter()
            .flat_map(|u| u.supported_upgrades())
            .collect()
    }
    
    /// 检查是否支持指定的升级路径
    pub fn can_upgrade(&self, from: ProtocolType, to: ProtocolType) -> bool {
        self.upgraders.iter().any(|u| u.can_upgrade(from, to))
    }
    
    /// 获取统计信息
    pub fn stats(&self) -> &UpgradeStats {
        &self.stats
    }
    
    /// 清理过期缓存
    pub fn cleanup_cache(&mut self) {
        let now = Instant::now();
        let ttl = self.config.cache_ttl;
        
        let expired_keys: Vec<_> = self.cache_timestamps
            .iter()
            .filter(|(_, &timestamp)| now.duration_since(timestamp) > ttl)
            .map(|(&key, _)| key)
            .collect();
        
        for key in expired_keys {
            self.cache.remove(&key);
            self.cache_timestamps.remove(&key);
        }
    }
    
    /// 获取缓存的结果
    fn get_cached_result(&mut self, from: ProtocolType, to: ProtocolType) -> Option<UpgradeResult> {
        let key = (from, to);
        
        if let Some(&timestamp) = self.cache_timestamps.get(&key) {
            if Instant::now().duration_since(timestamp) <= self.config.cache_ttl {
                return self.cache.get(&key).cloned();
            } else {
                // 缓存过期，清理
                self.cache.remove(&key);
                self.cache_timestamps.remove(&key);
            }
        }
        
        None
    }
    
    /// 缓存升级结果
    fn cache_result(&mut self, from: ProtocolType, to: ProtocolType, result: UpgradeResult) {
        let key = (from, to);
        self.cache.insert(key, result);
        self.cache_timestamps.insert(key, Instant::now());
    }
}

impl Default for UpgradeManager {
    fn default() -> Self {
        let mut manager = Self::new();
        
        // 添加默认升级器
        manager.add_upgrader(Box::new(HttpUpgrader::new()));
        manager.add_upgrader(Box::new(WebSocketUpgrader::new()));
        // TODO: 实现 HTTP/2 和 QUIC 升级器
        // manager.add_upgrader(Box::new(Http2Upgrader::new()));
        // manager.add_upgrader(Box::new(QuicUpgrader::new()));
        
        manager
    }
}