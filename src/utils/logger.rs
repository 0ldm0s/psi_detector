//! 日志模块
//!
//! 封装rat_logger日志库，提供统一的日志接口和配置。

use std::sync::Once;
// use rat_logger::prelude::*;  // 暂时注释，等待 rat_logger 实现

/// 日志配置
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// 是否启用日志
    pub enabled: bool,
    /// 日志级别
    pub level: LogLevel,
    /// 是否显示时间戳
    pub show_timestamp: bool,
    /// 是否显示模块路径
    pub show_module: bool,
    /// 是否显示行号
    pub show_line_number: bool,
    /// 是否使用彩色输出
    pub use_colors: bool,
    /// 自定义格式
    pub custom_format: Option<String>,
    /// 输出目标
    pub target: LogTarget,
}

/// 日志级别
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// 错误
    Error,
    /// 警告
    Warn,
    /// 信息
    Info,
    /// 调试
    Debug,
    /// 跟踪
    Trace,
}

/// 日志输出目标
#[derive(Debug, Clone)]
pub enum LogTarget {
    /// 标准输出
    Stdout,
    /// 标准错误
    Stderr,
    /// 文件
    File(String),
    /// 无输出（禁用）
    None,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: LogLevel::Info,
            show_timestamp: true,
            show_module: true,
            show_line_number: false,
            use_colors: true,
            custom_format: None,
            target: LogTarget::Stdout,
        }
    }
}

// impl From<LogLevel> for rat_logger::Level {
//     fn from(level: LogLevel) -> Self {
//         match level {
//             LogLevel::Error => rat_logger::Level::Error,
//             LogLevel::Warn => rat_logger::Level::Warn,
//             LogLevel::Info => rat_logger::Level::Info,
//             LogLevel::Debug => rat_logger::Level::Debug,
//             LogLevel::Trace => rat_logger::Level::Trace,
//         }
//     }
// }

/// 全局日志初始化标志
static LOGGER_INIT: Once = Once::new();

/// 日志器
#[derive(Debug)]
pub struct Logger {
    config: LoggerConfig,
}

impl Logger {
    /// 创建新的日志器
    pub fn new(config: LoggerConfig) -> Self {
        Self { config }
    }
    
    /// 初始化日志器
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.enabled {
            return Ok(());
        }

        // 日志库初始化交给调用者处理，本库不自动初始化
        println!("Logger initialized with config: {:?}", self.config);

        Ok(())
    }
    
    /// 获取配置
    pub fn config(&self) -> &LoggerConfig {
        &self.config
    }
    
    /// 更新配置
    pub fn update_config(&mut self, config: LoggerConfig) {
        self.config = config;
    }
    
    /// 检查是否启用了指定级别的日志
    pub fn is_enabled(&self, level: &LogLevel) -> bool {
        self.config.enabled && level >= &self.config.level
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new(LoggerConfig::default())
    }
}

/// 全局日志器实例
static mut GLOBAL_LOGGER: Option<Logger> = None;
static GLOBAL_LOGGER_INIT: Once = Once::new();

/// 初始化全局日志器
pub fn init_logger(config: LoggerConfig) -> Result<(), Box<dyn std::error::Error>> {
    GLOBAL_LOGGER_INIT.call_once(|| {
        let logger = Logger::new(config);
        if let Err(e) = logger.init() {
            eprintln!("Failed to initialize global logger: {}", e);
            return;
        }
        unsafe {
            GLOBAL_LOGGER = Some(logger);
        }
    });
    Ok(())
}

/// 获取全局日志器
pub fn get_logger() -> Option<&'static Logger> {
    unsafe { GLOBAL_LOGGER.as_ref() }
}

/// 便捷的日志宏

/// 错误日志
#[macro_export]
macro_rules! psi_error {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Error) {
                rat_logger::error!($($arg)*);
            }
        }
    };
}

/// 警告日志
#[macro_export]
macro_rules! psi_warn {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Warn) {
                rat_logger::warn!($($arg)*);
            }
        }
    };
}

/// 信息日志
#[macro_export]
macro_rules! psi_info {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Info) {
                rat_logger::info!($($arg)*);
            }
        }
    };
}

/// 调试日志
#[macro_export]
macro_rules! psi_debug {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Debug) {
                rat_logger::debug!($($arg)*);
            }
        }
    };
}

/// 跟踪日志
#[macro_export]
macro_rules! psi_trace {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Trace) {
                rat_logger::trace!($($arg)*);
            }
        }
    };
}

/// 构建器模式的日志配置
#[derive(Debug)]
pub struct LoggerConfigBuilder {
    config: LoggerConfig,
}

impl LoggerConfigBuilder {
    /// 创建新的配置构建器
    pub fn new() -> Self {
        Self {
            config: LoggerConfig::default(),
        }
    }
    
    /// 设置是否启用日志
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }
    
    /// 设置日志级别
    pub fn level(mut self, level: LogLevel) -> Self {
        self.config.level = level;
        self
    }
    
    /// 设置是否显示时间戳
    pub fn show_timestamp(mut self, show: bool) -> Self {
        self.config.show_timestamp = show;
        self
    }
    
    /// 设置是否显示模块路径
    pub fn show_module(mut self, show: bool) -> Self {
        self.config.show_module = show;
        self
    }
    
    /// 设置是否显示行号
    pub fn show_line_number(mut self, show: bool) -> Self {
        self.config.show_line_number = show;
        self
    }
    
    /// 设置是否使用彩色输出
    pub fn use_colors(mut self, use_colors: bool) -> Self {
        self.config.use_colors = use_colors;
        self
    }
    
    /// 设置自定义格式
    pub fn custom_format<S: Into<String>>(mut self, format: S) -> Self {
        self.config.custom_format = Some(format.into());
        self
    }
    
    /// 设置输出目标
    pub fn target(mut self, target: LogTarget) -> Self {
        self.config.target = target;
        self
    }
    
    /// 构建配置
    pub fn build(self) -> LoggerConfig {
        self.config
    }
    
    /// 构建并初始化日志器
    pub fn init(self) -> Result<(), Box<dyn std::error::Error>> {
        init_logger(self.config)
    }
}

impl Default for LoggerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 创建禁用日志的配置
pub fn disabled_config() -> LoggerConfig {
    LoggerConfig {
        enabled: false,
        ..Default::default()
    }
}

/// 创建开发环境的日志配置
pub fn dev_config() -> LoggerConfig {
    LoggerConfigBuilder::new()
        .level(LogLevel::Debug)
        .show_timestamp(true)
        .show_module(true)
        .show_line_number(true)
        .use_colors(true)
        .target(LogTarget::Stdout)
        .build()
}

/// 创建生产环境的日志配置
pub fn prod_config() -> LoggerConfig {
    LoggerConfigBuilder::new()
        .level(LogLevel::Info)
        .show_timestamp(true)
        .show_module(false)
        .show_line_number(false)
        .use_colors(false)
        .target(LogTarget::Stdout)
        .build()
}

/// 创建文件日志配置
pub fn file_config<P: Into<String>>(path: P) -> LoggerConfig {
    LoggerConfigBuilder::new()
        .level(LogLevel::Info)
        .show_timestamp(true)
        .show_module(true)
        .show_line_number(true)
        .use_colors(false)
        .target(LogTarget::File(path.into()))
        .build()
}

/// 创建尤里心灵探测主题配置
pub fn yuri_psychic_config() -> LoggerConfig {
    LoggerConfigBuilder::new()
        .level(LogLevel::Info)
        .show_timestamp(true)
        .show_module(true)
        .show_line_number(false)
        .use_colors(true)
        .custom_format("🧠 {timestamp} | {level} | {module} | {message}")
        .target(LogTarget::Stdout)
        .build()
}

/// 创建PSI探测器专用配置
pub fn psi_detector_config() -> LoggerConfig {
    LoggerConfigBuilder::new()
        .level(LogLevel::Debug)
        .show_timestamp(true)
        .show_module(true)
        .show_line_number(true)
        .use_colors(true)
        .custom_format("🔍 PSI | {timestamp} | {level} | {module}:{line} | {message}")
        .target(LogTarget::Stdout)
        .build()
}

/// PSI主题日志宏

/// PSI探测日志
#[macro_export]
macro_rules! psi_detect {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Info) {
                rat_logger::info!("🔍 DETECT: {}", format!($($arg)*));
            }
        }
    };
}

/// PSI升级日志
#[macro_export]
macro_rules! psi_upgrade {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Info) {
                rat_logger::info!("⬆️ UPGRADE: {}", format!($($arg)*));
            }
        }
    };
}

/// PSI心灵控制日志
#[macro_export]
macro_rules! psi_mind_control {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Debug) {
                rat_logger::debug!("🧠 MIND_CONTROL: {}", format!($($arg)*));
            }
        }
    };
}

/// PSI扫描日志
#[macro_export]
macro_rules! psi_scan {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Trace) {
                rat_logger::trace!("📡 SCAN: {}", format!($($arg)*));
            }
        }
    };
}

/// PSI性能监控日志
#[macro_export]
macro_rules! psi_perf {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::utils::logger::get_logger() {
            if logger.is_enabled(&$crate::utils::logger::LogLevel::Debug) {
                rat_logger::debug!("⚡ PERF: {}", format!($($arg)*));
            }
        }
    };
}