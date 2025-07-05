//! 协议探测核心模块
//!
//! 实现协议探测的核心逻辑，包括探测策略、探测器管理和结果处理。

use crate::core::protocol::{ProtocolType, ProtocolInfo};
use crate::core::detector::{DetectionResult, DetectionMethod};
use crate::error::{DetectorError, Result};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// 探测策略
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeStrategy {
    /// 被动探测 - 仅分析现有数据
    Passive,
    /// 主动探测 - 发送探测包
    Active,
    /// 混合探测 - 被动优先，必要时主动
    Hybrid,
    /// 自适应探测 - 根据网络状况动态调整
    Adaptive,
}

/// 探测配置
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// 探测策略
    pub strategy: ProbeStrategy,
    /// 最大探测时间
    pub max_probe_time: Duration,
    /// 最小置信度阈值
    pub min_confidence: f32,
    /// 是否启用SIMD加速
    pub enable_simd: bool,
    /// 是否启用启发式探测
    pub enable_heuristic: bool,
    /// 探测缓冲区大小
    pub buffer_size: usize,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            strategy: ProbeStrategy::Passive,  // 默认使用被动探测
            max_probe_time: Duration::from_millis(100),
            min_confidence: 0.8,
            enable_simd: true,
            enable_heuristic: true,
            buffer_size: 4096,
        }
    }
}

/// 探测上下文
#[derive(Debug)]
pub struct ProbeContext {
    /// 探测开始时间
    pub start_time: Instant,
    /// 已读取的字节数
    pub bytes_read: usize,
    /// 探测尝试次数
    pub attempt_count: u32,
    /// 当前置信度
    pub current_confidence: f32,
    /// 候选协议列表
    pub candidates: Vec<ProtocolInfo>,
}

impl ProbeContext {
    /// 创建新的探测上下文
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            bytes_read: 0,
            attempt_count: 0,
            current_confidence: 0.0,
            candidates: Vec::new(),
        }
    }
    
    /// 添加候选协议
    pub fn add_candidate(&mut self, protocol: ProtocolInfo) {
        self.candidates.push(protocol);
        // 更新当前最高置信度
        if let Some(max_confidence) = self.candidates.iter().map(|p| p.confidence).fold(None, |acc: Option<f32>, x| {
            Some(acc.map_or(x, |a: f32| a.max(x)))
        }) {
            self.current_confidence = max_confidence;
        }
    }
    
    /// 获取最佳候选协议
    pub fn best_candidate(&self) -> Option<&ProtocolInfo> {
        self.candidates.iter().max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
    }
    
    /// 检查是否超时
    pub fn is_timeout(&self, max_time: Duration) -> bool {
        self.start_time.elapsed() > max_time
    }
}

/// 协议探测器接口
pub trait ProtocolProbe: Send + Sync {
    /// 探测器名称
    fn name(&self) -> &'static str;
    
    /// 支持的协议类型
    fn supported_protocols(&self) -> Vec<ProtocolType>;
    
    /// 执行探测
    fn probe(&self, data: &[u8], context: &mut ProbeContext) -> Result<Option<ProtocolInfo>>;
    
    /// 探测器优先级（数值越高优先级越高）
    fn priority(&self) -> u8 {
        50
    }
    
    /// 是否需要更多数据
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < 64 // 默认需要至少64字节
    }
}

/// 探测器注册表
#[derive(Default)]
pub struct ProbeRegistry {
    probes: HashMap<ProtocolType, Vec<Box<dyn ProtocolProbe>>>,
    global_probes: Vec<Box<dyn ProtocolProbe>>,
}

impl std::fmt::Debug for ProbeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeRegistry")
            .field("probes_count", &self.probes.len())
            .field("global_probes_count", &self.global_probes.len())
            .finish()
    }
}

impl ProbeRegistry {
    /// 创建新的探测器注册表
    pub fn new() -> Self {
        Self::default()
    }
    
    /// 注册协议特定的探测器
    pub fn register_probe(&mut self, protocol: ProtocolType, probe: Box<dyn ProtocolProbe>) {
        self.probes.entry(protocol).or_insert_with(Vec::new).push(probe);
    }
    
    /// 注册全局探测器（支持多种协议）
    pub fn register_global_probe(&mut self, probe: Box<dyn ProtocolProbe>) {
        self.global_probes.push(probe);
    }
    
    /// 获取指定协议的探测器
    pub fn get_probes(&self, protocol: ProtocolType) -> Vec<&dyn ProtocolProbe> {
        let mut probes = Vec::new();
        
        // 添加协议特定的探测器
        if let Some(protocol_probes) = self.probes.get(&protocol) {
            probes.extend(protocol_probes.iter().map(|p| p.as_ref()));
        }
        
        // 添加支持该协议的全局探测器
        for probe in &self.global_probes {
            if probe.supported_protocols().contains(&protocol) {
                probes.push(probe.as_ref());
            }
        }
        
        // 按优先级排序
        probes.sort_by(|a, b| b.priority().cmp(&a.priority()));
        probes
    }
    
    /// 获取所有探测器
    pub fn get_all_probes(&self) -> Vec<&dyn ProtocolProbe> {
        let mut probes = Vec::new();
        
        // 添加所有协议特定的探测器
        for protocol_probes in self.probes.values() {
            probes.extend(protocol_probes.iter().map(|p| p.as_ref()));
        }
        
        // 添加全局探测器
        probes.extend(self.global_probes.iter().map(|p| p.as_ref()));
        
        // 按优先级排序
        probes.sort_by(|a, b| b.priority().cmp(&a.priority()));
        probes
    }
}

/// 探测结果聚合器
#[derive(Debug)]
pub struct ProbeAggregator {
    config: ProbeConfig,
}

impl ProbeAggregator {
    /// 创建新的探测结果聚合器
    pub fn new(config: ProbeConfig) -> Self {
        Self { config }
    }
    
    /// 聚合多个探测结果
    pub fn aggregate(&self, results: Vec<ProtocolInfo>) -> Option<ProtocolInfo> {
        if results.is_empty() {
            return None;
        }
        
        // 按置信度排序
        let mut sorted_results = results;
        sorted_results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        
        // 检查最高置信度是否满足阈值
        let best = &sorted_results[0];
        if best.confidence >= self.config.min_confidence {
            Some(best.clone())
        } else {
            None
        }
    }
    
    /// 创建最终的探测结果
    pub fn create_result(
        &self,
        protocol_info: ProtocolInfo,
        duration: Duration,
        detector_name: String,
    ) -> DetectionResult {
        let method = match self.config.strategy {
            ProbeStrategy::Passive => DetectionMethod::Passive,
            ProbeStrategy::Active => DetectionMethod::Active,
            ProbeStrategy::Hybrid | ProbeStrategy::Adaptive => DetectionMethod::Hybrid,
        };
        
        DetectionResult::new(protocol_info, duration, method, detector_name)
    }
}