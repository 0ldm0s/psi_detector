//! 探测引擎模块
//!
//! 提供被动探测和启发式探测功能。

pub mod passive;
// pub mod active;  // 暂时禁用主动探测模块
pub mod heuristic;

pub use passive::PassiveProbe;
// pub use active::ActiveProbe;  // 暂时禁用主动探测
pub use heuristic::HeuristicProbe;

use crate::core::{ProtocolType, DetectionResult};
use crate::error::{Result, DetectorError};

/// 探测引擎trait
pub trait ProbeEngine {
    /// 执行探测
    fn probe(&self, data: &[u8]) -> Result<DetectionResult>;
    
    /// 获取探测类型
    fn probe_type(&self) -> ProbeType;
    
    /// 是否需要更多数据
    fn needs_more_data(&self, data: &[u8]) -> bool;
}

/// 探测类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeType {
    /// 被动探测
    Passive,
    /// 主动探测
    Active,
    /// 启发式探测
    Heuristic,
}

/// 探测结果聚合器
pub struct ProbeAggregator {
    engines: Vec<Box<dyn ProbeEngine>>,
}

impl ProbeAggregator {
    /// 创建新的聚合器
    pub fn new() -> Self {
        Self {
            engines: Vec::new(),
        }
    }
    
    /// 添加探测引擎
    pub fn add_engine(&mut self, engine: Box<dyn ProbeEngine>) {
        self.engines.push(engine);
    }
    
    /// 执行所有探测引擎并聚合结果
    pub fn probe_all(&self, data: &[u8]) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        for engine in &self.engines {
            match engine.probe(data) {
                Ok(result) => results.push(result),
                Err(DetectorError::NeedMoreData(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        
        Ok(results)
    }
    
    /// 获取最佳探测结果
    pub fn best_result(&self, data: &[u8]) -> Result<DetectionResult> {
        let results = self.probe_all(data)?;
        
        if results.is_empty() {
            return Err(DetectorError::detection_failed("No probe results available"));
        }
        
        // 选择置信度最高的结果
        let best = results.into_iter()
            .max_by(|a, b| a.confidence().partial_cmp(&b.confidence()).unwrap())
            .unwrap();
            
        Ok(best)
    }
}

impl Default for ProbeAggregator {
    fn default() -> Self {
        Self::new()
    }
}