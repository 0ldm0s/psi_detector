//! 探测器构造器模块
//!
//! 提供流畅的链式API来构建和配置协议探测器。

use crate::core::{
    detector::{
        ProtocolDetector, DetectionConfig, DefaultProtocolDetector,
        Agent, AgentConfig, Role, LoadBalancerConfig, LoadBalanceStrategy
    },
    protocol::ProtocolType,
    probe::{ProbeStrategy, ProbeConfig, ProbeRegistry, ProtocolProbe},
};
use crate::error::{DetectorError, Result};
use std::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

/// 探测器构造器
/// 
/// 提供流畅的API来配置和创建协议探测器实例。
/// 
/// # 示例
/// 
/// ```rust
/// use psi_detector::DetectorBuilder;
/// use psi_detector::core::ProbeStrategy;
/// use std::time::Duration;
/// 
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let detector = DetectorBuilder::new()
///     .enable_http()
///     .enable_tls()
///     .with_strategy(ProbeStrategy::Hybrid)
///     .with_timeout(Duration::from_millis(200))
///     .with_min_confidence(0.85)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct DetectorBuilder {
    enabled_protocols: HashSet<ProtocolType>,
    probe_config: ProbeConfig,
    detection_config: DetectionConfig,
    custom_probes: Vec<Box<dyn ProtocolProbe>>,
    yuri_theme: bool,
    agent_config: Option<AgentConfig>,
    load_balancer_config: Option<LoadBalancerConfig>,
}

impl Default for DetectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectorBuilder {
    /// 创建新的探测器构造器
    pub fn new() -> Self {
        Self {
            enabled_protocols: HashSet::new(),
            probe_config: ProbeConfig::default(),
            detection_config: DetectionConfig::default(),
            custom_probes: Vec::new(),
            yuri_theme: false,
            agent_config: None,
            load_balancer_config: None,
        }
    }
    
    /// 启用HTTP协议探测
    pub fn enable_http(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::HTTP1_1);
        self
    }
    
    /// 启用HTTP/2协议探测
    pub fn enable_http2(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::HTTP2);
        self
    }
    
    /// 启用HTTP/3协议探测
    pub fn enable_http3(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::HTTP3);
        self
    }
    
    /// 启用TLS协议探测
    pub fn enable_tls(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::TLS);
        self
    }
    
    /// 启用QUIC协议探测
    pub fn enable_quic(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::QUIC);
        self
    }
    
    /// 启用SSH协议探测
    pub fn enable_ssh(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::SSH);
        self
    }
    
    /// 启用gRPC协议探测
    pub fn enable_grpc(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::GRPC);
        self
    }
    
    /// 启用WebSocket协议探测
    pub fn enable_websocket(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::WebSocket);
        self
    }
    
    /// 启用所有支持的协议
    pub fn enable_all(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::HTTP1_1);
        self.enabled_protocols.insert(ProtocolType::HTTP2);
        self.enabled_protocols.insert(ProtocolType::TLS);
        self.enabled_protocols.insert(ProtocolType::QUIC);
        self.enabled_protocols.insert(ProtocolType::SSH);
        self.enabled_protocols.insert(ProtocolType::WebSocket);
        self
    }
    
    /// 设置探测策略
    pub fn with_strategy(mut self, strategy: ProbeStrategy) -> Self {
        self.probe_config.strategy = strategy;
        self
    }
    
    /// 设置最大探测时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.probe_config.max_probe_time = timeout;
        self.detection_config.timeout = timeout;
        self
    }
    
    /// 设置最小置信度阈值
    pub fn with_min_confidence(mut self, confidence: f32) -> Self {
        self.probe_config.min_confidence = confidence;
        self.detection_config.min_confidence = confidence;
        self
    }
    
    /// 启用SIMD加速
    pub fn enable_simd(mut self) -> Self {
        self.probe_config.enable_simd = true;
        self
    }
    
    /// 禁用SIMD加速
    pub fn disable_simd(mut self) -> Self {
        self.probe_config.enable_simd = false;
        self
    }
    
    /// 启用启发式探测
    pub fn enable_heuristic(mut self) -> Self {
        self.probe_config.enable_heuristic = true;
        self.detection_config.enable_heuristic = true;
        self
    }
    
    /// 禁用启发式探测
    pub fn disable_heuristic(mut self) -> Self {
        self.probe_config.enable_heuristic = false;
        self.detection_config.enable_heuristic = false;
        self
    }
    
    /// 启用主动探测
    pub fn enable_active_probing(mut self) -> Self {
        self.detection_config.enable_active_probing = true;
        self
    }
    
    /// 禁用主动探测
    pub fn disable_active_probing(mut self) -> Self {
        self.detection_config.enable_active_probing = false;
        self
    }
    
    /// 设置探测缓冲区大小
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.probe_config.buffer_size = size;
        self
    }
    
    /// 设置最小探测数据大小
    pub fn with_min_probe_size(mut self, size: usize) -> Self {
        self.detection_config.min_probe_size = size;
        self
    }
    
    /// 添加自定义探测器
    pub fn add_custom_probe(mut self, probe: Box<dyn ProtocolProbe>) -> Self {
        self.custom_probes.push(probe);
        self
    }
    
    /// 启用尤里主题
    pub fn with_yuri_theme(mut self) -> Self {
        self.yuri_theme = true;
        self
    }
    
    /// 配置Agent角色
     pub fn with_role(mut self, role: Role) -> Self {
         if let Some(ref mut config) = self.agent_config {
             config.role = role;
         } else {
             self.agent_config = Some(AgentConfig {
                 role,
                 instance_id: uuid::Uuid::new_v4().to_string(),
                 detection_config: self.detection_config.clone(),
                 probe_config: self.probe_config.clone(),
                 enabled_protocols: self.enabled_protocols.iter().cloned().collect(),
                 enable_upgrade: true,
                 load_balancer_config: None,
             });
         }
         self
     }
     
     /// 配置Agent实例ID
     pub fn with_instance_id(mut self, instance_id: String) -> Self {
         if let Some(ref mut config) = self.agent_config {
             config.instance_id = instance_id;
         } else {
             self.agent_config = Some(AgentConfig {
                 role: Role::Server,
                 instance_id,
                 detection_config: self.detection_config.clone(),
                 probe_config: self.probe_config.clone(),
                 enabled_protocols: self.enabled_protocols.iter().cloned().collect(),
                 enable_upgrade: true,
                 load_balancer_config: None,
             });
         }
         self
     }
     
     /// 配置负载均衡
     pub fn with_load_balancer(
         mut self,
         strategy: LoadBalanceStrategy,
         backend_instances: Vec<String>,
     ) -> Self {
         let lb_config = LoadBalancerConfig {
             is_load_balancer: true,
             backend_instances,
             strategy,
         };
         
         if let Some(ref mut config) = self.agent_config {
             config.load_balancer_config = Some(lb_config.clone());
         }
         
         self.load_balancer_config = Some(lb_config);
         self
     }
     
     /// 启用协议升级
     pub fn enable_protocol_upgrade(mut self) -> Self {
         if let Some(ref mut config) = self.agent_config {
             config.enable_upgrade = true;
         }
         self
     }
     
     /// 禁用协议升级
     pub fn disable_protocol_upgrade(mut self) -> Self {
         if let Some(ref mut config) = self.agent_config {
             config.enable_upgrade = false;
         }
         self
     }
     
     /// 验证配置
    fn validate_config(&self) -> Result<()> {
        // 验证协议配置
        if self.enabled_protocols.is_empty() {
            return Err(DetectorError::config_error(
                "至少需要启用一个协议"
            ));
        }
        
        // 验证置信度配置
        if self.probe_config.min_confidence < 0.0 || self.probe_config.min_confidence > 1.0 {
            return Err(DetectorError::config_error(
                "置信度阈值必须在0.0到1.0之间"
            ));
        }
        
        // 验证缓冲区大小
        if self.probe_config.buffer_size == 0 {
            return Err(DetectorError::config_error(
                "缓冲区大小必须大于0"
            ));
        }
        
        // 验证Agent配置（如果存在）
        if let Some(ref config) = self.agent_config {
            if config.instance_id.is_empty() {
                return Err(DetectorError::config_error(
                    "实例ID不能为空"
                ));
            }
        }
        
        Ok(())
    }
    
    /// 创建高性能配置
    /// 
    /// 优化配置以获得最佳性能：
    /// - 启用SIMD加速
    /// - 使用被动探测策略
    /// - 较短的超时时间
    /// - 较大的缓冲区
    pub fn high_performance(mut self) -> Self {
        self.probe_config.enable_simd = true;
        self.probe_config.strategy = ProbeStrategy::Passive;
        self.probe_config.max_probe_time = Duration::from_millis(50);
        self.probe_config.buffer_size = 8192;
        self.detection_config.timeout = Duration::from_millis(50);
        self
    }
    
    /// 创建高精度配置
    /// 
    /// 优化配置以获得最佳准确性：
    /// - 启用启发式探测
    /// - 使用被动探测策略
    /// - 较长的超时时间
    /// - 较高的置信度阈值
    pub fn high_accuracy(mut self) -> Self {
        self.probe_config.enable_heuristic = true;
        self.probe_config.strategy = ProbeStrategy::Passive;
        self.probe_config.max_probe_time = Duration::from_millis(200);
        self.probe_config.min_confidence = 0.9;
        self.detection_config.timeout = Duration::from_millis(200);
        self.detection_config.min_confidence = 0.9;
        self.detection_config.enable_heuristic = true;
        self
    }
    
    /// 创建平衡配置
    /// 
    /// 在性能和准确性之间取得平衡的配置。
    pub fn balanced(mut self) -> Self {
        self.probe_config.enable_simd = true;
        self.probe_config.enable_heuristic = true;
        self.probe_config.strategy = ProbeStrategy::Passive;
        self.probe_config.max_probe_time = Duration::from_millis(100);
        self.probe_config.min_confidence = 0.8;
        self.detection_config.timeout = Duration::from_millis(100);
        self.detection_config.min_confidence = 0.8;
        self.detection_config.enable_heuristic = true;
        self
    }
    
    /// 构建探测器实例
    pub fn build(self) -> Result<DefaultProtocolDetector> {
        // 验证配置
        if self.enabled_protocols.is_empty() {
            return Err(DetectorError::config_error(
                "至少需要启用一个协议"
            ));
        }
        
        if self.probe_config.min_confidence < 0.0 || self.probe_config.min_confidence > 1.0 {
            return Err(DetectorError::config_error(
                "置信度阈值必须在0.0到1.0之间"
            ));
        }
        
        if self.probe_config.buffer_size == 0 {
            return Err(DetectorError::config_error(
                "缓冲区大小必须大于0"
            ));
        }
        
        // 创建探测器注册表
        let mut registry = ProbeRegistry::new();
        
        // 注册默认探测器
        self.register_default_probes(&mut registry)?;
        
        // 注册自定义探测器
        for probe in self.custom_probes {
            registry.register_global_probe(probe);
        }
        
        // 创建探测器实例
         DefaultProtocolDetector::new(
             registry,
             self.probe_config,
             self.detection_config,
             self.enabled_protocols.into_iter().collect(),
         )
     }
     
     /// 构建Agent实例
     pub fn build_agent(self) -> Result<Agent> {
         // 验证配置
        self.validate_config()?;
         
         // 创建探测器注册表
         let mut registry = ProbeRegistry::new();
         
         // 注册默认探测器
         self.register_default_probes(&mut registry)?;
         
         // 注册自定义探测器
         for probe in self.custom_probes {
             registry.register_global_probe(probe);
         }
         
         // 创建探测器实例
         let enabled_protocols_vec: Vec<ProtocolType> = self.enabled_protocols.iter().cloned().collect();
         let detector = Arc::new(DefaultProtocolDetector::new(
             registry,
             self.probe_config.clone(),
             self.detection_config.clone(),
             enabled_protocols_vec.clone(),
         )?);
         
         // 获取或创建Agent配置
         let agent_config = self.agent_config.unwrap_or_else(|| AgentConfig {
             role: Role::Server,
             instance_id: uuid::Uuid::new_v4().to_string(),
             detection_config: self.detection_config,
             probe_config: self.probe_config,
             enabled_protocols: enabled_protocols_vec,
             enable_upgrade: true,
             load_balancer_config: self.load_balancer_config,
         });
         
         // 创建升级器（如果启用）
         let upgrader = if agent_config.enable_upgrade {
             // 这里可以根据配置创建相应的升级器
             // 暂时返回None，后续可以扩展
             None
         } else {
             None
         };
         
         Ok(Agent::new(agent_config, detector, upgrader))
    }
    
    /// 注册默认探测器
    fn register_default_probes(&self, registry: &mut ProbeRegistry) -> Result<()> {
        use crate::probe::passive::PassiveProbe;
        
        // 注册被动探测器作为全局探测器（支持多种协议）
        let passive_probe = PassiveProbe::new()
            .with_min_data_size(self.detection_config.min_probe_size)
            .with_confidence_threshold(self.detection_config.min_confidence);
        
        registry.register_global_probe(Box::new(passive_probe));
        
        Ok(())
    }
}

/// 尤里主题构造器扩展
impl DetectorBuilder {
    /// 心灵探测模式 - 高精度被动探测
    pub fn psychic_detection(self) -> Self {
        self.with_yuri_theme()
            .with_strategy(ProbeStrategy::Passive)
            .high_accuracy()
            .enable_heuristic()
    }
    
    /// 心灵控制模式 - 高性能被动探测和协议升级
    pub fn mind_control(self) -> Self {
        self.with_yuri_theme()
            .with_strategy(ProbeStrategy::Passive)
            .disable_active_probing()  // 当前阶段禁用主动探测
            .high_performance()
    }
    
    /// 心灵风暴模式 - 全面被动探测
    pub fn psychic_storm(self) -> Self {
        self.with_yuri_theme()
            .enable_all()
            .with_strategy(ProbeStrategy::Passive)
            .enable_simd()
            .enable_heuristic()
            .disable_active_probing()  // 当前阶段禁用主动探测
    }
}