//! 协议探测器核心接口
//!
//! 定义协议探测的核心trait和相关类型。

use crate::core::protocol::{ProtocolType, ProtocolInfo};
use crate::core::probe::{ProbeRegistry, ProbeConfig, ProbeContext, ProbeAggregator};
use crate::error::{DetectorError, Result};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;

/// 协议代理角色
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// 服务器模式 - 被动探测传入连接
    Server,
    /// 客户端模式 - 主动探测服务端能力
    Client,
}

impl Role {
    /// 检查是否为服务器角色
    pub fn is_server(&self) -> bool {
        matches!(self, Role::Server)
    }
    
    /// 检查是否为客户端角色
    pub fn is_client(&self) -> bool {
        matches!(self, Role::Client)
    }
}

/// 协议代理配置
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// 代理角色
    pub role: Role,
    /// 实例ID（用于多实例场景）
    pub instance_id: String,
    /// 探测配置
    pub detection_config: DetectionConfig,
    /// 探测器配置
    pub probe_config: ProbeConfig,
    /// 启用的协议列表
    pub enabled_protocols: Vec<ProtocolType>,
    /// 是否启用协议升级
    pub enable_upgrade: bool,
    /// 负载均衡配置（仅服务器模式）
    pub load_balancer_config: Option<LoadBalancerConfig>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            role: Role::Server,
            instance_id: uuid::Uuid::new_v4().to_string(),
            detection_config: DetectionConfig::default(),
            probe_config: ProbeConfig::default(),
            enabled_protocols: vec![
                ProtocolType::HTTP1_1,
                ProtocolType::HTTP2,
                ProtocolType::TLS,
            ],
            enable_upgrade: true,
            load_balancer_config: None,
        }
    }
}

/// 负载均衡配置
#[derive(Debug, Clone)]
pub struct LoadBalancerConfig {
    /// 是否作为负载均衡器
    pub is_load_balancer: bool,
    /// 后端实例列表
    pub backend_instances: Vec<String>,
    /// 负载均衡策略
    pub strategy: LoadBalanceStrategy,
}

/// 负载均衡策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    /// 轮询
    RoundRobin,
    /// 最少连接
    LeastConnections,
    /// 加权轮询
    WeightedRoundRobin,
    /// 一致性哈希
    ConsistentHash,
}

/// 探测结果
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    /// 探测到的协议信息
    pub protocol_info: ProtocolInfo,
    /// 探测耗时
    pub detection_time: Duration,
    /// 使用的探测方法
    pub detection_method: DetectionMethod,
    /// 探测器名称
    pub detector_name: String,
}

impl DetectionResult {
    /// 创建新的探测结果
    pub fn new(
        protocol_info: ProtocolInfo,
        detection_time: Duration,
        detection_method: DetectionMethod,
        detector_name: String,
    ) -> Self {
        Self {
            protocol_info,
            detection_time,
            detection_method,
            detector_name,
        }
    }
    
    /// 获取协议类型
    pub fn protocol_type(&self) -> ProtocolType {
        self.protocol_info.protocol_type
    }
    
    /// 获取置信度
    pub fn confidence(&self) -> f32 {
        self.protocol_info.confidence
    }
    
    /// 检查是否为高置信度结果
    pub fn is_high_confidence(&self) -> bool {
        self.confidence() >= 0.8
    }
    
    /// 检查是否为可接受的结果
    pub fn is_acceptable(&self, min_confidence: f32) -> bool {
        self.confidence() >= min_confidence
    }
}

/// 默认协议探测器实现
#[derive(Debug)]
pub struct DefaultProtocolDetector {
    registry: ProbeRegistry,
    probe_config: ProbeConfig,
    detection_config: DetectionConfig,
    enabled_protocols: Vec<ProtocolType>,
    aggregator: ProbeAggregator,
}

impl DefaultProtocolDetector {
    /// 创建新的协议探测器
    pub fn new(
        registry: ProbeRegistry,
        probe_config: ProbeConfig,
        detection_config: DetectionConfig,
        enabled_protocols: Vec<ProtocolType>,
    ) -> Result<Self> {
        let aggregator = ProbeAggregator::new(probe_config.clone());
        
        Ok(Self {
            registry,
            probe_config,
            detection_config,
            enabled_protocols,
            aggregator,
        })
    }
    
    /// 获取探测配置
    pub fn probe_config(&self) -> &ProbeConfig {
        &self.probe_config
    }
    
    /// 获取检测配置
    pub fn detection_config(&self) -> &DetectionConfig {
        &self.detection_config
    }
    
    /// 获取启用的协议列表
    pub fn enabled_protocols(&self) -> &[ProtocolType] {
        &self.enabled_protocols
    }
}

impl ProtocolDetector for DefaultProtocolDetector {
    fn detect(&self, data: &[u8]) -> Result<DetectionResult> {
        let start_time = Instant::now();
        let mut context = ProbeContext::new();
        context.bytes_read = data.len();
        
        // 检查数据大小
        if data.len() < self.min_probe_size() {
            return Err(DetectorError::InsufficientData(
                format!("需要至少 {} 字节，但只有 {} 字节", self.min_probe_size(), data.len())
            ));
        }
        
        if data.len() > self.max_probe_size() {
            return Err(DetectorError::DataTooLarge(
                format!("数据大小 {} 字节超过最大限制 {} 字节", data.len(), self.max_probe_size())
            ));
        }
        
        // 收集所有探测结果
        let mut all_results = Vec::new();
        
        // 对每个启用的协议运行探测器
        let start_time = Instant::now();
        let max_detection_time = self.detection_config.timeout;
        
        for &protocol in &self.enabled_protocols {
            // 更频繁的超时检查
            if start_time.elapsed() > max_detection_time {
                break;
            }
            
            let probes = self.registry.get_probes(protocol);
            
            for probe in probes {
                // 检查是否需要更多数据
                if probe.needs_more_data(data) {
                    continue;
                }
                
                // 更频繁的超时检查
                if start_time.elapsed() > max_detection_time {
                    break;
                }
                
                // 执行探测
                match probe.probe(data, &mut context) {
                    Ok(Some(protocol_info)) => {
                        all_results.push(protocol_info);
                    }
                    Ok(None) => {
                        // 探测器没有检测到协议，继续
                    }
                    Err(e) => {
                        // 记录错误但继续其他探测器
                        eprintln!("探测器 {} 出错: {}", probe.name(), e);
                    }
                }
            }
        }
        
        // 运行所有全局探测器（支持未知协议的探测器）
        let all_probes = self.registry.get_all_probes();
        for probe in all_probes {
            // 检查是否需要更多数据
            if probe.needs_more_data(data) {
                continue;
            }
            
            // 检查超时
            if context.is_timeout(self.detection_config.timeout) {
                break;
            }
            
            // 执行探测
            match probe.probe(data, &mut context) {
                Ok(Some(protocol_info)) => {
                    all_results.push(protocol_info);
                }
                Ok(None) => {
                    // 探测器没有检测到协议，继续
                }
                Err(e) => {
                    // 记录错误但继续其他探测器
                    eprintln!("探测器 {} 出错: {}", probe.name(), e);
                }
            }
        }
        
        // 聚合结果
        let best_result = self.aggregator.aggregate(all_results)
            .ok_or_else(|| DetectorError::NoProtocolDetected("未检测到任何协议".to_string()))?;
        
        // 创建最终结果
        let detection_time = start_time.elapsed();
        Ok(self.aggregator.create_result(
            best_result,
            detection_time,
            "DefaultProtocolDetector".to_string(),
        ))
    }
    
    fn min_probe_size(&self) -> usize {
        self.detection_config.min_probe_size
    }
    
    fn max_probe_size(&self) -> usize {
        self.detection_config.max_probe_size
    }
    
    fn supported_protocols(&self) -> Vec<ProtocolType> {
        self.enabled_protocols.clone()
    }
    
    fn name(&self) -> &str {
        "DefaultProtocolDetector"
    }
}

/// 探测方法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// 被动探测（仅分析数据）
    Passive,
    /// 主动探测（发送探测包）
    Active,
    /// 启发式探测
    Heuristic,
    /// SIMD加速探测
    SimdAccelerated,
    /// 混合探测
    Hybrid,
}

/// 协议代理trait - 统一的双向框架接口
pub trait ProtocolAgent: Send + Sync + std::fmt::Debug {
    /// 探测协议类型（被动模式 - 服务器角色）
    fn detect(&self, data: &[u8]) -> Result<DetectionResult>;
    
    /// 主动探测协议能力（主动模式 - 客户端角色）
    fn probe_capabilities(&self, transport: &mut dyn Transport) -> Result<Vec<ProtocolType>> {
        match self.role() {
            Role::Client => {
                // 客户端模式：主动发送探测请求
                self.active_probe(transport)
            },
            Role::Server => {
                // 服务器模式：不支持主动探测
                Err(DetectorError::unsupported_protocol(
                    "Server role does not support active probing"
                ))
            },
        }
    }
    
    /// 主动探测实现（客户端专用）
    fn active_probe(&self, transport: &mut dyn Transport) -> Result<Vec<ProtocolType>> {
        let mut supported_protocols = Vec::new();
        
        // 按优先级顺序探测协议
        let probe_order = [
            ProtocolType::HTTP3,
            ProtocolType::HTTP2, 
            ProtocolType::HTTP1_1,
            ProtocolType::TLS,
            ProtocolType::QUIC,
        ];
        
        for protocol in probe_order {
            if self.supports_protocol(protocol) {
                match self.send_protocol_probe(transport, protocol) {
                    Ok(true) => {
                        supported_protocols.push(protocol);
                        // 找到最高优先级协议后可以选择停止或继续探测
                        if matches!(protocol, ProtocolType::HTTP3 | ProtocolType::QUIC) {
                            break;
                        }
                    },
                    Ok(false) => continue,
                    Err(_) => continue, // 探测失败，继续下一个协议
                }
            }
        }
        
        if supported_protocols.is_empty() {
            // 保底协议
            supported_protocols.push(ProtocolType::HTTP1_1);
        }
        
        Ok(supported_protocols)
    }
    
    /// 发送特定协议的探测请求
    fn send_protocol_probe(&self, transport: &mut dyn Transport, protocol: ProtocolType) -> Result<bool> {
        match protocol {
            ProtocolType::HTTP2 => {
                // HTTP/2 连接前言探测
                let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                transport.write(h2_preface)?;
                
                // 读取响应
                let mut response = vec![0u8; 24];
                match transport.read(&mut response) {
                    Ok(n) if n > 0 => {
                        // 检查是否收到HTTP/2 SETTINGS帧
                        Ok(response.len() >= 9 && response[3] == 0x04) // SETTINGS帧类型
                    },
                    _ => Ok(false),
                }
            },
            ProtocolType::HTTP3 => {
                // HTTP/3 over QUIC探测
                // 这里需要QUIC握手逻辑，简化实现
                Ok(false) // 暂时返回false，需要完整的QUIC实现
            },
            ProtocolType::HTTP1_1 => {
                // HTTP/1.1 OPTIONS请求探测
                let options_request = b"OPTIONS * HTTP/1.1\r\nHost: probe\r\n\r\n";
                transport.write(options_request)?;
                
                let mut response = vec![0u8; 256];
                match transport.read(&mut response) {
                    Ok(n) if n > 0 => {
                        let response_str = String::from_utf8_lossy(&response[..n]);
                        Ok(response_str.starts_with("HTTP/1.1") || response_str.starts_with("HTTP/1.0"))
                    },
                    _ => Ok(false),
                }
            },
            ProtocolType::TLS => {
                // TLS ClientHello探测
                let client_hello = self.create_tls_client_hello();
                transport.write(&client_hello)?;
                
                let mut response = vec![0u8; 1024];
                match transport.read(&mut response) {
                    Ok(n) if n >= 5 => {
                        // 检查TLS ServerHello响应
                        Ok(response[0] == 0x16 && response[1] == 0x03) // TLS握手记录
                    },
                    _ => Ok(false),
                }
            },
            _ => Ok(false), // 其他协议暂不支持主动探测
        }
    }
    
    /// 创建TLS ClientHello消息
    fn create_tls_client_hello(&self) -> Vec<u8> {
        // 简化的TLS 1.2 ClientHello
        vec![
            0x16, 0x03, 0x01, 0x00, 0x2f, // TLS记录头
            0x01, 0x00, 0x00, 0x2b,       // 握手消息头
            0x03, 0x03,                   // TLS版本1.2
            // 32字节随机数（简化）
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,                         // 会话ID长度
            0x00, 0x02,                   // 密码套件长度
            0x00, 0x35,                   // AES128-SHA
            0x01, 0x00,                   // 压缩方法
        ]
    }
    
    /// 协议升级（主动/被动模式）
    fn upgrade(
        &self,
        transport: Box<dyn Transport>,
        role: Role,
    ) -> Result<Box<dyn Transport>>;
    
    /// 协议协商（客户端模式）
    fn negotiate_protocol(&self, max_supported: ProtocolType) -> ProtocolType {
        let candidates = [
            ProtocolType::HTTP3,
            ProtocolType::HTTP2,
            ProtocolType::HTTP1_1,
        ];
        
        for proto in candidates {
            if self.supports_protocol(proto) && proto <= max_supported {
                return proto;
            }
        }
        ProtocolType::HTTP1_1 // 保底协议
    }
    
    /// 智能降级策略（客户端模式）
    fn auto_fallback(&self, transport: &mut dyn Transport, preferred: ProtocolType) -> Result<ProtocolType> {
        match self.role() {
            Role::Client => {
                // 尝试首选协议
                if self.send_protocol_probe(transport, preferred)? {
                    return Ok(preferred);
                }
                
                // 自动降级
                let fallback_chain = match preferred {
                    ProtocolType::HTTP3 => vec![ProtocolType::HTTP2, ProtocolType::HTTP1_1],
                    ProtocolType::HTTP2 => vec![ProtocolType::HTTP1_1],
                    ProtocolType::QUIC => vec![ProtocolType::TLS, ProtocolType::TCP],
                    _ => vec![ProtocolType::HTTP1_1],
                };
                
                for fallback in fallback_chain {
                    if self.supports_protocol(fallback) && 
                       self.send_protocol_probe(transport, fallback)? {
                        return Ok(fallback);
                    }
                }
                
                // 最终保底
                Ok(ProtocolType::HTTP1_1)
            },
            Role::Server => {
                Err(DetectorError::unsupported_protocol(
                    "Server role does not support auto fallback"
                ))
            },
        }
    }
    
    /// 检查是否支持指定协议
    fn supports_protocol(&self, protocol: ProtocolType) -> bool;
    
    /// 获取代理角色
    fn role(&self) -> Role;
    
    /// 获取实例ID
    fn instance_id(&self) -> &str;
    
    /// 获取代理名称
    fn name(&self) -> &str;
}

/// 传输层抽象trait
pub trait Transport: Send + Sync {
    /// 读取数据
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    
    /// 写入数据
    fn write(&mut self, data: &[u8]) -> Result<usize>;
    
    /// 预览数据（不消费）
    fn peek(&self, size: usize) -> Result<Vec<u8>>;
    
    /// 关闭连接
    fn close(&mut self) -> Result<()>;
    
    /// 获取传输层类型
    fn transport_type(&self) -> &str;
}

/// 协议探测器trait
pub trait ProtocolDetector: Send + Sync + std::fmt::Debug {
    /// 探测协议类型
    fn detect(&self, data: &[u8]) -> Result<DetectionResult>;
    
    /// 获取协议特征置信度
    fn confidence(&self, data: &[u8]) -> Result<f32> {
        self.detect(data).map(|result| result.confidence())
    }
    
    /// 最小探测数据要求
    fn min_probe_size(&self) -> usize {
        64 // 默认64字节
    }
    
    /// 最大探测数据大小
    fn max_probe_size(&self) -> usize {
        4096 // 默认4KB
    }
    
    /// 支持的协议类型
    fn supported_protocols(&self) -> Vec<ProtocolType>;
    
    /// 探测器名称
    fn name(&self) -> &str;
    
    /// 检查是否可以探测指定协议
    fn can_detect(&self, protocol: ProtocolType) -> bool {
        self.supported_protocols().contains(&protocol)
    }
    
    /// 批量探测（可选实现）
    fn detect_batch(&self, data_chunks: &[&[u8]]) -> Result<Vec<DetectionResult>> {
        data_chunks
            .iter()
            .map(|chunk| self.detect(chunk))
            .collect()
    }
}

/// 异步协议探测器trait
#[cfg(any(feature = "runtime-tokio", feature = "runtime-async-std"))]
#[async_trait::async_trait]
pub trait AsyncProtocolDetector: Send + Sync {
    /// 异步探测协议类型
    async fn detect_async(&self, data: &[u8]) -> Result<DetectionResult>;
    
    /// 异步获取置信度
    async fn confidence_async(&self, data: &[u8]) -> Result<f32> {
        self.detect_async(data).await.map(|result| result.confidence())
    }
    
    /// 最小探测数据要求
    fn min_probe_size(&self) -> usize {
        64
    }
    
    /// 最大探测数据大小
    fn max_probe_size(&self) -> usize {
        4096
    }
    
    /// 支持的协议类型
    fn supported_protocols(&self) -> Vec<ProtocolType>;
    
    /// 探测器名称
    fn name(&self) -> &str;
    
    /// 异步批量探测
    async fn detect_batch_async(&self, data_chunks: &[&[u8]]) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        for chunk in data_chunks {
            results.push(self.detect_async(chunk).await?);
        }
        Ok(results)
    }
}

/// 探测配置
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// 最小置信度阈值
    pub min_confidence: f32,
    /// 探测超时时间
    pub timeout: Duration,
    /// 是否启用启发式探测
    pub enable_heuristic: bool,
    /// 是否启用主动探测
    pub enable_active_probing: bool,
    /// 最大探测数据大小
    pub max_probe_size: usize,
    /// 最小探测数据大小
    pub min_probe_size: usize,
    /// 是否启用SIMD加速
    pub enable_simd: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            timeout: Duration::from_millis(1000),
            enable_heuristic: true,
            enable_active_probing: false,
            max_probe_size: 4096,
            min_probe_size: 16,  // 默认16字节，适合大多数协议
            enable_simd: true,
        }
    }
}

/// 协议代理实现 - 支持双向框架和多实例
#[derive(Debug)]
pub struct Agent {
    /// 代理配置
    config: AgentConfig,
    /// 协议探测器
    detector: Arc<dyn ProtocolDetector>,
    /// 协议升级器
    upgrader: Option<Arc<dyn crate::upgrade::ProtocolUpgrader>>,
    /// 实例状态
    state: Arc<std::sync::RwLock<AgentState>>,
    /// 负载均衡器（仅服务器模式）
    load_balancer: Option<Arc<LoadBalancer>>,
}

/// 代理状态
#[derive(Debug, Clone)]
pub struct AgentState {
    /// 活跃连接数
    pub active_connections: usize,
    /// 处理的总请求数
    pub total_requests: u64,
    /// 成功的协议升级数
    pub successful_upgrades: u64,
    /// 失败的协议升级数
    pub failed_upgrades: u64,
    /// 最后活动时间
    pub last_activity: Instant,
    /// 是否健康
    pub is_healthy: bool,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            active_connections: 0,
            total_requests: 0,
            successful_upgrades: 0,
            failed_upgrades: 0,
            last_activity: Instant::now(),
            is_healthy: true,
        }
    }
}

/// 负载均衡器
#[derive(Debug)]
pub struct LoadBalancer {
    /// 配置
    config: LoadBalancerConfig,
    /// 后端实例状态
    backends: Arc<std::sync::RwLock<HashMap<String, BackendState>>>,
    /// 当前轮询索引
    round_robin_index: Arc<std::sync::atomic::AtomicUsize>,
}

/// 后端实例状态
#[derive(Debug, Clone)]
pub struct BackendState {
    /// 实例ID
    pub instance_id: String,
    /// 活跃连接数
    pub active_connections: usize,
    /// 权重
    pub weight: u32,
    /// 是否健康
    pub is_healthy: bool,
    /// 最后健康检查时间
    pub last_health_check: Instant,
}

impl Agent {
    /// 创建新的协议代理
    pub fn new(
        config: AgentConfig,
        detector: Arc<dyn ProtocolDetector>,
        upgrader: Option<Arc<dyn crate::upgrade::ProtocolUpgrader>>,
    ) -> Self {
        let load_balancer = config.load_balancer_config.as_ref().map(|lb_config| {
            Arc::new(LoadBalancer::new(lb_config.clone()))
        });
        
        Self {
            config,
            detector,
            upgrader,
            state: Arc::new(std::sync::RwLock::new(AgentState::default())),
            load_balancer,
        }
    }
    
    /// 获取代理配置
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }
    
    /// 获取代理状态
    pub fn state(&self) -> Result<AgentState> {
        self.state.read()
            .map_err(|_| DetectorError::internal_error("Failed to read agent state"))
            .map(|state| state.clone())
    }
    
    /// 更新连接计数
    pub fn update_connection_count(&self, delta: i32) -> Result<()> {
        // 使用 try_write 避免阻塞，提高并发性能
        if let Ok(mut state) = self.state.try_write() {
            if delta > 0 {
                state.active_connections += delta as usize;
            } else {
                state.active_connections = state.active_connections.saturating_sub((-delta) as usize);
            }
            state.last_activity = Instant::now();
        } else {
            // 如果获取锁失败，记录警告但不阻塞
            zerg_creep::warn!("Failed to acquire lock for connection count update");
        }
        Ok(())
    }
    
    /// 选择后端实例（负载均衡）
    pub fn select_backend(&self) -> Option<String> {
        self.load_balancer.as_ref()?.select_backend()
    }
    
    /// 健康检查
    pub fn health_check(&self) -> bool {
        if let Ok(state) = self.state.read() {
            state.is_healthy && state.last_activity.elapsed() < Duration::from_secs(300)
        } else {
            false
        }
    }
}

impl LoadBalancer {
    /// 创建新的负载均衡器
    pub fn new(config: LoadBalancerConfig) -> Self {
        let backends = config.backend_instances.iter()
            .map(|instance_id| {
                let state = BackendState {
                    instance_id: instance_id.clone(),
                    active_connections: 0,
                    weight: 1,
                    is_healthy: true,
                    last_health_check: Instant::now(),
                };
                (instance_id.clone(), state)
            })
            .collect();
        
        Self {
            config,
            backends: Arc::new(std::sync::RwLock::new(backends)),
            round_robin_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
    
    /// 选择后端实例
    pub fn select_backend(&self) -> Option<String> {
        let backends = self.backends.read().ok()?;
        let healthy_backends: Vec<_> = backends.values()
            .filter(|backend| backend.is_healthy)
            .collect();
        
        if healthy_backends.is_empty() {
            return None;
        }
        
        match self.config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let index = self.round_robin_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(healthy_backends[index % healthy_backends.len()].instance_id.clone())
            },
            LoadBalanceStrategy::LeastConnections => {
                healthy_backends.iter()
                    .min_by_key(|backend| backend.active_connections)
                    .map(|backend| backend.instance_id.clone())
            },
            LoadBalanceStrategy::WeightedRoundRobin => {
                // 简化实现，后续可以优化
                let total_weight: u32 = healthy_backends.iter().map(|b| b.weight).sum();
                if total_weight == 0 {
                    return None;
                }
                
                let mut target = (self.round_robin_index.load(std::sync::atomic::Ordering::Relaxed) as u32) % total_weight;
                self.round_robin_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                
                for backend in healthy_backends {
                    if target < backend.weight {
                        return Some(backend.instance_id.clone());
                    }
                    target -= backend.weight;
                }
                None
            },
            LoadBalanceStrategy::ConsistentHash => {
                // 简化实现，使用第一个健康实例
                healthy_backends.first().map(|backend| backend.instance_id.clone())
            },
        }
    }
}

/// 为Agent实现ProtocolAgent trait
impl ProtocolAgent for Agent {
    /// 探测协议类型（被动模式 - 服务器角色）
    fn detect(&self, data: &[u8]) -> Result<DetectionResult> {
        // 更新请求计数
        if let Ok(mut state) = self.state.write() {
            state.total_requests += 1;
            state.last_activity = Instant::now();
        }
        
        // 根据角色选择探测策略
        match self.config.role {
            Role::Server => {
                // 服务器模式：被动探测传入数据
                self.detector.detect(data)
            },
            Role::Client => {
                // 客户端模式：通常不需要被动探测，但可以用于验证
                self.detector.detect(data)
            },
        }
    }
    
    /// 主动探测协议能力（客户端专用）
    fn probe_capabilities(&self, transport: &mut dyn Transport) -> Result<Vec<ProtocolType>> {
        match self.config.role {
            Role::Client => {
                // 更新请求计数
                if let Ok(mut state) = self.state.write() {
                    state.total_requests += 1;
                    state.last_activity = Instant::now();
                }
                
                self.active_probe(transport)
            },
            Role::Server => {
                Err(DetectorError::unsupported_protocol(
                    "Server role does not support active probing"
                ))
            },
        }
    }
    
    /// 主动探测实现（客户端专用）
    fn active_probe(&self, transport: &mut dyn Transport) -> Result<Vec<ProtocolType>> {
        let mut supported_protocols = Vec::new();
        
        // 只探测配置中启用的协议
        let probe_order = [
            ProtocolType::HTTP3,
            ProtocolType::HTTP2, 
            ProtocolType::HTTP1_1,
            ProtocolType::TLS,
            ProtocolType::QUIC,
        ];
        
        for protocol in probe_order {
            if self.config.enabled_protocols.contains(&protocol) {
                match self.send_protocol_probe(transport, protocol) {
                    Ok(true) => {
                        supported_protocols.push(protocol);
                        // 找到最高优先级协议后可以选择停止或继续探测
                        if matches!(protocol, ProtocolType::HTTP3 | ProtocolType::QUIC) {
                            break;
                        }
                    },
                    Ok(false) => continue,
                    Err(_) => continue, // 探测失败，继续下一个协议
                }
            }
        }
        
        if supported_protocols.is_empty() {
            // 保底协议
            supported_protocols.push(ProtocolType::HTTP1_1);
        }
        
        Ok(supported_protocols)
    }
    
    /// 发送特定协议的探测请求
    fn send_protocol_probe(&self, transport: &mut dyn Transport, protocol: ProtocolType) -> Result<bool> {
        match protocol {
            ProtocolType::HTTP2 => {
                // HTTP/2 连接前言探测
                let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                transport.write(h2_preface)?;
                
                // 读取响应
                let mut response = vec![0u8; 24];
                match transport.read(&mut response) {
                    Ok(n) if n > 0 => {
                        // 检查是否收到HTTP/2 SETTINGS帧
                        Ok(response.len() >= 9 && response[3] == 0x04) // SETTINGS帧类型
                    },
                    _ => Ok(false),
                }
            },
            ProtocolType::HTTP3 => {
                // HTTP/3 over QUIC探测
                // 这里需要QUIC握手逻辑，简化实现
                Ok(false) // 暂时返回false，需要完整的QUIC实现
            },
            ProtocolType::HTTP1_1 => {
                // HTTP/1.1 OPTIONS请求探测
                let options_request = b"OPTIONS * HTTP/1.1\r\nHost: probe\r\n\r\n";
                transport.write(options_request)?;
                
                let mut response = vec![0u8; 256];
                match transport.read(&mut response) {
                    Ok(n) if n > 0 => {
                        let response_str = String::from_utf8_lossy(&response[..n]);
                        Ok(response_str.starts_with("HTTP/1.1") || response_str.starts_with("HTTP/1.0"))
                    },
                    _ => Ok(false),
                }
            },
            ProtocolType::TLS => {
                // TLS ClientHello探测
                let client_hello = self.create_tls_client_hello();
                transport.write(&client_hello)?;
                
                let mut response = vec![0u8; 1024];
                match transport.read(&mut response) {
                    Ok(n) if n >= 5 => {
                        // 检查TLS ServerHello响应
                        Ok(response[0] == 0x16 && response[1] == 0x03) // TLS握手记录
                    },
                    _ => Ok(false),
                }
            },
            _ => Ok(false), // 其他协议暂不支持主动探测
        }
    }
    
    /// 创建TLS ClientHello消息
    fn create_tls_client_hello(&self) -> Vec<u8> {
        // 简化的TLS 1.2 ClientHello
        vec![
            0x16, 0x03, 0x01, 0x00, 0x2f, // TLS记录头
            0x01, 0x00, 0x00, 0x2b,       // 握手消息头
            0x03, 0x03,                   // TLS版本1.2
            // 32字节随机数（简化）
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,                         // 会话ID长度
            0x00, 0x02,                   // 密码套件长度
            0x00, 0x35,                   // AES128-SHA
            0x01, 0x00,                   // 压缩方法
        ]
    }
    
    /// 智能降级策略（客户端模式）
    fn auto_fallback(&self, transport: &mut dyn Transport, preferred: ProtocolType) -> Result<ProtocolType> {
        match self.config.role {
            Role::Client => {
                // 尝试首选协议
                if self.send_protocol_probe(transport, preferred)? {
                    return Ok(preferred);
                }
                
                // 自动降级
                let fallback_chain = match preferred {
                    ProtocolType::HTTP3 => vec![ProtocolType::HTTP2, ProtocolType::HTTP1_1],
                    ProtocolType::HTTP2 => vec![ProtocolType::HTTP1_1],
                    ProtocolType::QUIC => vec![ProtocolType::TLS, ProtocolType::TCP],
                    _ => vec![ProtocolType::HTTP1_1],
                };
                
                for fallback in fallback_chain {
                    if self.config.enabled_protocols.contains(&fallback) && 
                       self.send_protocol_probe(transport, fallback)? {
                        return Ok(fallback);
                    }
                }
                
                // 最终保底
                Ok(ProtocolType::HTTP1_1)
            },
            Role::Server => {
                Err(DetectorError::unsupported_protocol(
                    "Server role does not support auto fallback"
                ))
            },
        }
    }
    
    /// 协议升级（主动/被动模式）
    fn upgrade(
        &self,
        transport: Box<dyn Transport>,
        role: Role,
    ) -> Result<Box<dyn Transport>> {
        match &self.upgrader {
            Some(upgrader) => {
                let result = match role {
                    Role::Server => {
                        // 服务器模式：响应客户端的升级请求
                        let current_protocol = ProtocolType::HTTP1_1; // 当前协议
                         let target_protocol = ProtocolType::HTTP2; // 目标协议
                        let data = b""; // 升级数据
                        upgrader.upgrade(current_protocol, target_protocol, data)
                    },
                    Role::Client => {
                        // 客户端模式：发起协议升级请求
                        let current_protocol = ProtocolType::HTTP1_1; // 当前协议
                        let target_protocol = ProtocolType::HTTP2; // 目标协议
                        let data = b""; // 升级数据
                        upgrader.upgrade(current_protocol, target_protocol, data)
                    },
                };
                
                // 更新升级统计
                if let Ok(mut state) = self.state.write() {
                    match result {
                        Ok(_) => state.successful_upgrades += 1,
                        Err(_) => state.failed_upgrades += 1,
                    }
                    state.last_activity = Instant::now();
                }
                
                result.map(|_| transport) // 简化实现，实际应返回升级后的transport
            },
            None => Err(DetectorError::unsupported_protocol("Protocol upgrade not supported")),
        }
    }
    
    /// 检查是否支持指定协议
    fn supports_protocol(&self, protocol: ProtocolType) -> bool {
        self.config.enabled_protocols.contains(&protocol)
    }
    
    /// 获取代理角色
    fn role(&self) -> Role {
        self.config.role
    }
    
    /// 获取实例ID
    fn instance_id(&self) -> &str {
        &self.config.instance_id
    }
    
    /// 获取代理名称
    fn name(&self) -> &str {
        match self.config.role {
            Role::Server => "PSI Server Agent",
            Role::Client => "PSI Client Agent",
        }
    }
}

impl DetectionConfig {
    /// 创建新的探测配置
    pub fn new() -> Self {
        Self::default()
    }
    
    /// 设置最小置信度
    pub fn with_min_confidence(mut self, confidence: f32) -> Self {
        self.min_confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// 启用启发式探测
    pub fn enable_heuristic(mut self) -> Self {
        self.enable_heuristic = true;
        self
    }
    
    /// 禁用启发式探测
    pub fn disable_heuristic(mut self) -> Self {
        self.enable_heuristic = false;
        self
    }
    
    /// 启用主动探测
    pub fn enable_active_probing(mut self) -> Self {
        self.enable_active_probing = true;
        self
    }
    
    /// 禁用主动探测
    pub fn disable_active_probing(mut self) -> Self {
        self.enable_active_probing = false;
        self
    }
    
    /// 设置最大探测数据大小
    pub fn with_max_probe_size(mut self, size: usize) -> Self {
        self.max_probe_size = size;
        self
    }
    
    /// 设置最小探测数据大小
    pub fn with_min_probe_size(mut self, size: usize) -> Self {
        self.min_probe_size = size;
        self
    }
    
    /// 启用SIMD加速
    pub fn enable_simd(mut self) -> Self {
        self.enable_simd = true;
        self
    }
    
    /// 禁用SIMD加速
    pub fn disable_simd(mut self) -> Self {
        self.enable_simd = false;
        self
    }
}

/// 探测统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionStats {
    /// 总探测次数
    pub total_detections: u64,
    /// 成功探测次数
    pub successful_detections: u64,
    /// 失败探测次数
    pub failed_detections: u64,
    /// 平均探测时间
    pub avg_detection_time: Duration,
    /// 各协议探测次数
    pub protocol_counts: std::collections::HashMap<ProtocolType, u64>,
}

impl DetectionStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self::default()
    }
    
    /// 记录成功探测
    pub fn record_success(&mut self, protocol: ProtocolType, duration: Duration) {
        self.total_detections += 1;
        self.successful_detections += 1;
        self.update_avg_time(duration);
        *self.protocol_counts.entry(protocol).or_insert(0) += 1;
    }
    
    /// 记录失败探测
    pub fn record_failure(&mut self, duration: Duration) {
        self.total_detections += 1;
        self.failed_detections += 1;
        self.update_avg_time(duration);
    }
    
    /// 获取成功率
    pub fn success_rate(&self) -> f64 {
        if self.total_detections == 0 {
            0.0
        } else {
            self.successful_detections as f64 / self.total_detections as f64
        }
    }
    
    /// 获取最常见的协议
    pub fn most_common_protocol(&self) -> Option<ProtocolType> {
        self.protocol_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(protocol, _)| *protocol)
    }
    
    fn update_avg_time(&mut self, new_duration: Duration) {
        if self.total_detections == 1 {
            self.avg_detection_time = new_duration;
        } else {
            let total_nanos = self.avg_detection_time.as_nanos() * (self.total_detections - 1) as u128
                + new_duration.as_nanos();
            self.avg_detection_time = Duration::from_nanos((total_nanos / self.total_detections as u128) as u64);
        }
    }
}