//! 流处理模块
//!
//! 提供流式协议探测和数据处理功能。

use crate::core::detector::{DetectionResult, ProtocolDetector};
use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub mod buffer;
pub mod processor;
pub mod analyzer;

// 重导出主要类型
pub use buffer::{StreamBuffer, BufferConfig};
pub use processor::{StreamProcessor, ProcessorConfig};
pub use analyzer::{StreamAnalyzer, AnalysisResult};

/// 流状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// 初始状态
    Initial,
    /// 正在探测
    Detecting,
    /// 探测完成
    Detected(ProtocolType),
    /// 探测失败
    Failed(String),
    /// 流已关闭
    Closed,
}

/// 流方向
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDirection {
    /// 入站流量
    Inbound,
    /// 出站流量
    Outbound,
    /// 双向流量
    Bidirectional,
}

/// 流元数据
#[derive(Debug, Clone)]
pub struct StreamMetadata {
    /// 流ID
    pub stream_id: String,
    /// 源地址
    pub source_addr: Option<String>,
    /// 目标地址
    pub dest_addr: Option<String>,
    /// 流方向
    pub direction: StreamDirection,
    /// 创建时间
    pub created_at: Instant,
    /// 最后活动时间
    pub last_activity: Instant,
    /// 总字节数
    pub total_bytes: usize,
    /// 数据包数量
    pub packet_count: usize,
    /// 自定义属性
    pub attributes: std::collections::HashMap<String, String>,
}

impl StreamMetadata {
    /// 创建新的流元数据
    pub fn new(stream_id: String, direction: StreamDirection) -> Self {
        let now = Instant::now();
        Self {
            stream_id,
            source_addr: None,
            dest_addr: None,
            direction,
            created_at: now,
            last_activity: now,
            total_bytes: 0,
            packet_count: 0,
            attributes: std::collections::HashMap::new(),
        }
    }
    
    /// 设置源地址
    pub fn with_source_addr(mut self, addr: String) -> Self {
        self.source_addr = Some(addr);
        self
    }
    
    /// 设置目标地址
    pub fn with_dest_addr(mut self, addr: String) -> Self {
        self.dest_addr = Some(addr);
        self
    }
    
    /// 添加属性
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.insert(key, value);
        self
    }
    
    /// 更新活动时间
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// 添加字节数
    pub fn add_bytes(&mut self, bytes: usize) {
        self.total_bytes += bytes;
        self.packet_count += 1;
        self.update_activity();
    }
    
    /// 获取流持续时间
    pub fn duration(&self) -> Duration {
        self.last_activity.duration_since(self.created_at)
    }
    
    /// 获取平均包大小
    pub fn average_packet_size(&self) -> f64 {
        if self.packet_count == 0 {
            0.0
        } else {
            self.total_bytes as f64 / self.packet_count as f64
        }
    }
}

/// 流事件
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// 数据到达
    DataReceived {
        /// 接收到的数据
        data: Vec<u8>,
        /// 时间戳
        timestamp: Instant,
    },
    /// 协议探测完成
    ProtocolDetected {
        /// 探测到的协议类型
        protocol: ProtocolType,
        /// 置信度
        confidence: f64,
        /// 时间戳
        timestamp: Instant,
    },
    /// 探测失败
    DetectionFailed {
        /// 错误信息
        error: String,
        /// 时间戳
        timestamp: Instant,
    },
    /// 流关闭
    StreamClosed {
        /// 时间戳
        timestamp: Instant,
    },
    /// 缓冲区满
    BufferFull {
        /// 缓冲区大小
        size: usize,
        /// 时间戳
        timestamp: Instant,
    },
    /// 超时
    Timeout {
        /// 超时持续时间
        duration: Duration,
        /// 时间戳
        timestamp: Instant,
    },
}

/// 流事件处理器
pub trait StreamEventHandler {
    /// 处理流事件
    fn handle_event(&mut self, event: StreamEvent) -> Result<()>;
}

/// 流配置
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// 最大缓冲区大小
    pub max_buffer_size: usize,
    /// 探测超时
    pub detection_timeout: Duration,
    /// 最小探测数据大小
    pub min_detection_size: usize,
    /// 最大探测数据大小
    pub max_detection_size: usize,
    /// 是否启用流分析
    pub enable_analysis: bool,
    /// 是否保留原始数据
    pub keep_raw_data: bool,
    /// 事件队列大小
    pub event_queue_size: usize,
    /// 是否启用统计
    pub enable_stats: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 64 * 1024,      // 64KB
            detection_timeout: Duration::from_secs(30),
            min_detection_size: 16,
            max_detection_size: 8 * 1024,    // 8KB
            enable_analysis: true,
            keep_raw_data: false,
            event_queue_size: 1000,
            enable_stats: true,
        }
    }
}

/// 流统计信息
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    /// 处理的流数量
    pub streams_processed: usize,
    /// 成功探测的流数量
    pub successful_detections: usize,
    /// 失败的探测数量
    pub failed_detections: usize,
    /// 超时的流数量
    pub timeouts: usize,
    /// 总处理字节数
    pub total_bytes_processed: usize,
    /// 平均探测时间
    pub average_detection_time: Duration,
    /// 各协议探测次数
    pub protocol_counts: std::collections::HashMap<ProtocolType, usize>,
    /// 错误计数
    pub error_counts: std::collections::HashMap<String, usize>,
}

impl StreamStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self::default()
    }
    
    /// 记录成功探测
    pub fn record_successful_detection(&mut self, protocol: ProtocolType, duration: Duration) {
        self.successful_detections += 1;
        *self.protocol_counts.entry(protocol).or_insert(0) += 1;
        self.update_average_time(duration);
    }
    
    /// 记录失败探测
    pub fn record_failed_detection(&mut self, error: &str) {
        self.failed_detections += 1;
        *self.error_counts.entry(error.to_string()).or_insert(0) += 1;
    }
    
    /// 记录超时
    pub fn record_timeout(&mut self) {
        self.timeouts += 1;
    }
    
    /// 记录处理的字节数
    pub fn record_bytes_processed(&mut self, bytes: usize) {
        self.total_bytes_processed += bytes;
    }
    
    /// 记录新流
    pub fn record_new_stream(&mut self) {
        self.streams_processed += 1;
    }
    
    /// 更新平均探测时间
    fn update_average_time(&mut self, duration: Duration) {
        let total_detections = self.successful_detections;
        if total_detections == 1 {
            self.average_detection_time = duration;
        } else {
            let current_total = self.average_detection_time.as_nanos() * (total_detections - 1) as u128;
            let new_total = current_total + duration.as_nanos();
            self.average_detection_time = Duration::from_nanos((new_total / total_detections as u128) as u64);
        }
    }
    
    /// 获取成功率
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_detections + self.failed_detections;
        if total == 0 {
            0.0
        } else {
            self.successful_detections as f64 / total as f64
        }
    }
    
    /// 获取超时率
    pub fn timeout_rate(&self) -> f64 {
        if self.streams_processed == 0 {
            0.0
        } else {
            self.timeouts as f64 / self.streams_processed as f64
        }
    }
    
    /// 获取最常见的协议
    pub fn most_common_protocol(&self) -> Option<ProtocolType> {
        self.protocol_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(protocol, _)| *protocol)
    }
    
    /// 获取最常见的错误
    pub fn most_common_error(&self) -> Option<String> {
        self.error_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(error, _)| error.clone())
    }
    
    /// 重置统计信息
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// 流管理器
pub struct StreamManager {
    /// 活动流
    active_streams: std::collections::HashMap<String, StreamMetadata>,
    /// 配置
    config: StreamConfig,
    /// 统计信息
    stats: StreamStats,
    /// 事件队列
    event_queue: VecDeque<StreamEvent>,
    /// 事件处理器
    event_handlers: Vec<Box<dyn StreamEventHandler>>,
}

impl StreamManager {
    /// 创建新的流管理器
    pub fn new(config: StreamConfig) -> Self {
        Self {
            active_streams: std::collections::HashMap::new(),
            config,
            stats: StreamStats::new(),
            event_queue: VecDeque::with_capacity(1000),
            event_handlers: Vec::new(),
        }
    }
    
    /// 添加事件处理器
    pub fn add_event_handler(&mut self, handler: Box<dyn StreamEventHandler>) {
        self.event_handlers.push(handler);
    }
    
    /// 创建新流
    pub fn create_stream(&mut self, stream_id: String, direction: StreamDirection) -> Result<()> {
        let metadata = StreamMetadata::new(stream_id.clone(), direction);
        self.active_streams.insert(stream_id, metadata);
        self.stats.record_new_stream();
        Ok(())
    }
    
    /// 获取流元数据
    pub fn get_stream(&self, stream_id: &str) -> Option<&StreamMetadata> {
        self.active_streams.get(stream_id)
    }
    
    /// 获取可变流元数据
    pub fn get_stream_mut(&mut self, stream_id: &str) -> Option<&mut StreamMetadata> {
        self.active_streams.get_mut(stream_id)
    }
    
    /// 关闭流
    pub fn close_stream(&mut self, stream_id: &str) -> Result<()> {
        if self.active_streams.remove(stream_id).is_some() {
            let event = StreamEvent::StreamClosed {
                timestamp: Instant::now(),
            };
            self.emit_event(event)?;
        }
        Ok(())
    }
    
    /// 发送事件
    pub fn emit_event(&mut self, event: StreamEvent) -> Result<()> {
        // 添加到事件队列
        if self.event_queue.len() >= self.config.event_queue_size {
            self.event_queue.pop_front();
        }
        self.event_queue.push_back(event.clone());
        
        // 通知事件处理器
        for handler in &mut self.event_handlers {
            handler.handle_event(event.clone())?;
        }
        
        Ok(())
    }
    
    /// 处理超时流
    pub fn handle_timeouts(&mut self) -> Result<()> {
        let now = Instant::now();
        let timeout_duration = self.config.detection_timeout;
        
        let mut timed_out_streams = Vec::new();
        
        for (stream_id, metadata) in &self.active_streams {
            if now.duration_since(metadata.last_activity) > timeout_duration {
                timed_out_streams.push(stream_id.clone());
            }
        }
        
        for stream_id in timed_out_streams {
            self.stats.record_timeout();
            
            let event = StreamEvent::Timeout {
                duration: timeout_duration,
                timestamp: now,
            };
            self.emit_event(event)?;
            
            self.close_stream(&stream_id)?;
        }
        
        Ok(())
    }
    
    /// 获取活动流数量
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }
    
    /// 获取统计信息
    pub fn stats(&self) -> &StreamStats {
        &self.stats
    }
    
    /// 获取可变统计信息
    pub fn stats_mut(&mut self) -> &mut StreamStats {
        &mut self.stats
    }
    
    /// 获取配置
    pub fn config(&self) -> &StreamConfig {
        &self.config
    }
    
    /// 更新配置
    pub fn update_config(&mut self, config: StreamConfig) {
        self.config = config;
    }
    
    /// 清理资源
    pub fn cleanup(&mut self) {
        self.active_streams.clear();
        self.event_queue.clear();
        self.stats.reset();
    }
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new(StreamConfig::default())
    }
}