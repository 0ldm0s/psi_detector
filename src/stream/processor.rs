//! 流处理器模块
//!
//! 提供流式协议探测和数据处理功能。

use crate::core::detector::{DetectionConfig, DetectionResult, ProtocolDetector};
use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};
use crate::stream::buffer::{StreamBuffer, BufferConfig};
use crate::stream::{StreamEvent, StreamMetadata, StreamState};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 处理器配置
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// 缓冲区配置
    pub buffer_config: BufferConfig,
    /// 探测配置
    pub detection_config: DetectionConfig,
    /// 最大并发流数量
    pub max_concurrent_streams: usize,
    /// 流超时时间
    pub stream_timeout: Duration,
    /// 探测间隔
    pub detection_interval: Duration,
    /// 最小探测数据大小
    pub min_detection_size: usize,
    /// 最大探测尝试次数
    pub max_detection_attempts: usize,
    /// 是否启用增量探测
    pub enable_incremental_detection: bool,
    /// 是否保留探测历史
    pub keep_detection_history: bool,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            buffer_config: BufferConfig::default(),
            detection_config: DetectionConfig::default(),
            max_concurrent_streams: 1000,
            stream_timeout: Duration::from_secs(300), // 5分钟
            detection_interval: Duration::from_millis(100),
            min_detection_size: 64,
            max_detection_attempts: 5,
            enable_incremental_detection: true,
            keep_detection_history: false,
        }
    }
}

/// 流上下文
#[derive(Debug)]
struct StreamContext {
    /// 流元数据
    metadata: StreamMetadata,
    /// 流状态
    state: StreamState,
    /// 数据缓冲区
    buffer: StreamBuffer,
    /// 探测历史
    detection_history: Vec<DetectionResult>,
    /// 探测尝试次数
    detection_attempts: usize,
    /// 最后探测时间
    last_detection: Option<Instant>,
    /// 最后活动时间
    last_activity: Instant,
}

impl StreamContext {
    fn new(metadata: StreamMetadata, buffer_config: BufferConfig) -> Self {
        Self {
            metadata,
            state: StreamState::Initial,
            buffer: StreamBuffer::new(buffer_config),
            detection_history: Vec::new(),
            detection_attempts: 0,
            last_detection: None,
            last_activity: Instant::now(),
        }
    }
    
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
        self.metadata.update_activity();
    }
    
    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
    
    fn should_detect(&self, interval: Duration, min_size: usize) -> bool {
        // 检查状态
        if matches!(self.state, StreamState::Detected(_) | StreamState::Failed(_) | StreamState::Closed) {
            return false;
        }
        
        // 检查缓冲区大小
        if self.buffer.size() < min_size {
            return false;
        }
        
        // 检查探测间隔
        if let Some(last_detection) = self.last_detection {
            if last_detection.elapsed() < interval {
                return false;
            }
        }
        
        true
    }
}

/// 流处理器
#[derive(Debug)]
pub struct StreamProcessor {
    /// 配置
    config: ProcessorConfig,
    /// 活动流上下文
    streams: HashMap<String, StreamContext>,
    /// 协议探测器
    detector: Box<dyn ProtocolDetector>,
    /// 处理统计
    stats: ProcessorStats,
}

/// 处理器统计信息
#[derive(Debug, Clone, Default)]
pub struct ProcessorStats {
    /// 处理的流总数
    pub total_streams: usize,
    /// 当前活动流数
    pub active_streams: usize,
    /// 成功探测数
    pub successful_detections: usize,
    /// 失败探测数
    pub failed_detections: usize,
    /// 超时流数
    pub timed_out_streams: usize,
    /// 总处理字节数
    pub total_bytes_processed: usize,
    /// 平均探测时间
    pub average_detection_time: Duration,
    /// 各协议探测统计
    pub protocol_stats: HashMap<ProtocolType, usize>,
    /// 错误统计
    pub error_stats: HashMap<String, usize>,
}

impl ProcessorStats {
    fn record_new_stream(&mut self) {
        self.total_streams += 1;
        self.active_streams += 1;
    }
    
    fn record_stream_closed(&mut self) {
        if self.active_streams > 0 {
            self.active_streams -= 1;
        }
    }
    
    fn record_successful_detection(&mut self, protocol: ProtocolType, duration: Duration) {
        self.successful_detections += 1;
        *self.protocol_stats.entry(protocol).or_insert(0) += 1;
        self.update_average_detection_time(duration);
    }
    
    fn record_failed_detection(&mut self, error: &str) {
        self.failed_detections += 1;
        *self.error_stats.entry(error.to_string()).or_insert(0) += 1;
    }
    
    fn record_timeout(&mut self) {
        self.timed_out_streams += 1;
    }
    
    fn record_bytes_processed(&mut self, bytes: usize) {
        self.total_bytes_processed += bytes;
    }
    
    fn update_average_detection_time(&mut self, duration: Duration) {
        let total_detections = self.successful_detections;
        if total_detections == 1 {
            self.average_detection_time = duration;
        } else {
            let current_total = self.average_detection_time.as_nanos() * (total_detections - 1) as u128;
            let new_total = current_total + duration.as_nanos();
            self.average_detection_time = Duration::from_nanos((new_total / total_detections as u128) as u64);
        }
    }
}

impl StreamProcessor {
    /// 创建新的流处理器
    pub fn new(config: ProcessorConfig, detector: Box<dyn ProtocolDetector>) -> Self {
        Self {
            config,
            streams: HashMap::new(),
            detector,
            stats: ProcessorStats::default(),
        }
    }
    
    /// 创建新流
    pub fn create_stream(&mut self, metadata: StreamMetadata) -> Result<()> {
        let stream_id = metadata.stream_id.clone();
        
        // 检查并发限制
        if self.streams.len() >= self.config.max_concurrent_streams {
            return Err(DetectorError::config_error(
                "Maximum concurrent streams exceeded".to_string()
            ));
        }
        
        // 创建流上下文
        let context = StreamContext::new(metadata, self.config.buffer_config.clone());
        self.streams.insert(stream_id, context);
        
        self.stats.record_new_stream();
        Ok(())
    }
    
    /// 处理流数据
    pub fn process_data(&mut self, stream_id: &str, data: Vec<u8>) -> Result<Vec<StreamEvent>> {
        let mut events = Vec::new();
        
        // 获取流上下文
        let context = self.streams.get_mut(stream_id)
            .ok_or_else(|| DetectorError::config_error(
                format!("Stream not found: {}", stream_id)
            ))?;
        
        // 更新活动时间
        context.update_activity();
        
        // 添加数据到缓冲区
        let data_size = data.len();
        context.buffer.push(data)?;
        context.metadata.add_bytes(data_size);
        self.stats.record_bytes_processed(data_size);
        
        // 发送数据接收事件
        events.push(StreamEvent::DataReceived {
            data: context.buffer.peek(data_size),
            timestamp: Instant::now(),
        });
        
        // 检查是否需要探测
        let should_detect = context.should_detect(
            self.config.detection_interval,
            self.config.min_detection_size,
        );
        
        // 检查缓冲区是否已满
        let buffer_full = context.buffer.is_full();
        let buffer_size = context.buffer.size();
        
        // 释放对context的借用
        drop(context);
        
        // 尝试协议探测
        if should_detect {
            if let Some(detection_event) = self.attempt_detection(stream_id)? {
                events.push(detection_event);
            }
        }
        
        // 检查缓冲区是否已满
        if buffer_full {
            events.push(StreamEvent::BufferFull {
                size: buffer_size,
                timestamp: Instant::now(),
            });
        }
        
        Ok(events)
    }
    
    /// 尝试协议探测
    fn attempt_detection(&mut self, stream_id: &str) -> Result<Option<StreamEvent>> {
        let context = self.streams.get_mut(stream_id)
            .ok_or_else(|| DetectorError::config_error(
                format!("Stream not found: {}", stream_id)
            ))?;
        
        // 检查探测尝试次数
        if context.detection_attempts >= self.config.max_detection_attempts {
            context.state = StreamState::Failed("Max detection attempts exceeded".to_string());
            self.stats.record_failed_detection("max_attempts_exceeded");
            
            return Ok(Some(StreamEvent::DetectionFailed {
                error: "Maximum detection attempts exceeded".to_string(),
                timestamp: Instant::now(),
            }));
        }
        
        // 获取探测数据
        let detection_size = std::cmp::min(
            context.buffer.size(),
            self.config.detection_config.max_probe_size
        );
        
        if detection_size < self.config.min_detection_size {
            return Ok(None);
        }
        
        let data = context.buffer.peek(detection_size);
        
        // 执行协议探测
        context.detection_attempts += 1;
        context.last_detection = Some(Instant::now());
        context.state = StreamState::Detecting;
        
        let start_time = Instant::now();
        match self.detector.detect(&data) {
            Ok(result) => {
                let detection_time = start_time.elapsed();
                
                // 检查置信度
                if result.protocol_info.confidence >= self.config.detection_config.min_confidence {
                    // 探测成功
                    context.state = StreamState::Detected(result.protocol_info.protocol_type);
                    
                    if self.config.keep_detection_history {
                        context.detection_history.push(result.clone());
                    }
                    
                    self.stats.record_successful_detection(
                        result.protocol_info.protocol_type,
                        detection_time,
                    );
                    
                    Ok(Some(StreamEvent::ProtocolDetected {
                        protocol: result.protocol_info.protocol_type,
                        confidence: result.protocol_info.confidence as f64,
                        timestamp: Instant::now(),
                    }))
                } else {
                    // 置信度不够，继续等待更多数据
                    context.state = StreamState::Initial;
                    
                    if self.config.keep_detection_history {
                        context.detection_history.push(result);
                    }
                    
                    Ok(None)
                }
            }
            Err(err) => {
                // 探测失败
                let error_msg = err.to_string();
                context.state = StreamState::Failed(error_msg.clone());
                self.stats.record_failed_detection(&error_msg);
                
                Ok(Some(StreamEvent::DetectionFailed {
                    error: error_msg,
                    timestamp: Instant::now(),
                }))
            }
        }
    }
    
    /// 获取流状态
    pub fn get_stream_state(&self, stream_id: &str) -> Option<&StreamState> {
        self.streams.get(stream_id).map(|ctx| &ctx.state)
    }
    
    /// 获取流元数据
    pub fn get_stream_metadata(&self, stream_id: &str) -> Option<&StreamMetadata> {
        self.streams.get(stream_id).map(|ctx| &ctx.metadata)
    }
    
    /// 获取流缓冲区大小
    pub fn get_buffer_size(&self, stream_id: &str) -> Option<usize> {
        self.streams.get(stream_id).map(|ctx| ctx.buffer.size())
    }
    
    /// 获取流探测历史
    pub fn get_detection_history(&self, stream_id: &str) -> Option<&[DetectionResult]> {
        self.streams.get(stream_id).map(|ctx| ctx.detection_history.as_slice())
    }
    
    /// 关闭流
    pub fn close_stream(&mut self, stream_id: &str) -> Result<()> {
        if let Some(mut context) = self.streams.remove(stream_id) {
            context.state = StreamState::Closed;
            self.stats.record_stream_closed();
        }
        Ok(())
    }
    
    /// 处理超时流
    pub fn handle_timeouts(&mut self) -> Result<Vec<StreamEvent>> {
        let mut events = Vec::new();
        let mut timed_out_streams = Vec::new();
        
        // 查找超时的流
        for (stream_id, context) in &self.streams {
            if context.is_expired(self.config.stream_timeout) {
                timed_out_streams.push(stream_id.clone());
            }
        }
        
        // 处理超时流
        for stream_id in timed_out_streams {
            self.stats.record_timeout();
            
            events.push(StreamEvent::Timeout {
                duration: self.config.stream_timeout,
                timestamp: Instant::now(),
            });
            
            self.close_stream(&stream_id)?;
        }
        
        Ok(events)
    }
    
    /// 获取活动流列表
    pub fn get_active_streams(&self) -> Vec<&str> {
        self.streams.keys().map(|s| s.as_str()).collect()
    }
    
    /// 获取统计信息
    pub fn stats(&self) -> &ProcessorStats {
        &self.stats
    }
    
    /// 获取配置
    pub fn config(&self) -> &ProcessorConfig {
        &self.config
    }
    
    /// 更新配置
    pub fn update_config(&mut self, config: ProcessorConfig) {
        self.config = config;
    }
    
    /// 清理资源
    pub fn cleanup(&mut self) {
        self.streams.clear();
        self.stats = ProcessorStats::default();
    }
    
    /// 强制探测流
    pub fn force_detection(&mut self, stream_id: &str) -> Result<Option<StreamEvent>> {
        // 临时重置探测间隔检查
        if let Some(context) = self.streams.get_mut(stream_id) {
            context.last_detection = None;
        }
        
        self.attempt_detection(stream_id)
    }
    
    /// 获取流数据
    pub fn get_stream_data(&self, stream_id: &str, size: usize) -> Option<Vec<u8>> {
        self.streams.get(stream_id).map(|ctx| ctx.buffer.peek(size))
    }
    
    /// 消费流数据
    pub fn consume_stream_data(&mut self, stream_id: &str, size: usize) -> Option<Vec<u8>> {
        self.streams.get_mut(stream_id).map(|ctx| ctx.buffer.pop(size))
    }
    
    /// 获取处理器负载
    pub fn load(&self) -> f64 {
        if self.config.max_concurrent_streams == 0 {
            0.0
        } else {
            self.streams.len() as f64 / self.config.max_concurrent_streams as f64
        }
    }
    
    /// 获取成功率
    pub fn success_rate(&self) -> f64 {
        let total = self.stats.successful_detections + self.stats.failed_detections;
        if total == 0 {
            0.0
        } else {
            self.stats.successful_detections as f64 / total as f64
        }
    }
}