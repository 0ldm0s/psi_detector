//! 流分析器模块
//!
//! 提供流数据的深度分析和特征提取功能。

use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 分析结果
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// 流ID
    pub stream_id: String,
    /// 分析时间戳
    pub timestamp: Instant,
    /// 流特征
    pub features: StreamFeatures,
    /// 行为模式
    pub patterns: Vec<BehaviorPattern>,
    /// 异常检测结果
    pub anomalies: Vec<Anomaly>,
    /// 性能指标
    pub performance: PerformanceMetrics,
    /// 置信度
    pub confidence: f64,
}

/// 流特征
#[derive(Debug, Clone, Default)]
pub struct StreamFeatures {
    /// 数据包大小分布
    pub packet_size_distribution: PacketSizeDistribution,
    /// 时间间隔分布
    pub timing_distribution: TimingDistribution,
    /// 字节频率分析
    pub byte_frequency: ByteFrequency,
    /// 熵值
    pub entropy: f64,
    /// 压缩率
    pub compression_ratio: f64,
    /// 周期性特征
    pub periodicity: PeriodicityFeatures,
    /// 协议特征
    pub protocol_features: ProtocolFeatures,
}

/// 数据包大小分布
#[derive(Debug, Clone, Default)]
pub struct PacketSizeDistribution {
    /// 最小包大小
    pub min_size: usize,
    /// 最大包大小
    pub max_size: usize,
    /// 平均包大小
    pub mean_size: f64,
    /// 标准差
    pub std_dev: f64,
    /// 中位数
    pub median: usize,
    /// 大小直方图
    pub histogram: HashMap<usize, usize>,
}

/// 时间间隔分布
#[derive(Debug, Clone, Default)]
pub struct TimingDistribution {
    /// 最小间隔
    pub min_interval: Duration,
    /// 最大间隔
    pub max_interval: Duration,
    /// 平均间隔
    pub mean_interval: Duration,
    /// 标准差
    pub std_dev: Duration,
    /// 间隔直方图
    pub histogram: HashMap<u64, usize>, // 毫秒为单位
}

/// 字节频率分析
#[derive(Debug, Clone)]
pub struct ByteFrequency {
    /// 字节频率表
    pub frequencies: [usize; 256],
    /// 最常见字节
    pub most_common: u8,
    /// 最少见字节
    pub least_common: u8,
    /// 唯一字节数
    pub unique_bytes: usize,
}

impl Default for ByteFrequency {
    fn default() -> Self {
        Self {
            frequencies: [0; 256],
            most_common: 0,
            least_common: 0,
            unique_bytes: 0,
        }
    }
}

/// 周期性特征
#[derive(Debug, Clone, Default)]
pub struct PeriodicityFeatures {
    /// 是否检测到周期性
    pub has_periodicity: bool,
    /// 周期长度
    pub period_length: Option<Duration>,
    /// 周期强度
    pub period_strength: f64,
    /// 周期偏差
    pub period_variance: f64,
}

/// 协议特征
#[derive(Debug, Clone, Default)]
pub struct ProtocolFeatures {
    /// 检测到的协议类型
    pub detected_protocols: Vec<ProtocolType>,
    /// 协议置信度
    pub protocol_confidence: HashMap<ProtocolType, f64>,
    /// 协议特征向量
    pub feature_vector: Vec<f64>,
    /// 协议签名
    pub signatures: Vec<String>,
}

/// 行为模式
#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    /// 模式类型
    pub pattern_type: PatternType,
    /// 模式描述
    pub description: String,
    /// 置信度
    pub confidence: f64,
    /// 开始时间
    pub start_time: Instant,
    /// 持续时间
    pub duration: Duration,
    /// 相关数据
    pub metadata: HashMap<String, String>,
}

/// 模式类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternType {
    /// 突发流量
    BurstTraffic,
    /// 周期性流量
    PeriodicTraffic,
    /// 渐增流量
    GradualIncrease,
    /// 渐减流量
    GradualDecrease,
    /// 空闲期
    IdlePeriod,
    /// 异常峰值
    AnomalousSpike,
    /// 协议切换
    ProtocolSwitch,
    /// 加密流量
    EncryptedTraffic,
    /// 压缩流量
    CompressedTraffic,
    /// 自定义模式
    Custom(String),
}

/// 异常检测结果
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// 异常类型
    pub anomaly_type: AnomalyType,
    /// 严重程度
    pub severity: AnomalySeverity,
    /// 描述
    pub description: String,
    /// 检测时间
    pub detected_at: Instant,
    /// 异常值
    pub value: f64,
    /// 期望值
    pub expected_value: f64,
    /// 偏差程度
    pub deviation: f64,
}

/// 异常类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyType {
    /// 大小异常
    SizeAnomaly,
    /// 时间异常
    TimingAnomaly,
    /// 频率异常
    FrequencyAnomaly,
    /// 熵值异常
    EntropyAnomaly,
    /// 模式异常
    PatternAnomaly,
    /// 协议异常
    ProtocolAnomaly,
}

/// 异常严重程度
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    /// 低
    Low,
    /// 中
    Medium,
    /// 高
    High,
    /// 严重
    Critical,
}

/// 性能指标
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    /// 吞吐量（字节/秒）
    pub throughput: f64,
    /// 延迟
    pub latency: Duration,
    /// 抖动
    pub jitter: Duration,
    /// 丢包率
    pub packet_loss_rate: f64,
    /// 带宽利用率
    pub bandwidth_utilization: f64,
    /// 连接质量评分
    pub quality_score: f64,
}

/// 分析器配置
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// 分析窗口大小
    pub window_size: Duration,
    /// 最小样本数
    pub min_samples: usize,
    /// 异常检测阈值
    pub anomaly_threshold: f64,
    /// 是否启用深度分析
    pub enable_deep_analysis: bool,
    /// 是否启用模式检测
    pub enable_pattern_detection: bool,
    /// 是否启用异常检测
    pub enable_anomaly_detection: bool,
    /// 历史数据保留时间
    pub history_retention: Duration,
    /// 分析间隔
    pub analysis_interval: Duration,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            window_size: Duration::from_secs(60),
            min_samples: 10,
            anomaly_threshold: 2.0, // 2个标准差
            enable_deep_analysis: true,
            enable_pattern_detection: true,
            enable_anomaly_detection: true,
            history_retention: Duration::from_secs(3600), // 1小时
            analysis_interval: Duration::from_secs(10),
        }
    }
}

/// 流分析器
#[derive(Debug)]
pub struct StreamAnalyzer {
    /// 配置
    config: AnalyzerConfig,
    /// 历史数据
    history: HashMap<String, StreamHistory>,
    /// 分析统计
    stats: AnalyzerStats,
}

/// 流历史数据
#[derive(Debug)]
struct StreamHistory {
    /// 数据点
    data_points: Vec<DataPoint>,
    /// 最后分析时间
    last_analysis: Option<Instant>,
    /// 累积特征
    accumulated_features: StreamFeatures,
}

/// 数据点
#[derive(Debug, Clone)]
struct DataPoint {
    /// 时间戳
    timestamp: Instant,
    /// 数据大小
    size: usize,
    /// 数据内容（采样）
    sample: Vec<u8>,
}

/// 分析器统计
#[derive(Debug, Clone, Default)]
pub struct AnalyzerStats {
    /// 分析次数
    pub analysis_count: usize,
    /// 检测到的模式数
    pub patterns_detected: usize,
    /// 检测到的异常数
    pub anomalies_detected: usize,
    /// 平均分析时间
    pub average_analysis_time: Duration,
    /// 总处理字节数
    pub total_bytes_analyzed: usize,
}

impl StreamAnalyzer {
    /// 创建新的流分析器
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            config,
            history: HashMap::new(),
            stats: AnalyzerStats::default(),
        }
    }
    
    /// 添加数据点
    pub fn add_data_point(&mut self, stream_id: String, data: &[u8]) {
        // 创建数据点（只保存前1KB作为样本）
        let sample_size = std::cmp::min(data.len(), 1024);
        let data_point = DataPoint {
            timestamp: Instant::now(),
            size: data.len(),
            sample: data[..sample_size].to_vec(),
        };
        
        let history = self.history.entry(stream_id).or_insert_with(|| StreamHistory {
            data_points: Vec::new(),
            last_analysis: None,
            accumulated_features: StreamFeatures::default(),
        });
        
        history.data_points.push(data_point);
        
        // 清理过期数据 - 需要分离借用
        let cutoff_time = Instant::now() - self.config.history_retention;
        history.data_points.retain(|dp| dp.timestamp > cutoff_time);
        
        self.stats.total_bytes_analyzed += data.len();
    }
    
    /// 分析流
    pub fn analyze_stream(&mut self, stream_id: &str) -> Result<AnalysisResult> {
        let start_time = Instant::now();
        
        // 首先获取数据点的克隆以避免借用冲突
        let data_points = {
            let history = self.history.get(stream_id)
                .ok_or_else(|| DetectorError::config_error(
                    format!("Stream not found: {}", stream_id)
                ))?;
            
            // 检查是否有足够的数据
            if history.data_points.len() < self.config.min_samples {
                return Err(DetectorError::NeedMoreData(
                    self.config.min_samples - history.data_points.len()
                ));
            }
            
            history.data_points.clone()
        };
        
        // 提取特征
        let features = self.extract_features(&data_points)?;
        
        // 检测模式
        let patterns = if self.config.enable_pattern_detection {
            self.detect_patterns(&data_points, &features)?
        } else {
            Vec::new()
        };
        
        // 检测异常
        let anomalies = if self.config.enable_anomaly_detection {
            self.detect_anomalies(&data_points, &features)?
        } else {
            Vec::new()
        };
        
        // 计算性能指标
        let performance = self.calculate_performance_metrics(&data_points)?;
        
        // 计算整体置信度
        let confidence = self.calculate_confidence(&features, &patterns, &anomalies);
        
        // 更新历史 - 现在可以安全地获取可变引用
        if let Some(history) = self.history.get_mut(stream_id) {
            history.last_analysis = Some(Instant::now());
            history.accumulated_features = features.clone();
        }
        
        // 更新统计
        self.stats.analysis_count += 1;
        self.stats.patterns_detected += patterns.len();
        self.stats.anomalies_detected += anomalies.len();
        self.update_average_analysis_time(start_time.elapsed());
        
        Ok(AnalysisResult {
            stream_id: stream_id.to_string(),
            timestamp: Instant::now(),
            features,
            patterns,
            anomalies,
            performance,
            confidence,
        })
    }
    
    /// 提取流特征
    fn extract_features(&self, data_points: &[DataPoint]) -> Result<StreamFeatures> {
        let mut features = StreamFeatures::default();
        
        if data_points.is_empty() {
            return Ok(features);
        }
        
        // 计算包大小分布
        features.packet_size_distribution = self.calculate_packet_size_distribution(data_points);
        
        // 计算时间间隔分布
        features.timing_distribution = self.calculate_timing_distribution(data_points);
        
        // 计算字节频率
        features.byte_frequency = self.calculate_byte_frequency(data_points);
        
        // 计算熵值
        features.entropy = self.calculate_entropy(data_points);
        
        // 计算压缩率
        features.compression_ratio = self.calculate_compression_ratio(data_points);
        
        // 检测周期性
        features.periodicity = self.detect_periodicity(data_points);
        
        // 提取协议特征
        features.protocol_features = self.extract_protocol_features(data_points);
        
        Ok(features)
    }
    
    /// 计算包大小分布
    fn calculate_packet_size_distribution(&self, data_points: &[DataPoint]) -> PacketSizeDistribution {
        let sizes: Vec<usize> = data_points.iter().map(|dp| dp.size).collect();
        
        if sizes.is_empty() {
            return PacketSizeDistribution::default();
        }
        
        let min_size = *sizes.iter().min().unwrap();
        let max_size = *sizes.iter().max().unwrap();
        let mean_size = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;
        
        // 计算标准差
        let variance = sizes.iter()
            .map(|&size| (size as f64 - mean_size).powi(2))
            .sum::<f64>() / sizes.len() as f64;
        let std_dev = variance.sqrt();
        
        // 计算中位数
        let mut sorted_sizes = sizes.clone();
        sorted_sizes.sort_unstable();
        let median = sorted_sizes[sorted_sizes.len() / 2];
        
        // 构建直方图
        let mut histogram = HashMap::new();
        for &size in &sizes {
            *histogram.entry(size).or_insert(0) += 1;
        }
        
        PacketSizeDistribution {
            min_size,
            max_size,
            mean_size,
            std_dev,
            median,
            histogram,
        }
    }
    
    /// 计算时间间隔分布
    fn calculate_timing_distribution(&self, data_points: &[DataPoint]) -> TimingDistribution {
        if data_points.len() < 2 {
            return TimingDistribution::default();
        }
        
        let intervals: Vec<Duration> = data_points.windows(2)
            .map(|window| window[1].timestamp.duration_since(window[0].timestamp))
            .collect();
        
        let min_interval = intervals.iter().min().cloned().unwrap_or_default();
        let max_interval = intervals.iter().max().cloned().unwrap_or_default();
        
        let mean_nanos = intervals.iter()
            .map(|d| d.as_nanos())
            .sum::<u128>() / intervals.len() as u128;
        let mean_interval = Duration::from_nanos(mean_nanos as u64);
        
        // 计算标准差
        let variance_nanos = intervals.iter()
            .map(|d| (d.as_nanos() as i128 - mean_nanos as i128).pow(2) as u128)
            .sum::<u128>() / intervals.len() as u128;
        let std_dev = Duration::from_nanos((variance_nanos as f64).sqrt() as u64);
        
        // 构建直方图（以毫秒为单位）
        let mut histogram = HashMap::new();
        for interval in &intervals {
            let millis = interval.as_millis() as u64;
            *histogram.entry(millis).or_insert(0) += 1;
        }
        
        TimingDistribution {
            min_interval,
            max_interval,
            mean_interval,
            std_dev,
            histogram,
        }
    }
    
    /// 计算字节频率
    fn calculate_byte_frequency(&self, data_points: &[DataPoint]) -> ByteFrequency {
        let mut frequencies = [0usize; 256];
        let mut total_bytes = 0;
        
        for data_point in data_points {
            for &byte in &data_point.sample {
                frequencies[byte as usize] += 1;
                total_bytes += 1;
            }
        }
        
        if total_bytes == 0 {
            return ByteFrequency::default();
        }
        
        // 找到最常见和最少见的字节
        let mut most_common = 0u8;
        let mut least_common = 0u8;
        let mut max_freq = 0;
        let mut min_freq = usize::MAX;
        
        for (byte, &freq) in frequencies.iter().enumerate() {
            if freq > 0 {
                if freq > max_freq {
                    max_freq = freq;
                    most_common = byte as u8;
                }
                if freq < min_freq {
                    min_freq = freq;
                    least_common = byte as u8;
                }
            }
        }
        
        // 计算唯一字节数
        let unique_bytes = frequencies.iter().filter(|&&freq| freq > 0).count();
        
        ByteFrequency {
            frequencies,
            most_common,
            least_common,
            unique_bytes,
        }
    }
    
    /// 计算熵值
    fn calculate_entropy(&self, data_points: &[DataPoint]) -> f64 {
        let byte_freq = self.calculate_byte_frequency(data_points);
        let total_bytes: usize = byte_freq.frequencies.iter().sum();
        
        if total_bytes == 0 {
            return 0.0;
        }
        
        let mut entropy = 0.0;
        for &freq in &byte_freq.frequencies {
            if freq > 0 {
                let probability = freq as f64 / total_bytes as f64;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    /// 计算压缩率
    fn calculate_compression_ratio(&self, data_points: &[DataPoint]) -> f64 {
        if data_points.is_empty() {
            return 1.0;
        }
        
        // 简化的压缩率估算：基于熵值
        let entropy = self.calculate_entropy(data_points);
        let max_entropy = 8.0; // 最大熵值（每字节8位）
        
        if max_entropy == 0.0 {
            1.0
        } else {
            entropy / max_entropy
        }
    }
    
    /// 检测周期性
    fn detect_periodicity(&self, data_points: &[DataPoint]) -> PeriodicityFeatures {
        if data_points.len() < 10 {
            return PeriodicityFeatures::default();
        }
        
        // 简化的周期性检测：检查包大小的周期性
        let sizes: Vec<usize> = data_points.iter().map(|dp| dp.size).collect();
        
        // 使用自相关函数检测周期性
        let mut max_correlation = 0.0;
        let mut best_period = None;
        
        for period in 2..std::cmp::min(sizes.len() / 2, 100) {
            let correlation = self.calculate_autocorrelation(&sizes, period);
            if correlation > max_correlation {
                max_correlation = correlation;
                if correlation > 0.5 { // 阈值
                    best_period = Some(Duration::from_secs(period as u64));
                }
            }
        }
        
        PeriodicityFeatures {
            has_periodicity: best_period.is_some(),
            period_length: best_period,
            period_strength: max_correlation,
            period_variance: 0.0, // 简化实现
        }
    }
    
    /// 计算自相关
    fn calculate_autocorrelation(&self, data: &[usize], lag: usize) -> f64 {
        if data.len() <= lag {
            return 0.0;
        }
        
        let n = data.len() - lag;
        let mean: f64 = data.iter().sum::<usize>() as f64 / data.len() as f64;
        
        let mut numerator = 0.0;
        let mut denominator = 0.0;
        
        for i in 0..n {
            let x = data[i] as f64 - mean;
            let y = data[i + lag] as f64 - mean;
            numerator += x * y;
            denominator += x * x;
        }
        
        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }
    
    /// 提取协议特征
    fn extract_protocol_features(&self, data_points: &[DataPoint]) -> ProtocolFeatures {
        let mut features = ProtocolFeatures::default();
        
        // 简化的协议特征提取
        for data_point in data_points {
            if !data_point.sample.is_empty() {
                // 检查HTTP特征
                if self.has_http_signature(&data_point.sample) {
                    features.detected_protocols.push(ProtocolType::HTTP1_1);
                    features.protocol_confidence.insert(ProtocolType::HTTP1_1, 0.8);
                }
                
                // 检查TLS特征
                if self.has_tls_signature(&data_point.sample) {
                    features.detected_protocols.push(ProtocolType::TLS);
                    features.protocol_confidence.insert(ProtocolType::TLS, 0.7);
                }
            }
        }
        
        features.detected_protocols.sort();
        features.detected_protocols.dedup();
        
        features
    }
    
    /// 检查HTTP签名
    fn has_http_signature(&self, data: &[u8]) -> bool {
        let data_str = String::from_utf8_lossy(data).to_lowercase();
        data_str.contains("http/") || 
        data_str.starts_with("get ") ||
        data_str.starts_with("post ") ||
        data_str.starts_with("put ") ||
        data_str.starts_with("delete ")
    }
    
    /// 检查TLS签名
    fn has_tls_signature(&self, data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }
        
        // TLS记录头：类型(1) + 版本(2) + 长度(2)
        data[0] >= 20 && data[0] <= 24 && // TLS记录类型
        data[1] == 3 && // TLS主版本
        (data[2] >= 1 && data[2] <= 4) // TLS次版本
    }
    
    /// 检测模式
    fn detect_patterns(&self, data_points: &[DataPoint], features: &StreamFeatures) -> Result<Vec<BehaviorPattern>> {
        let mut patterns = Vec::new();
        
        // 检测突发流量
        if let Some(pattern) = self.detect_burst_pattern(data_points)? {
            patterns.push(pattern);
        }
        
        // 检测周期性流量
        if features.periodicity.has_periodicity {
            patterns.push(BehaviorPattern {
                pattern_type: PatternType::PeriodicTraffic,
                description: format!("Periodic traffic detected with period {:?}", 
                    features.periodicity.period_length),
                confidence: features.periodicity.period_strength,
                start_time: data_points.first().unwrap().timestamp,
                duration: data_points.last().unwrap().timestamp
                    .duration_since(data_points.first().unwrap().timestamp),
                metadata: HashMap::new(),
            });
        }
        
        // 检测加密流量
        if features.entropy > 7.5 { // 高熵值表示可能的加密数据
            patterns.push(BehaviorPattern {
                pattern_type: PatternType::EncryptedTraffic,
                description: format!("High entropy traffic detected (entropy: {:.2})", features.entropy),
                confidence: (features.entropy - 7.0) / 1.0, // 归一化到0-1
                start_time: data_points.first().unwrap().timestamp,
                duration: data_points.last().unwrap().timestamp
                    .duration_since(data_points.first().unwrap().timestamp),
                metadata: HashMap::new(),
            });
        }
        
        Ok(patterns)
    }
    
    /// 检测突发模式
    fn detect_burst_pattern(&self, data_points: &[DataPoint]) -> Result<Option<BehaviorPattern>> {
        if data_points.len() < 5 {
            return Ok(None);
        }
        
        let sizes: Vec<usize> = data_points.iter().map(|dp| dp.size).collect();
        let mean_size = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;
        
        // 检查是否有连续的大包
        let mut burst_start = None;
        let mut burst_count = 0;
        
        for (i, &size) in sizes.iter().enumerate() {
            if size as f64 > mean_size * 2.0 { // 大于平均值2倍
                if burst_start.is_none() {
                    burst_start = Some(i);
                }
                burst_count += 1;
            } else {
                if burst_count >= 3 { // 至少3个连续大包
                    let start_idx = burst_start.unwrap();
                    return Ok(Some(BehaviorPattern {
                        pattern_type: PatternType::BurstTraffic,
                        description: format!("Burst traffic detected: {} large packets", burst_count),
                        confidence: 0.8,
                        start_time: data_points[start_idx].timestamp,
                        duration: data_points[i - 1].timestamp
                            .duration_since(data_points[start_idx].timestamp),
                        metadata: HashMap::new(),
                    }));
                }
                burst_start = None;
                burst_count = 0;
            }
        }
        
        Ok(None)
    }
    
    /// 检测异常
    fn detect_anomalies(&self, data_points: &[DataPoint], features: &StreamFeatures) -> Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();
        
        // 检测大小异常
        let size_anomalies = self.detect_size_anomalies(data_points, features)?;
        anomalies.extend(size_anomalies);
        
        // 检测时间异常
        let timing_anomalies = self.detect_timing_anomalies(data_points, features)?;
        anomalies.extend(timing_anomalies);
        
        // 检测熵值异常
        if features.entropy < 1.0 || features.entropy > 7.9 {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::EntropyAnomaly,
                severity: if features.entropy < 0.5 || features.entropy > 7.95 {
                    AnomalySeverity::High
                } else {
                    AnomalySeverity::Medium
                },
                description: format!("Unusual entropy value: {:.2}", features.entropy),
                detected_at: Instant::now(),
                value: features.entropy,
                expected_value: 4.0, // 期望的中等熵值
                deviation: (features.entropy - 4.0).abs(),
            });
        }
        
        Ok(anomalies)
    }
    
    /// 检测大小异常
    fn detect_size_anomalies(&self, data_points: &[DataPoint], features: &StreamFeatures) -> Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();
        let threshold = self.config.anomaly_threshold;
        
        for data_point in data_points {
            let size = data_point.size as f64;
            let deviation = (size - features.packet_size_distribution.mean_size).abs() 
                / features.packet_size_distribution.std_dev;
            
            if deviation > threshold {
                let severity = if deviation > threshold * 2.0 {
                    AnomalySeverity::High
                } else if deviation > threshold * 1.5 {
                    AnomalySeverity::Medium
                } else {
                    AnomalySeverity::Low
                };
                
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::SizeAnomaly,
                    severity,
                    description: format!("Unusual packet size: {} bytes", data_point.size),
                    detected_at: data_point.timestamp,
                    value: size,
                    expected_value: features.packet_size_distribution.mean_size,
                    deviation,
                });
            }
        }
        
        Ok(anomalies)
    }
    
    /// 检测时间异常
    fn detect_timing_anomalies(&self, data_points: &[DataPoint], features: &StreamFeatures) -> Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();
        
        if data_points.len() < 2 {
            return Ok(anomalies);
        }
        
        let threshold = self.config.anomaly_threshold;
        let mean_interval_nanos = features.timing_distribution.mean_interval.as_nanos() as f64;
        let std_dev_nanos = features.timing_distribution.std_dev.as_nanos() as f64;
        
        for window in data_points.windows(2) {
            let interval = window[1].timestamp.duration_since(window[0].timestamp);
            let interval_nanos = interval.as_nanos() as f64;
            
            let deviation = (interval_nanos - mean_interval_nanos).abs() / std_dev_nanos;
            
            if deviation > threshold {
                let severity = if deviation > threshold * 2.0 {
                    AnomalySeverity::High
                } else if deviation > threshold * 1.5 {
                    AnomalySeverity::Medium
                } else {
                    AnomalySeverity::Low
                };
                
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::TimingAnomaly,
                    severity,
                    description: format!("Unusual timing interval: {:?}", interval),
                    detected_at: window[1].timestamp,
                    value: interval_nanos,
                    expected_value: mean_interval_nanos,
                    deviation,
                });
            }
        }
        
        Ok(anomalies)
    }
    
    /// 计算性能指标
    fn calculate_performance_metrics(&self, data_points: &[DataPoint]) -> Result<PerformanceMetrics> {
        if data_points.is_empty() {
            return Ok(PerformanceMetrics::default());
        }
        
        let total_bytes: usize = data_points.iter().map(|dp| dp.size).sum();
        let duration = data_points.last().unwrap().timestamp
            .duration_since(data_points.first().unwrap().timestamp);
        
        let throughput = if duration.as_secs_f64() > 0.0 {
            total_bytes as f64 / duration.as_secs_f64()
        } else {
            0.0
        };
        
        // 简化的性能指标计算
        let mut metrics = PerformanceMetrics {
            throughput,
            latency: Duration::from_millis(10), // 假设值
            jitter: Duration::from_millis(5),   // 假设值
            packet_loss_rate: 0.0,             // 假设无丢包
            bandwidth_utilization: 0.8,        // 假设值
            quality_score: 0.9,                // 假设值
        };
        
        // 基于吞吐量调整质量评分
        if throughput < 1000.0 { // 低于1KB/s
            metrics.quality_score *= 0.5;
        } else if throughput > 1000000.0 { // 高于1MB/s
            metrics.quality_score = (metrics.quality_score * 1.2).min(1.0);
        }
        
        Ok(metrics)
    }
    
    /// 计算置信度
    fn calculate_confidence(&self, features: &StreamFeatures, patterns: &[BehaviorPattern], anomalies: &[Anomaly]) -> f64 {
        let mut confidence = 0.5; // 基础置信度
        
        // 基于特征质量调整
        if features.packet_size_distribution.histogram.len() > 5 {
            confidence += 0.1;
        }
        
        if features.entropy > 0.0 && features.entropy < 8.0 {
            confidence += 0.1;
        }
        
        // 基于模式数量调整
        confidence += (patterns.len() as f64 * 0.05).min(0.2);
        
        // 基于异常数量调整（异常越多，置信度越低）
        confidence -= (anomalies.len() as f64 * 0.02).min(0.3);
        
        confidence.clamp(0.0, 1.0)
    }
    
    /// 清理过期数据
    fn cleanup_expired_data(&self, data_points: &mut Vec<DataPoint>) {
        let cutoff = Instant::now() - self.config.history_retention;
        data_points.retain(|dp| dp.timestamp > cutoff);
    }
    
    /// 更新平均分析时间
    fn update_average_analysis_time(&mut self, duration: Duration) {
        let count = self.stats.analysis_count;
        if count == 1 {
            self.stats.average_analysis_time = duration;
        } else {
            let current_total = self.stats.average_analysis_time.as_nanos() * (count - 1) as u128;
            let new_total = current_total + duration.as_nanos();
            self.stats.average_analysis_time = Duration::from_nanos((new_total / count as u128) as u64);
        }
    }
    
    /// 获取统计信息
    pub fn stats(&self) -> &AnalyzerStats {
        &self.stats
    }
    
    /// 获取配置
    pub fn config(&self) -> &AnalyzerConfig {
        &self.config
    }
    
    /// 更新配置
    pub fn update_config(&mut self, config: AnalyzerConfig) {
        self.config = config;
    }
    
    /// 清理所有历史数据
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
    
    /// 获取流数量
    pub fn stream_count(&self) -> usize {
        self.history.len()
    }
}

impl Default for StreamAnalyzer {
    fn default() -> Self {
        Self::new(AnalyzerConfig::default())
    }
}