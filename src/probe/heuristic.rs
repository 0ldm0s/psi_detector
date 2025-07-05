//! 启发式探测模块
//!
//! 基于统计分析和模式识别进行协议探测。

use crate::core::{ProtocolType, DetectionResult, ProtocolInfo};
use crate::core::detector::DetectionMethod;
use crate::error::{Result, DetectorError};
use super::{ProbeEngine, ProbeType};
use std::collections::HashMap;

/// 启发式探测器
pub struct HeuristicProbe {
    /// 最小样本大小
    min_sample_size: usize,
    /// 统计窗口大小
    window_size: usize,
    /// 启用深度分析
    deep_analysis: bool,
    /// 字节频率阈值
    frequency_threshold: f32,
}

impl HeuristicProbe {
    /// 创建新的启发式探测器
    pub fn new() -> Self {
        Self {
            min_sample_size: 64,
            window_size: 256,
            deep_analysis: false,
            frequency_threshold: 0.1,
        }
    }
    
    /// 设置最小样本大小
    pub fn with_min_sample_size(mut self, size: usize) -> Self {
        self.min_sample_size = size;
        self
    }
    
    /// 设置统计窗口大小
    pub fn with_window_size(mut self, size: usize) -> Self {
        self.window_size = size;
        self
    }
    
    /// 启用深度分析
    pub fn with_deep_analysis(mut self, enabled: bool) -> Self {
        self.deep_analysis = enabled;
        self
    }
    
    /// 计算字节频率分布
    fn calculate_byte_frequency(&self, data: &[u8]) -> [f32; 256] {
        let mut frequency = [0u32; 256];
        let mut total = 0u32;
        
        for &byte in data {
            frequency[byte as usize] += 1;
            total += 1;
        }
        
        let mut normalized = [0.0f32; 256];
        if total > 0 {
            for i in 0..256 {
                normalized[i] = frequency[i] as f32 / total as f32;
            }
        }
        
        normalized
    }
    
    /// 计算熵值
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        let frequency = self.calculate_byte_frequency(data);
        let mut entropy = 0.0;
        
        for &freq in &frequency {
            if freq > 0.0 {
                entropy -= freq * freq.log2();
            }
        }
        
        entropy
    }
    
    /// 分析ASCII字符比例
    fn analyze_ascii_ratio(&self, data: &[u8]) -> f32 {
        let ascii_count = data.iter()
            .filter(|&&b| b >= 32 && b <= 126)
            .count();
        
        ascii_count as f32 / data.len() as f32
    }
    
    /// 分析数据模式
    fn analyze_patterns(&self, data: &[u8]) -> PatternAnalysis {
        let mut analysis = PatternAnalysis::default();
        
        // 分析重复模式
        analysis.repetition_score = self.calculate_repetition_score(data);
        
        // 分析结构化程度
        analysis.structure_score = self.calculate_structure_score(data);
        
        // 分析随机性
        analysis.randomness_score = self.calculate_entropy(data) / 8.0; // 归一化到0-1
        
        // 分析ASCII比例
        analysis.ascii_ratio = self.analyze_ascii_ratio(data);
        
        analysis
    }
    
    /// 计算重复模式得分
    fn calculate_repetition_score(&self, data: &[u8]) -> f32 {
        if data.len() < 4 {
            return 0.0;
        }
        
        let mut repetitions = 0;
        let mut total_comparisons = 0;
        
        // 检查2-4字节的重复模式
        for pattern_len in 2..=4 {
            if data.len() < pattern_len * 2 {
                continue;
            }
            
            for i in 0..=(data.len() - pattern_len * 2) {
                let pattern = &data[i..i + pattern_len];
                let next = &data[i + pattern_len..i + pattern_len * 2];
                
                if pattern == next {
                    repetitions += 1;
                }
                total_comparisons += 1;
            }
        }
        
        if total_comparisons > 0 {
            repetitions as f32 / total_comparisons as f32
        } else {
            0.0
        }
    }
    
    /// 计算结构化得分
    fn calculate_structure_score(&self, data: &[u8]) -> f32 {
        let mut structure_indicators = 0;
        let mut total_checks = 0;
        
        // 检查常见的结构化标记
        let markers = [b'\r', b'\n', b'\0', b' ', b'\t'];
        
        for &marker in &markers {
            let count = data.iter().filter(|&&b| b == marker).count();
            if count > 0 {
                structure_indicators += 1;
            }
            total_checks += 1;
        }
        
        // 检查括号匹配
        let brackets = [(b'(', b')'), (b'[', b']'), (b'{', b'}')];
        for (open, close) in &brackets {
            let open_count = data.iter().filter(|&&b| b == *open).count();
            let close_count = data.iter().filter(|&&b| b == *close).count();
            
            if open_count > 0 && close_count > 0 {
                structure_indicators += 1;
            }
            total_checks += 1;
        }
        
        structure_indicators as f32 / total_checks as f32
    }
    
    /// HTTP协议启发式分析
    fn heuristic_http(&self, data: &[u8], analysis: &PatternAnalysis) -> Option<f32> {
        let mut confidence = 0.0;
        
        // ASCII比例高表明可能是文本协议
        if analysis.ascii_ratio > 0.8 {
            confidence += 0.3;
        }
        
        // 检查HTTP特征字符串
        let data_str = String::from_utf8_lossy(data);
        let http_indicators = [
            "HTTP/", "GET ", "POST", "PUT ", "DELETE", 
            "Content-", "Host:", "User-Agent:", "\r\n\r\n"
        ];
        
        let mut indicator_count = 0;
        for indicator in &http_indicators {
            if data_str.contains(indicator) {
                indicator_count += 1;
            }
        }
        
        confidence += (indicator_count as f32 / http_indicators.len() as f32) * 0.5;
        
        // 结构化程度适中
        if analysis.structure_score > 0.2 && analysis.structure_score < 0.8 {
            confidence += 0.2;
        }
        
        if confidence > 0.4 {
            Some(confidence)
        } else {
            None
        }
    }
    
    /// 二进制协议启发式分析
    fn heuristic_binary(&self, data: &[u8], analysis: &PatternAnalysis) -> Option<f32> {
        let mut confidence = 0.0;
        
        // 低ASCII比例表明可能是二进制协议
        if analysis.ascii_ratio < 0.3 {
            confidence += 0.4;
        }
        
        // 高熵值表明数据压缩或加密
        if analysis.randomness_score > 0.7 {
            confidence += 0.3;
        }
        
        // 检查常见的二进制协议标记
        if data.len() >= 4 {
            // 检查可能的长度字段（网络字节序）
            let length_field = u32::from_be_bytes([
                data[0], data[1], data[2], data[3]
            ]) as usize;
            
            if length_field > 0 && length_field < data.len() * 2 {
                confidence += 0.2;
            }
        }
        
        // 检查重复模式（可能是协议帧结构）
        if analysis.repetition_score > 0.1 {
            confidence += 0.1;
        }
        
        if confidence > 0.5 {
            Some(confidence)
        } else {
            None
        }
    }
    
    /// QUIC协议启发式分析
    fn heuristic_quic(&self, data: &[u8], analysis: &PatternAnalysis) -> Option<f32> {
        if data.is_empty() {
            return None;
        }
        
        let mut confidence = 0.0;
        
        // QUIC是二进制协议
        if analysis.ascii_ratio < 0.2 {
            confidence += 0.3;
        }
        
        // 检查QUIC包头特征
        let first_byte = data[0];
        
        // 长包头格式
        if (first_byte & 0x80) != 0 {
            confidence += 0.4;
            
            // 检查版本字段
            if data.len() >= 5 {
                let version = u32::from_be_bytes([
                    data[1], data[2], data[3], data[4]
                ]);
                
                // 已知QUIC版本
                if version == 1 || version == 0xff00001d || version == 0 {
                    confidence += 0.3;
                }
            }
        }
        
        // 适中的随机性（加密但有结构）
        if analysis.randomness_score > 0.5 && analysis.randomness_score < 0.9 {
            confidence += 0.2;
        }
        
        if confidence > 0.6 {
            Some(confidence)
        } else {
            None
        }
    }
}

/// 模式分析结果
#[derive(Debug, Default)]
struct PatternAnalysis {
    /// 重复模式得分
    repetition_score: f32,
    /// 结构化得分
    structure_score: f32,
    /// 随机性得分
    randomness_score: f32,
    /// ASCII字符比例
    ascii_ratio: f32,
}

impl ProbeEngine for HeuristicProbe {
    fn probe(&self, data: &[u8]) -> Result<DetectionResult> {
        if data.len() < self.min_sample_size {
            return Err(DetectorError::NeedMoreData(self.min_sample_size));
        }
        
        // 限制分析窗口大小
        let analysis_data = if data.len() > self.window_size {
            &data[..self.window_size]
        } else {
            data
        };
        
        // 执行模式分析
        let analysis = self.analyze_patterns(analysis_data);
        
        let mut best_protocol = ProtocolType::Unknown;
        let mut best_confidence = 0.0;
        let mut metadata = HashMap::new();
        
        // 记录分析结果
        metadata.insert("entropy".to_string(), analysis.randomness_score.to_string());
        metadata.insert("ascii_ratio".to_string(), analysis.ascii_ratio.to_string());
        metadata.insert("structure_score".to_string(), analysis.structure_score.to_string());
        metadata.insert("repetition_score".to_string(), analysis.repetition_score.to_string());
        
        // 尝试各种启发式方法
        let heuristics = [
            ("http", self.heuristic_http(analysis_data, &analysis)),
            ("quic", self.heuristic_quic(analysis_data, &analysis)),
            ("binary", self.heuristic_binary(analysis_data, &analysis)),
        ];
        
        for (name, confidence_opt) in heuristics {
            if let Some(confidence) = confidence_opt {
                metadata.insert(
                    format!("{}_heuristic_confidence", name),
                    confidence.to_string()
                );
                
                if confidence > best_confidence {
                    best_confidence = confidence;
                    best_protocol = match name {
                        "http" => {
                            // 进一步区分HTTP版本
                            if analysis.structure_score > 0.6 {
                                ProtocolType::HTTP1_1
                            } else {
                                ProtocolType::HTTP2
                            }
                        }
                        "quic" => ProtocolType::QUIC,
                        "binary" => {
                            // 基于其他特征推断具体协议
                            if analysis.repetition_score > 0.2 {
                                ProtocolType::HTTP2
                            } else {
                                ProtocolType::GRPC
                            }
                        }
                        _ => ProtocolType::Unknown,
                    };
                }
            }
        }
        
        if best_confidence < 0.3 {
            return Err(DetectorError::detection_failed(
                "Heuristic analysis confidence too low"
            ));
        }
        
        let protocol_info = ProtocolInfo::new(best_protocol, best_confidence);
        
        Ok(DetectionResult::new(
            protocol_info,
            std::time::Duration::from_millis(0), // 启发式探测时间很短
            DetectionMethod::Heuristic,
            "HeuristicProbe".to_string(),
        ))
    }
    
    fn probe_type(&self) -> ProbeType {
        ProbeType::Heuristic
    }
    
    fn needs_more_data(&self, data: &[u8]) -> bool {
        data.len() < self.min_sample_size
    }
}

impl Default for HeuristicProbe {
    fn default() -> Self {
        Self::new()
    }
}