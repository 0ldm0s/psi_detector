//! 协议指纹识别模块
//!
//! 定义协议指纹和特征匹配功能。

use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 协议指纹
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolFingerprint {
    /// 协议类型
    pub protocol: ProtocolType,
    /// 指纹名称
    pub name: String,
    /// 指纹描述
    pub description: String,
    /// 匹配规则
    pub rules: Vec<FingerprintRule>,
    /// 指纹权重
    pub weight: f32,
    /// 是否启用
    pub enabled: bool,
}

impl ProtocolFingerprint {
    /// 创建新的协议指纹
    pub fn new<S: Into<String>>(
        protocol: ProtocolType,
        name: S,
        description: S,
    ) -> Self {
        Self {
            protocol,
            name: name.into(),
            description: description.into(),
            rules: Vec::new(),
            weight: 1.0,
            enabled: true,
        }
    }
    
    /// 添加匹配规则
    pub fn add_rule(mut self, rule: FingerprintRule) -> Self {
        self.rules.push(rule);
        self
    }
    
    /// 设置权重
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight.max(0.0);
        self
    }
    
    /// 启用指纹
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }
    
    /// 禁用指纹
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }
    
    /// 匹配数据
    pub fn matches(&self, data: &[u8]) -> Result<FingerprintMatch> {
        if !self.enabled {
            return Ok(FingerprintMatch::no_match());
        }
        
        let mut total_score = 0.0;
        let mut matched_rules = 0;
        let mut rule_matches = Vec::new();
        
        for rule in &self.rules {
            let rule_match = rule.matches(data)?;
            if rule_match.matched {
                total_score += rule_match.score * rule.weight;
                matched_rules += 1;
                rule_matches.push(rule_match);
            } else if rule.required {
                // 必需规则未匹配，整个指纹不匹配
                return Ok(FingerprintMatch::no_match());
            }
        }
        
        if matched_rules == 0 {
            return Ok(FingerprintMatch::no_match());
        }
        
        // 计算最终分数
        let final_score = (total_score / self.rules.len() as f32) * self.weight;
        
        Ok(FingerprintMatch {
            matched: true,
            score: final_score.min(1.0),
            fingerprint_name: self.name.clone(),
            protocol: self.protocol,
            rule_matches,
        })
    }
}

/// 指纹匹配规则
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FingerprintRule {
    /// 规则名称
    pub name: String,
    /// 规则类型
    pub rule_type: RuleType,
    /// 规则权重
    pub weight: f32,
    /// 是否为必需规则
    pub required: bool,
}

impl FingerprintRule {
    /// 创建新的指纹规则
    pub fn new<S: Into<String>>(name: S, rule_type: RuleType) -> Self {
        Self {
            name: name.into(),
            rule_type,
            weight: 1.0,
            required: false,
        }
    }
    
    /// 设置权重
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight.max(0.0);
        self
    }
    
    /// 设置为必需规则
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    
    /// 匹配数据
    pub fn matches(&self, data: &[u8]) -> Result<RuleMatch> {
        let matched = self.rule_type.matches(data)?;
        let score = if matched { 1.0 } else { 0.0 };
        
        Ok(RuleMatch {
            matched,
            score,
            rule_name: self.name.clone(),
            rule_type: self.rule_type.clone(),
        })
    }
}

/// 规则类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleType {
    /// 字节序列匹配
    ByteSequence {
        /// 匹配的字节序列
        pattern: Vec<u8>,
        /// 匹配位置偏移
        offset: usize,
    },
    /// 正则表达式匹配
    Regex {
        /// 正则表达式模式
        pattern: String,
    },
    /// 字符串匹配
    String {
        /// 匹配的字符串
        pattern: String,
        /// 是否区分大小写
        case_sensitive: bool,
    },
    /// 长度检查
    Length {
        /// 最小长度
        min: Option<usize>,
        /// 最大长度
        max: Option<usize>,
    },
    /// 端口匹配
    Port {
        /// 端口号
        port: u16,
    },
    /// 魔数匹配
    MagicBytes {
        /// 魔数字节
        magic: Vec<u8>,
        /// 偏移位置
        offset: usize,
    },
    /// 自定义匹配函数
    Custom {
        /// 函数名称
        name: String,
    },
}

impl RuleType {
    /// 匹配数据
    pub fn matches(&self, data: &[u8]) -> Result<bool> {
        match self {
            Self::ByteSequence { pattern, offset } => {
                if data.len() < offset + pattern.len() {
                    return Ok(false);
                }
                Ok(&data[*offset..*offset + pattern.len()] == pattern.as_slice())
            }
            Self::Regex { pattern } => {
                // 简化的正则匹配，实际项目中应使用regex crate
                let text = String::from_utf8_lossy(data);
                Ok(text.contains(pattern))
            }
            Self::String { pattern, case_sensitive } => {
                let text = String::from_utf8_lossy(data);
                if *case_sensitive {
                    Ok(text.contains(pattern))
                } else {
                    Ok(text.to_lowercase().contains(&pattern.to_lowercase()))
                }
            }
            Self::Length { min, max } => {
                let len = data.len();
                let min_ok = min.map_or(true, |m| len >= m);
                let max_ok = max.map_or(true, |m| len <= m);
                Ok(min_ok && max_ok)
            }
            Self::Port { port: _ } => {
                // 端口匹配需要额外的上下文信息，这里暂时返回false
                Ok(false)
            }
            Self::MagicBytes { magic, offset } => {
                if data.len() < offset + magic.len() {
                    return Ok(false);
                }
                Ok(&data[*offset..*offset + magic.len()] == magic.as_slice())
            }
            Self::Custom { name: _ } => {
                // 自定义匹配函数需要注册机制，这里暂时返回false
                Ok(false)
            }
        }
    }
}

/// 指纹匹配结果
#[derive(Debug, Clone, PartialEq)]
pub struct FingerprintMatch {
    /// 是否匹配
    pub matched: bool,
    /// 匹配分数 (0.0 - 1.0)
    pub score: f32,
    /// 指纹名称
    pub fingerprint_name: String,
    /// 协议类型
    pub protocol: ProtocolType,
    /// 规则匹配结果
    pub rule_matches: Vec<RuleMatch>,
}

impl FingerprintMatch {
    /// 创建无匹配结果
    pub fn no_match() -> Self {
        Self {
            matched: false,
            score: 0.0,
            fingerprint_name: String::new(),
            protocol: ProtocolType::Unknown,
            rule_matches: Vec::new(),
        }
    }
    
    /// 检查是否为高分匹配
    pub fn is_high_score(&self) -> bool {
        self.matched && self.score >= 0.8
    }
    
    /// 检查是否可接受
    pub fn is_acceptable(&self, threshold: f32) -> bool {
        self.matched && self.score >= threshold
    }
}

/// 规则匹配结果
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatch {
    /// 是否匹配
    pub matched: bool,
    /// 匹配分数
    pub score: f32,
    /// 规则名称
    pub rule_name: String,
    /// 规则类型
    pub rule_type: RuleType,
}

/// 指纹数据库
#[derive(Debug, Clone)]
pub struct FingerprintDatabase {
    /// 指纹集合
    fingerprints: HashMap<ProtocolType, Vec<ProtocolFingerprint>>,
}

impl FingerprintDatabase {
    /// 创建新的指纹数据库
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }
    
    /// 添加指纹
    pub fn add_fingerprint(&mut self, fingerprint: ProtocolFingerprint) {
        self.fingerprints
            .entry(fingerprint.protocol)
            .or_insert_with(Vec::new)
            .push(fingerprint);
    }
    
    /// 批量添加指纹
    pub fn add_fingerprints(&mut self, fingerprints: Vec<ProtocolFingerprint>) {
        for fingerprint in fingerprints {
            self.add_fingerprint(fingerprint);
        }
    }
    
    /// 匹配协议
    pub fn match_protocol(&self, data: &[u8]) -> Result<Vec<FingerprintMatch>> {
        let mut matches = Vec::new();
        
        for fingerprints in self.fingerprints.values() {
            for fingerprint in fingerprints {
                let fingerprint_match = fingerprint.matches(data)?;
                if fingerprint_match.matched {
                    matches.push(fingerprint_match);
                }
            }
        }
        
        // 按分数排序
        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(matches)
    }
    
    /// 匹配特定协议
    pub fn match_specific_protocol(
        &self,
        protocol: ProtocolType,
        data: &[u8],
    ) -> Result<Vec<FingerprintMatch>> {
        let mut matches = Vec::new();
        
        if let Some(fingerprints) = self.fingerprints.get(&protocol) {
            for fingerprint in fingerprints {
                let fingerprint_match = fingerprint.matches(data)?;
                if fingerprint_match.matched {
                    matches.push(fingerprint_match);
                }
            }
        }
        
        // 按分数排序
        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(matches)
    }
    
    /// 获取最佳匹配
    pub fn best_match(&self, data: &[u8]) -> Result<Option<FingerprintMatch>> {
        let matches = self.match_protocol(data)?;
        Ok(matches.into_iter().next())
    }
    
    /// 获取支持的协议列表
    pub fn supported_protocols(&self) -> Vec<ProtocolType> {
        self.fingerprints.keys().copied().collect()
    }
    
    /// 获取指纹数量
    pub fn fingerprint_count(&self) -> usize {
        self.fingerprints.values().map(|v| v.len()).sum()
    }
    
    /// 清空数据库
    pub fn clear(&mut self) {
        self.fingerprints.clear();
    }
    
    /// 加载默认指纹
    pub fn load_default_fingerprints(&mut self) {
        // HTTP/1.1 指纹
        let http11_fingerprint = ProtocolFingerprint::new(
            ProtocolType::HTTP1_1,
            "HTTP/1.1 Request",
            "HTTP/1.1 request detection",
        )
        .add_rule(
            FingerprintRule::new(
                "HTTP Method",
                RuleType::String {
                    pattern: "GET ".to_string(),
                    case_sensitive: true,
                },
            )
            .required(),
        )
        .add_rule(
            FingerprintRule::new(
                "HTTP Version",
                RuleType::String {
                    pattern: "HTTP/1.1".to_string(),
                    case_sensitive: false,
                },
            )
            .with_weight(0.8),
        );
        
        // HTTP/2 指纹
        let http2_fingerprint = ProtocolFingerprint::new(
            ProtocolType::HTTP2,
            "HTTP/2 Connection Preface",
            "HTTP/2 connection preface detection",
        )
        .add_rule(
            FingerprintRule::new(
                "HTTP/2 Preface",
                RuleType::ByteSequence {
                    pattern: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
                    offset: 0,
                },
            )
            .required(),
        );
        
        // TLS 指纹
        let tls_fingerprint = ProtocolFingerprint::new(
            ProtocolType::TLS,
            "TLS Handshake",
            "TLS handshake detection",
        )
        .add_rule(
            FingerprintRule::new(
                "TLS Record Type",
                RuleType::ByteSequence {
                    pattern: vec![0x16], // Handshake
                    offset: 0,
                },
            )
            .required(),
        )
        .add_rule(
            FingerprintRule::new(
                "TLS Version",
                RuleType::ByteSequence {
                    pattern: vec![0x03, 0x01], // TLS 1.0
                    offset: 1,
                },
            )
            .with_weight(0.7),
        );
        
        // SSH 指纹
        let ssh_fingerprint = ProtocolFingerprint::new(
            ProtocolType::SSH,
            "SSH Protocol",
            "SSH protocol detection",
        )
        .add_rule(
            FingerprintRule::new(
                "SSH Banner",
                RuleType::String {
                    pattern: "SSH-".to_string(),
                    case_sensitive: false,
                },
            )
            .required(),
        );
        
        self.add_fingerprint(http11_fingerprint);
        self.add_fingerprint(http2_fingerprint);
        self.add_fingerprint(tls_fingerprint);
        self.add_fingerprint(ssh_fingerprint);
    }
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        let mut db = Self::new();
        db.load_default_fingerprints();
        db
    }
}