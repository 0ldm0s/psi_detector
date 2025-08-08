//! SIMD加速协议探测模块
//!
//! 使用SIMD指令集加速协议特征匹配和探测过程。

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "wasm32")]
pub mod wasm32;

pub mod detector;
// TODO: 添加patterns模块
// pub mod patterns;

use crate::core::protocol::ProtocolType;
use crate::error::{DetectorError, Result};

/// SIMD探测结果
#[derive(Debug, Clone, PartialEq)]
pub struct SimdDetectionResult {
    /// 协议类型
    pub protocol: ProtocolType,
    /// 置信度
    pub confidence: f32,
    /// 匹配位置
    pub match_positions: Vec<usize>,
    /// 使用的SIMD指令集
    pub instruction_set: SimdInstructionSet,
}

/// SIMD指令集类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdInstructionSet {
    /// 无SIMD支持
    None,
    /// SSE2
    SSE2,
    /// SSE4.1
    SSE41,
    /// AVX2
    AVX2,
    /// AVX512
    AVX512,
    /// ARM NEON
    NEON,
    /// WebAssembly SIMD
    WasmSimd,
}

/// SIMD探测器trait
pub trait SimdDetector: Send + Sync {
    /// 探测HTTP/2协议
    fn detect_http2(&self, data: &[u8]) -> Result<SimdDetectionResult>;
    
    /// 探测QUIC协议
    fn detect_quic(&self, data: &[u8]) -> Result<SimdDetectionResult>;
    
    /// 探测gRPC协议
    fn detect_grpc(&self, data: &[u8]) -> Result<SimdDetectionResult>;
    
    /// 探测WebSocket协议
    fn detect_websocket(&self, data: &[u8]) -> Result<SimdDetectionResult>;
    
    /// 探测TLS协议
    fn detect_tls(&self, data: &[u8]) -> Result<SimdDetectionResult>;
    
    /// 批量探测多个协议
    fn detect_multiple(&self, data: &[u8], protocols: &[ProtocolType]) -> Result<Vec<SimdDetectionResult>>;
    
    /// 获取支持的指令集
    fn instruction_set(&self) -> SimdInstructionSet;
    
    /// 检查是否支持指定协议的SIMD探测
    fn supports_protocol(&self, protocol: ProtocolType) -> bool;
}

/// 创建最佳的SIMD探测器
pub fn create_best_detector() -> Box<dyn SimdDetector> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            return Box::new(x86_64::Avx512Detector::new());
        } else if is_x86_feature_detected!("avx2") {
            return Box::new(x86_64::Avx2Detector::new());
        } else if is_x86_feature_detected!("sse2") {
            return Box::new(x86_64::Sse2Detector::new());
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return Box::new(aarch64::AArch64SimdDetector::new());
        }
    }
    
    #[cfg(target_arch = "wasm32")]
    {
        return Box::new(wasm32::WasmSimdDetector::new());
    }
    
    // 回退到通用实现
    Box::new(detector::GenericSimdDetector::new())
}

/// 检查当前平台的SIMD支持
pub fn detect_simd_support() -> SimdInstructionSet {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            return SimdInstructionSet::AVX512;
        } else if is_x86_feature_detected!("avx2") {
            return SimdInstructionSet::AVX2;
        } else if is_x86_feature_detected!("sse2") {
            return SimdInstructionSet::SSE2;
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return SimdInstructionSet::NEON;
        }
    }
    
    #[cfg(target_arch = "wasm32")]
    {
        return SimdInstructionSet::WasmSimd;
    }
    
    SimdInstructionSet::None
}

/// SIMD模式匹配函数
pub fn simd_pattern_match(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let detector = create_best_detector();
    
    // 这里应该调用具体的SIMD实现
    // 为了简化，我们使用通用实现
    generic_pattern_match(haystack, needle)
}

/// 通用模式匹配（非SIMD回退）
fn generic_pattern_match(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    
    if needle.is_empty() || haystack.len() < needle.len() {
        return positions;
    }
    
    for i in 0..=haystack.len() - needle.len() {
        if haystack[i..i + needle.len()] == *needle {
            positions.push(i);
        }
    }
    
    positions
}

/// SIMD加速的字节计数
pub fn simd_count_bytes(data: &[u8], byte: u8) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                return x86_64::avx2_count_bytes(data, byte);
            }
        } else if is_x86_feature_detected!("sse2") {
            unsafe {
                return x86_64::sse2_count_bytes(data, byte);
            }
        }
    }
    
    // 回退到标准实现
    data.iter().filter(|&&b| b == byte).count()
}

/// SIMD加速的字节查找
pub fn simd_find_byte(data: &[u8], byte: u8) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                return x86_64::avx2_find_byte(data, byte);
            }
        } else if is_x86_feature_detected!("sse2") {
            unsafe {
                return x86_64::sse2_find_byte(data, byte);
            }
        }
    }
    
    // 回退到标准实现
    data.iter().position(|&b| b == byte)
}