//! 流缓冲区模块
//!
//! 提供高效的流数据缓存和管理功能。

use crate::error::{DetectorError, Result};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 缓冲区配置
#[derive(Debug, Clone)]
pub struct BufferConfig {
    /// 最大缓冲区大小（字节）
    pub max_size: usize,
    /// 最大块数量
    pub max_chunks: usize,
    /// 块超时时间
    pub chunk_timeout: Duration,
    /// 是否启用压缩
    pub enable_compression: bool,
    /// 压缩阈值
    pub compression_threshold: usize,
    /// 是否自动清理过期数据
    pub auto_cleanup: bool,
    /// 清理间隔
    pub cleanup_interval: Duration,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_size: 1024 * 1024,           // 1MB
            max_chunks: 1000,
            chunk_timeout: Duration::from_secs(300), // 5分钟
            enable_compression: false,
            compression_threshold: 4096,      // 4KB
            auto_cleanup: true,
            cleanup_interval: Duration::from_secs(60), // 1分钟
        }
    }
}

/// 数据块
#[derive(Debug, Clone)]
pub struct DataChunk {
    /// 数据内容
    pub data: Vec<u8>,
    /// 时间戳
    pub timestamp: Instant,
    /// 序列号
    pub sequence: u64,
    /// 是否已压缩
    pub compressed: bool,
    /// 原始大小（如果已压缩）
    pub original_size: Option<usize>,
}

impl DataChunk {
    /// 创建新的数据块
    pub fn new(data: Vec<u8>, sequence: u64) -> Self {
        Self {
            data,
            timestamp: Instant::now(),
            sequence,
            compressed: false,
            original_size: None,
        }
    }
    
    /// 获取数据大小
    pub fn size(&self) -> usize {
        self.data.len()
    }
    
    /// 获取年龄
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.timestamp)
    }
    
    /// 是否过期
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.age() > timeout
    }
    
    /// 压缩数据（简化实现）
    pub fn compress(&mut self) -> Result<()> {
        if self.compressed {
            return Ok(());
        }
        
        // 简化的压缩实现（实际应用中可以使用真正的压缩算法）
        if self.data.len() > 100 {
            self.original_size = Some(self.data.len());
            // 模拟压缩：移除重复字节
            let mut compressed_data = Vec::new();
            let mut last_byte = None;
            let mut count = 0u8;
            
            for &byte in &self.data {
                if Some(byte) == last_byte {
                    count = count.saturating_add(1);
                    if count == 255 {
                        compressed_data.push(count);
                        compressed_data.push(byte);
                        count = 0;
                        last_byte = None;
                    }
                } else {
                    if let Some(prev_byte) = last_byte {
                        if count > 0 {
                            compressed_data.push(count);
                            compressed_data.push(prev_byte);
                        } else {
                            compressed_data.push(prev_byte);
                        }
                    }
                    last_byte = Some(byte);
                    count = 0;
                }
            }
            
            // 处理最后一个字节
            if let Some(byte) = last_byte {
                if count > 0 {
                    compressed_data.push(count);
                    compressed_data.push(byte);
                } else {
                    compressed_data.push(byte);
                }
            }
            
            // 只有在压缩效果明显时才使用压缩数据
            if compressed_data.len() < self.data.len() * 3 / 4 {
                self.data = compressed_data;
                self.compressed = true;
            }
        }
        
        Ok(())
    }
    
    /// 解压缩数据
    pub fn decompress(&mut self) -> Result<()> {
        if !self.compressed {
            return Ok(());
        }
        
        // 简化的解压缩实现
        let mut decompressed_data = Vec::new();
        let mut i = 0;
        
        while i < self.data.len() {
            let byte = self.data[i];
            
            // 检查是否是重复计数
            if i + 1 < self.data.len() && byte > 1 {
                let repeat_byte = self.data[i + 1];
                for _ in 0..byte {
                    decompressed_data.push(repeat_byte);
                }
                i += 2;
            } else {
                decompressed_data.push(byte);
                i += 1;
            }
        }
        
        self.data = decompressed_data;
        self.compressed = false;
        self.original_size = None;
        
        Ok(())
    }
}

/// 流缓冲区
#[derive(Debug)]
pub struct StreamBuffer {
    /// 数据块队列
    chunks: VecDeque<DataChunk>,
    /// 配置
    config: BufferConfig,
    /// 当前总大小
    total_size: usize,
    /// 下一个序列号
    next_sequence: u64,
    /// 最后清理时间
    last_cleanup: Instant,
    /// 统计信息
    stats: BufferStats,
}

/// 缓冲区统计信息
#[derive(Debug, Clone, Default)]
pub struct BufferStats {
    /// 总接收字节数
    pub total_bytes_received: usize,
    /// 总发送字节数
    pub total_bytes_sent: usize,
    /// 当前缓冲字节数
    pub current_buffered_bytes: usize,
    /// 最大缓冲字节数
    pub max_buffered_bytes: usize,
    /// 块数量
    pub chunk_count: usize,
    /// 最大块数量
    pub max_chunk_count: usize,
    /// 压缩次数
    pub compression_count: usize,
    /// 清理次数
    pub cleanup_count: usize,
    /// 丢弃的字节数
    pub dropped_bytes: usize,
}

impl StreamBuffer {
    /// 创建新的流缓冲区
    pub fn new(config: BufferConfig) -> Self {
        Self {
            chunks: VecDeque::new(),
            config,
            total_size: 0,
            next_sequence: 0,
            last_cleanup: Instant::now(),
            stats: BufferStats::default(),
        }
    }
    
    /// 添加数据
    pub fn push(&mut self, data: Vec<u8>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        
        let data_size = data.len();
        self.stats.total_bytes_received += data_size;
        
        // 检查是否需要清理
        if self.config.auto_cleanup {
            self.maybe_cleanup()?;
        }
        
        // 检查缓冲区大小限制
        if self.total_size + data_size > self.config.max_size {
            self.make_space(data_size)?;
        }
        
        // 创建新的数据块
        let mut chunk = DataChunk::new(data, self.next_sequence);
        self.next_sequence += 1;
        
        // 压缩数据（如果启用）
        if self.config.enable_compression && chunk.size() >= self.config.compression_threshold {
            chunk.compress()?;
            self.stats.compression_count += 1;
        }
        
        // 添加到缓冲区
        self.total_size += chunk.size();
        self.chunks.push_back(chunk);
        
        // 更新统计信息
        self.stats.current_buffered_bytes = self.total_size;
        self.stats.chunk_count = self.chunks.len();
        
        if self.total_size > self.stats.max_buffered_bytes {
            self.stats.max_buffered_bytes = self.total_size;
        }
        
        if self.chunks.len() > self.stats.max_chunk_count {
            self.stats.max_chunk_count = self.chunks.len();
        }
        
        Ok(())
    }
    
    /// 获取数据（不移除）
    pub fn peek(&self, size: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let mut remaining = size;
        
        for chunk in &self.chunks {
            if remaining == 0 {
                break;
            }
            
            let chunk_data = if chunk.compressed {
                // 需要解压缩才能读取
                let mut temp_chunk = chunk.clone();
                if temp_chunk.decompress().is_ok() {
                    temp_chunk.data
                } else {
                    continue;
                }
            } else {
                chunk.data.clone()
            };
            
            let take_size = std::cmp::min(remaining, chunk_data.len());
            result.extend_from_slice(&chunk_data[..take_size]);
            remaining -= take_size;
        }
        
        result
    }
    
    /// 获取并移除数据
    pub fn pop(&mut self, size: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let mut remaining = size;
        
        while remaining > 0 && !self.chunks.is_empty() {
            let mut chunk = self.chunks.pop_front().unwrap();
            
            // 解压缩数据
            if chunk.compressed {
                if chunk.decompress().is_err() {
                    continue;
                }
            }
            
            let chunk_size = chunk.data.len();
            
            if chunk_size <= remaining {
                // 整个块都需要
                result.extend_from_slice(&chunk.data);
                remaining -= chunk_size;
                self.total_size -= chunk.size();
            } else {
                // 只需要块的一部分
                result.extend_from_slice(&chunk.data[..remaining]);
                
                // 创建剩余数据的新块
                let remaining_data = chunk.data[remaining..].to_vec();
                let new_chunk = DataChunk::new(remaining_data, chunk.sequence);
                self.chunks.push_front(new_chunk);
                
                self.total_size -= remaining;
                remaining = 0;
            }
        }
        
        // 更新统计信息
        self.stats.total_bytes_sent += result.len();
        self.stats.current_buffered_bytes = self.total_size;
        self.stats.chunk_count = self.chunks.len();
        
        result
    }
    
    /// 获取所有数据
    pub fn drain(&mut self) -> Vec<u8> {
        let total_size = self.total_size;
        self.pop(total_size)
    }
    
    /// 获取缓冲区大小
    pub fn size(&self) -> usize {
        self.total_size
    }
    
    /// 获取块数量
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
    
    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
    
    /// 是否已满
    pub fn is_full(&self) -> bool {
        self.total_size >= self.config.max_size || self.chunks.len() >= self.config.max_chunks
    }
    
    /// 清空缓冲区
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.total_size = 0;
        self.stats.current_buffered_bytes = 0;
        self.stats.chunk_count = 0;
    }
    
    /// 压缩所有数据
    pub fn compress_all(&mut self) -> Result<()> {
        if !self.config.enable_compression {
            return Ok(());
        }
        
        for chunk in &mut self.chunks {
            if !chunk.compressed && chunk.size() >= self.config.compression_threshold {
                let old_size = chunk.size();
                chunk.compress()?;
                let new_size = chunk.size();
                
                self.total_size = self.total_size - old_size + new_size;
                self.stats.compression_count += 1;
            }
        }
        
        self.stats.current_buffered_bytes = self.total_size;
        Ok(())
    }
    
    /// 清理过期数据
    pub fn cleanup(&mut self) -> Result<()> {
        let mut removed_size = 0;
        let mut removed_count = 0;
        
        while let Some(chunk) = self.chunks.front() {
            if chunk.is_expired(self.config.chunk_timeout) {
                let chunk = self.chunks.pop_front().unwrap();
                removed_size += chunk.size();
                removed_count += 1;
            } else {
                break;
            }
        }
        
        if removed_size > 0 {
            self.total_size -= removed_size;
            self.stats.current_buffered_bytes = self.total_size;
            self.stats.chunk_count = self.chunks.len();
            self.stats.dropped_bytes += removed_size;
            self.stats.cleanup_count += 1;
        }
        
        self.last_cleanup = Instant::now();
        Ok(())
    }
    
    /// 可能需要清理
    fn maybe_cleanup(&mut self) -> Result<()> {
        if self.last_cleanup.elapsed() >= self.config.cleanup_interval {
            self.cleanup()?;
        }
        Ok(())
    }
    
    /// 为新数据腾出空间
    fn make_space(&mut self, needed_size: usize) -> Result<()> {
        let mut freed_size = 0;
        
        // 首先尝试清理过期数据
        self.cleanup()?;
        
        // 如果还不够，移除最老的数据
        while freed_size < needed_size && !self.chunks.is_empty() {
            if let Some(chunk) = self.chunks.pop_front() {
                freed_size += chunk.size();
                self.total_size -= chunk.size();
                self.stats.dropped_bytes += chunk.size();
            }
        }
        
        // 检查是否有足够空间
        if self.total_size + needed_size > self.config.max_size {
            return Err(DetectorError::buffer_error(
                "Cannot make enough space in buffer".to_string()
            ));
        }
        
        self.stats.current_buffered_bytes = self.total_size;
        self.stats.chunk_count = self.chunks.len();
        
        Ok(())
    }
    
    /// 获取统计信息
    pub fn stats(&self) -> &BufferStats {
        &self.stats
    }
    
    /// 获取配置
    pub fn config(&self) -> &BufferConfig {
        &self.config
    }
    
    /// 更新配置
    pub fn update_config(&mut self, config: BufferConfig) {
        self.config = config;
    }
    
    /// 获取缓冲区利用率
    pub fn utilization(&self) -> f64 {
        if self.config.max_size == 0 {
            0.0
        } else {
            self.total_size as f64 / self.config.max_size as f64
        }
    }
    
    /// 获取压缩率
    pub fn compression_ratio(&self) -> f64 {
        let mut original_size = 0;
        let mut compressed_size = 0;
        
        for chunk in &self.chunks {
            if chunk.compressed {
                compressed_size += chunk.size();
                original_size += chunk.original_size.unwrap_or(chunk.size());
            } else {
                let size = chunk.size();
                compressed_size += size;
                original_size += size;
            }
        }
        
        if original_size == 0 {
            1.0
        } else {
            compressed_size as f64 / original_size as f64
        }
    }
}

impl Default for StreamBuffer {
    fn default() -> Self {
        Self::new(BufferConfig::default())
    }
}