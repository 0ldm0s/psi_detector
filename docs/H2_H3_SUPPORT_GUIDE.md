# HTTP/2 和 HTTP/3 协议支持指南

## 概述

PSI-Detector 现已全面支持现代 HTTP 协议的探测和识别，包括：

- **HTTP/1.0** - 传统 HTTP 协议
- **HTTP/1.1** - 改进的 HTTP 协议，支持持久连接
- **HTTP/2** - 二进制多路复用协议
- **HTTP/3** - 基于 QUIC 的下一代 HTTP 协议

## 功能特性

### 🎯 协议探测能力

| 协议 | 探测方式 | 置信度 | 特征识别 |
|------|----------|--------|----------|
| HTTP/1.1 | 文本模式匹配 | 90-95% | GET/POST/PUT 等方法 |
| HTTP/2 | 连接前言 + 帧格式 | 80-100% | PRI 前言、SETTINGS/HEADERS 帧 |
| HTTP/3 | QUIC + ALPN 标识 | 60-90% | QUIC 长包头 + h3 ALPN |

### 🔄 协议升级支持

- **HTTP/1.1 → HTTP/2 (h2c)**: 明文 HTTP/2 升级
- **HTTP/1.1 → WebSocket**: WebSocket 协议升级
- **TLS + ALPN**: 基于 ALPN 的协议协商

## 使用示例

### 基础协议探测

```rust
use psi_detector::{DetectorBuilder, ProtocolType};

// 创建支持现代 HTTP 协议的探测器
let detector = DetectorBuilder::new()
    .enable_http()      // HTTP/1.x
    .enable_http2()     // HTTP/2
    .enable_http3()     // HTTP/3
    .enable_tls()       // HTTPS
    .build()?;

// HTTP/2 连接前言探测
let http2_data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
match detector.detect(http2_data) {
    Ok(result) => {
        assert_eq!(result.protocol_type(), ProtocolType::HTTP2);
        println!("检测到 HTTP/2，置信度: {:.2}%", result.confidence() * 100.0);
    }
    Err(e) => eprintln!("探测失败: {}", e),
}
```

### HTTP/2 特性探测

```rust
// HTTP/2 SETTINGS 帧探测
let http2_settings = vec![
    // HTTP/2 连接前言
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
    // SETTINGS 帧
    vec![
        0x00, 0x00, 0x12, // 长度: 18字节
        0x04,             // 类型: SETTINGS
        0x00,             // 标志: 无
        0x00, 0x00, 0x00, 0x00, // 流ID: 0
        // SETTINGS 参数...
    ]
].concat();

let result = detector.detect(&http2_settings)?;
assert_eq!(result.protocol_type(), ProtocolType::HTTP2);
```

### HTTP/3 over QUIC 探测

```rust
// HTTP/3 over QUIC 数据包
let http3_data = vec![
    0x80,                   // QUIC 长包头标志
    0x00, 0x00, 0x00, 0x01, // QUIC v1
    0x08,                   // 连接ID长度
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // 连接ID
    // ALPN 扩展包含 "h3"
    0x68, 0x33, // "h3"
    // 更多数据...
];

let result = detector.detect(&http3_data)?;
// 注意: HTTP/3 可能被识别为 QUIC，因为 HTTP/3 基于 QUIC
assert!(matches!(result.protocol_type(), ProtocolType::HTTP3 | ProtocolType::QUIC));
```

### 协议升级场景

```rust
// HTTP/1.1 到 HTTP/2 升级请求
let h2c_upgrade = b"GET / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Connection: Upgrade, HTTP2-Settings\r\n\
                    Upgrade: h2c\r\n\
                    HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n";

let result = detector.detect(h2c_upgrade)?;
assert_eq!(result.protocol_type(), ProtocolType::HTTP1_1);

// 检查升级标识
let data_str = String::from_utf8_lossy(h2c_upgrade);
if data_str.contains("Upgrade: h2c") {
    println!("检测到 HTTP/2 升级请求");
}
```

## 示例程序

### 1. basic_detection.rs
基础协议探测示例，包含 HTTP/1.1、HTTP/2、HTTP/3 的测试数据。

```bash
cargo run --example basic_detection
```

### 2. protocol_upgrade.rs
协议升级场景演示，包括 H2C 升级、WebSocket 升级等。

```bash
cargo run --example protocol_upgrade
```

### 3. h2_h3_advanced.rs
**新增**：HTTP/2 和 HTTP/3 高级特性演示，包括：
- HTTP/2 连接前言和帧格式
- HTTP/3 over QUIC 探测
- TLS + ALPN 协商
- 性能测试

```bash
cargo run --example h2_h3_advanced
```

## 技术实现细节

### HTTP/2 探测逻辑

1. **连接前言检测**：
   ```rust
   const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
   if data.starts_with(HTTP2_PREFACE) {
       return Some(1.0); // 100% 置信度
   }
   ```

2. **帧格式检测**：
   ```rust
   if data.len() >= 9 {
       let frame_type = data[3];
       // SETTINGS帧 (0x4) 或 HEADERS帧 (0x1)
       if frame_type == 0x4 || frame_type == 0x1 {
           return Some(0.8); // 80% 置信度
       }
   }
   ```

### HTTP/3 探测逻辑

1. **基于 QUIC 检测**：
   ```rust
   if let Some(quic_confidence) = self.detect_quic(data) {
       if quic_confidence > 0.7 {
           // 检查 HTTP/3 特有标识
       }
   }
   ```

2. **ALPN 标识检测**：
   ```rust
   let data_str = String::from_utf8_lossy(data);
   if data_str.contains("h3") || data_str.contains("h3-") {
       return Some(0.9); // 90% 置信度
   }
   ```

### 构建器 API 扩展

```rust
impl DetectorBuilder {
    /// 启用 HTTP/2 协议探测
    pub fn enable_http2(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::HTTP2);
        self
    }
    
    /// 启用 HTTP/3 协议探测
    pub fn enable_http3(mut self) -> Self {
        self.enabled_protocols.insert(ProtocolType::HTTP3);
        self
    }
}
```

## 性能指标

基于 `h2_h3_advanced.rs` 示例的性能测试结果：

| 指标 | HTTP/1.1 | HTTP/2 | HTTP/3 |
|------|----------|--------|--------|
| 平均延迟 | ~6µs | ~7µs | ~9µs |
| 吞吐量 | ~160k/s | ~140k/s | ~110k/s |
| 内存使用 | 低 | 中 | 中 |

## 最佳实践

### 1. 协议优先级

建议按以下优先级启用协议：

```rust
let detector = DetectorBuilder::new()
    .enable_http3()     // 最新协议，优先检测
    .enable_http2()     // 现代协议
    .enable_http()      // 兼容性协议
    .enable_tls()       // 安全层
    .build()?;
```

### 2. 最小数据大小配置

不同协议需要不同的最小数据量：

```rust
let detector = DetectorBuilder::new()
    .with_min_probe_size(24)  // HTTP/2 需要至少 24 字节
    .build()?;
```

### 3. 置信度阈值

根据应用场景调整置信度：

```rust
let detector = DetectorBuilder::new()
    .with_min_confidence(0.8)  // 高精度场景
    // .with_min_confidence(0.6)  // 高召回场景
    .build()?;
```

## 故障排除

### 常见问题

1. **HTTP/3 被识别为 QUIC**
   - 原因：HTTP/3 基于 QUIC，需要更多上下文信息
   - 解决：增加 ALPN 标识检测，提高数据样本大小

2. **HTTP/2 探测失败**
   - 原因：数据不足或缺少连接前言
   - 解决：确保数据包含完整的 HTTP/2 前言或帧头

3. **性能问题**
   - 原因：启用过多协议或数据量过大
   - 解决：只启用必要的协议，优化数据大小

### 调试技巧

```rust
// 启用详细日志
let detector = DetectorBuilder::new()
    .with_strategy(ProbeStrategy::Passive)
    .with_timeout(Duration::from_millis(100))
    .build()?;

// 检查探测结果详情
match detector.detect(data) {
    Ok(result) => {
        println!("协议: {:?}", result.protocol_type());
        println!("置信度: {:.2}%", result.confidence() * 100.0);
        println!("处理时间: {:?}", result.detection_time);
        println!("探测方法: {:?}", result.detection_method);
    }
    Err(e) => eprintln!("探测失败: {}", e),
}
```

## 未来规划

- [ ] **HTTP/3 帧级别解析**：更精确的 HTTP/3 协议识别
- [ ] **gRPC over HTTP/3**：支持基于 HTTP/3 的 gRPC 探测
- [ ] **WebTransport**：支持 WebTransport 协议探测
- [ ] **性能优化**：SIMD 加速的 HTTP/2 和 HTTP/3 解析
- [ ] **协议升级管道**：自动化的协议升级处理

## 参考资料

- [RFC 7540 - HTTP/2](https://tools.ietf.org/html/rfc7540)
- [RFC 9114 - HTTP/3](https://tools.ietf.org/html/rfc9114)
- [RFC 9000 - QUIC](https://tools.ietf.org/html/rfc9000)
- [ALPN Extension](https://tools.ietf.org/html/rfc7301)