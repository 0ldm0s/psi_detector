# PSI-Detector

**Protocol Stream Intelligence Detector** - 高性能协议探测与升级框架

## 📋 项目概述

PSI-Detector 是一个用 Rust 编写的高性能协议探测和升级框架，专为现代网络应用设计。它能够实时识别网络流量中的协议类型，支持协议升级检测，并提供强大的 SIMD 优化性能。

### 🎯 核心特性

- **🔍 多协议支持**: HTTP/1.1, HTTP/2, HTTP/3, TLS, SSH, WebSocket, gRPC, QUIC, MQTT, DNS
- **🧩 插件系统**: 支持自定义协议探测器，可扩展的插件架构
- **⚡ 高性能**: SIMD 优化，微秒级探测延迟，支持 280k+ 检测/秒吞吐量
- **🛡️ 安全设计**: 被动探测，无侵入性，内存安全
- **🔧 易于集成**: 简洁的 Builder API，支持自定义配置
- **📊 实时统计**: 详细的性能指标和探测统计
- **🎛️ 灵活配置**: 可调节置信度阈值、超时时间、探测策略

### 🏗️ 架构特点

- **模块化设计**: 核心探测器、SIMD 优化、流处理、协议升级独立模块
- **插件架构**: 支持自定义探测器插件，灵活的协议扩展机制
- **零拷贝**: 高效的内存管理和数据处理
- **并发安全**: 线程安全的设计，支持高并发场景
- **可扩展性**: 易于添加新协议支持，支持 UDP/TCP 双栈协议

## 🚀 快速开始

### 基础用法

```rust
use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy,
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建探测器
    let detector = DetectorBuilder::new()
        .enable_http()          // 启用 HTTP/1.1 探测
        .enable_http2()         // 启用 HTTP/2 探测
        .enable_tls()           // 启用 TLS 探测
        .enable_ssh()           // 启用 SSH 探测
        .with_strategy(ProbeStrategy::Passive)
        .with_timeout(Duration::from_millis(100))
        .with_min_confidence(0.8)
        .build()?;

    // 探测协议
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = detector.detect(data)?;
    
    println!("协议类型: {:?}", result.protocol_type());
    println!("置信度: {:.2}%", result.confidence() * 100.0);
    println!("探测时间: {:?}", result.detection_time);
    
    Ok(())
}
```

### 客户端-服务端示例

```rust
use psi_detector::{DetectorBuilder, ProtocolDetector};
use std::net::{TcpListener, TcpStream};
use std::io::Read;

// 协议感知服务器
struct ProtocolAwareServer {
    detector: Box<dyn ProtocolDetector>,
}

impl ProtocolAwareServer {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let detector = DetectorBuilder::new()
            .enable_http()
            .enable_http2()
            .enable_tls()
            .build()?;
            
        Ok(Self {
            detector: Box::new(detector),
        })
    }
    
    fn handle_connection(&self, mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; 1024];
        let bytes_read = stream.read(&mut buffer)?;
        buffer.truncate(bytes_read);
        
        match self.detector.detect(&buffer) {
            Ok(result) => {
                println!("检测到协议: {:?}, 置信度: {:.1}%", 
                    result.protocol_type(), 
                    result.confidence() * 100.0
                );
                // 根据协议类型处理请求...
            }
            Err(e) => {
                println!("协议探测失败: {}", e);
            }
        }
        
        Ok(())
    }
}
```

## 📚 API 文档

### DetectorBuilder

构建器模式用于创建和配置协议探测器。

```rust
let detector = DetectorBuilder::new()
    .enable_http()                              // 启用 HTTP/1.1
    .enable_http2()                             // 启用 HTTP/2
    .enable_http3()                             // 启用 HTTP/3
    .enable_tls()                               // 启用 TLS
    .enable_ssh()                               // 启用 SSH
    .add_custom_probe(Box::new(DnsProbe))       // 添加自定义 DNS 探测器
    .add_custom_probe(Box::new(MqttProbe))      // 添加自定义 MQTT 探测器
    .with_strategy(ProbeStrategy::Passive)      // 设置探测策略
    .with_timeout(Duration::from_millis(100))   // 设置超时时间
    .with_min_confidence(0.8)                   // 设置最小置信度
    .with_min_probe_size(16)                    // 设置最小探测数据大小
    .build()?;
```

### ProtocolDetector Trait

核心探测接口，提供协议识别功能。

```rust
pub trait ProtocolDetector {
    fn detect(&self, data: &[u8]) -> Result<DetectionResult, DetectorError>;
}
```

### DetectionResult

探测结果包含协议类型、置信度和性能指标。

```rust
pub struct DetectionResult {
    pub protocol_info: ProtocolInfo,
    pub detection_time: Duration,
    pub detection_method: DetectionMethod,
    pub detector_name: String,
}

impl DetectionResult {
    pub fn protocol_type(&self) -> ProtocolType;
    pub fn confidence(&self) -> f32;
    pub fn is_high_confidence(&self) -> bool;
}
```

### 支持的协议类型

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    HTTP1_0,
    HTTP1_1,
    HTTP2,
    HTTP3,
    TLS,
    SSH,
    WebSocket,
    GRPC,
    QUIC,
    MQTT,
    DNS,        // 新增 DNS 协议支持
    TCP,
    UDP,        // 新增 UDP 协议支持
    Unknown,
}
```

## 🎯 示例程序

项目提供了丰富的示例程序，展示不同使用场景：

### 基础示例

```bash
# 基础协议探测
cargo run --example basic_detection

# 流式协议探测
cargo run --example streaming_detection

# 并发性能测试
cargo run --example concurrent_detection

# SIMD 性能测试
cargo run --example simd_performance
```

### 高级示例

```bash
# 协议升级检测
cargo run --example protocol_upgrade

# HTTP/2 和 HTTP/3 高级特性
cargo run --example h2_h3_advanced

# 完整客户端-服务端演示
cargo run --example client_server_demo

# 简化集成示例
cargo run --example simple_client_server

# 插件系统演示（DNS/MQTT 自定义探测器）
cargo run --example plugin_system_demo
```

### 自定义配置

```bash
# 自定义配置示例
cargo run --example custom_configuration
```

## 🧩 插件系统

### 自定义协议探测器

PSI-Detector 支持通过插件系统扩展协议支持，您可以轻松添加自定义协议探测器：

```rust
use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::{ProtocolProbe, ProtocolInfo, ProbeResult},
};

// 实现自定义 DNS 探测器
struct DnsProbe;

impl ProtocolProbe for DnsProbe {
    fn probe(&self, data: &[u8]) -> ProbeResult {
        if data.len() < 12 {
            return ProbeResult::NotDetected;
        }
        
        // DNS 头部验证逻辑
        let confidence = self.calculate_confidence(data);
        
        if confidence > 0.5 {
            let mut info = ProtocolInfo::new(ProtocolType::DNS, confidence);
            info.add_feature("query_type", "standard");
            info.add_metadata("header_valid", "true");
            ProbeResult::Detected(info)
        } else {
            ProbeResult::NotDetected
        }
    }
    
    fn supported_protocols(&self) -> Vec<ProtocolType> {
        vec![ProtocolType::DNS]
    }
    
    fn name(&self) -> &'static str {
        "DNS Probe"
    }
}

// 使用自定义探测器
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = DetectorBuilder::new()
        .enable_http()
        .add_custom_probe(Box::new(DnsProbe))  // 添加自定义探测器
        .build()?;
    
    // DNS 查询数据包
    let dns_query = create_dns_query_packet();
    let result = detector.detect(&dns_query)?;
    
    println!("检测到协议: {:?}", result.protocol_type());
    println!("置信度: {:.1}%", result.confidence() * 100.0);
    
    Ok(())
}
```

### 插件优先级管理

```rust
// 演示插件优先级和多协议探测
let detector = DetectorBuilder::new()
    .enable_http()                           // 内置协议
    .add_custom_probe(Box::new(DnsProbe))    // 自定义 DNS 探测器
    .add_custom_probe(Box::new(MqttProbe))   // 自定义 MQTT 探测器
    .with_min_confidence(0.6)                // 设置置信度阈值
    .build()?;

// 测试不同协议数据
let test_cases = vec![
    ("HTTP", create_http_request()),
    ("DNS", create_dns_query_packet()),
    ("MQTT", create_mqtt_connect_packet()),
];

for (name, data) in test_cases {
    match detector.detect(&data) {
        Ok(result) => {
            println!("{}: {:?} (置信度: {:.1}%)", 
                name, result.protocol_type(), result.confidence() * 100.0);
        }
        Err(e) => println!("{}: 探测失败 - {}", name, e),
    }
}
```

## 📊 性能指标

### 基准测试结果

| 指标 | 数值 | 说明 |
|------|------|------|
| **探测延迟** | 2-5 μs | 单次协议探测平均时间 |
| **吞吐量** | 289,503 检测/秒 | 并发处理能力 |
| **并发提升** | 3.91x | 相比单线程的性能提升 |
| **准确率** | 90-98% | 协议识别准确率 |
| **内存使用** | < 1MB | 运行时内存占用 |

### SIMD 优化效果

- **x86_64**: 支持 AVX2/SSE4.2 指令集优化
- **AArch64**: 支持 NEON 指令集优化
- **性能提升**: 相比标量实现提升 2-4 倍

### 协议探测准确率

| 协议 | 准确率 | 最小数据量 |
|------|--------|------------|
| HTTP/1.1 | 95% | 16 bytes |
| HTTP/2 | 100% | 24 bytes |
| TLS | 95% | 47 bytes |
| SSH | 98% | 21 bytes |
| WebSocket | 95% | 152 bytes |
| gRPC | 90% | 90 bytes |
| DNS | 92% | 12 bytes |
| MQTT | 88% | 14 bytes |

## 🏗️ 项目结构

```
psi_detector/
├── src/
│   ├── lib.rs              # 库入口
│   ├── builder.rs          # 构建器实现
│   ├── error.rs            # 错误类型定义
│   ├── core/               # 核心模块
│   │   ├── mod.rs
│   │   ├── detector.rs     # 探测器核心逻辑
│   │   ├── protocol.rs     # 协议类型定义
│   │   └── strategy.rs     # 探测策略
│   ├── probe/              # 探测实现
│   │   ├── mod.rs
│   │   ├── passive.rs      # 被动探测
│   │   └── active.rs       # 主动探测
│   ├── simd/               # SIMD 优化
│   │   ├── mod.rs
│   │   ├── x86_64.rs       # x86_64 优化
│   │   └── aarch64.rs      # AArch64 优化
│   ├── stream/             # 流处理
│   │   ├── mod.rs
│   │   └── buffer.rs       # 缓冲区管理
│   ├── upgrade/            # 协议升级
│   │   ├── mod.rs
│   │   └── detector.rs     # 升级检测
│   └── utils/              # 工具函数
│       ├── mod.rs
│       └── helpers.rs
├── examples/               # 示例程序
├── tests/                  # 测试用例
├── docs/                   # 文档
└── benches/                # 性能测试
```

## 🔧 配置选项

### 探测策略

```rust
pub enum ProbeStrategy {
    Passive,    // 被动探测（推荐）
    Active,     // 主动探测
    Hybrid,     // 混合模式
}
```

### 性能调优

```rust
let detector = DetectorBuilder::new()
    .with_min_probe_size(32)        // 增加最小探测数据大小提高准确率
    .with_timeout(Duration::from_millis(50))  // 减少超时时间提高响应速度
    .with_min_confidence(0.9)       // 提高置信度阈值减少误报
    .enable_simd_optimization()     // 启用 SIMD 优化
    .build()?;
```

### 内存优化

```rust
let detector = DetectorBuilder::new()
    .with_buffer_size(1024)         // 设置缓冲区大小
    .with_max_concurrent_detections(100)  // 限制并发检测数量
    .enable_zero_copy()             // 启用零拷贝优化
    .build()?;
```

## 🧪 测试

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定测试模块
cargo test core_detector_tests
cargo test simd_tests
cargo test integration_tests

# 运行性能测试
cargo test --release -- --ignored
```

### 基准测试

```bash
# 运行基准测试
cargo bench

# 生成性能报告
cargo bench -- --output-format html
```

## 🔍 故障排除

### 常见问题

**Q: 协议探测失败，返回 "Insufficient data" 错误**

A: 检查输入数据大小是否满足最小要求，可以通过 `with_min_probe_size()` 调整阈值。

```rust
let detector = DetectorBuilder::new()
    .with_min_probe_size(8)  // 降低最小数据要求
    .build()?;
```

**Q: 探测准确率不高**

A: 尝试调整置信度阈值或启用更多协议支持：

```rust
let detector = DetectorBuilder::new()
    .with_min_confidence(0.7)  // 降低置信度阈值
    .enable_http()
    .enable_http2()
    .enable_tls()
    .build()?;
```

**Q: 性能不达预期**

A: 启用 SIMD 优化和调整并发参数：

```rust
let detector = DetectorBuilder::new()
    .enable_simd_optimization()
    .with_timeout(Duration::from_millis(10))  // 减少超时时间
    .build()?;
```

### 调试模式

```rust
use log::info;

// 启用详细日志
env_logger::init();

let detector = DetectorBuilder::new()
    .with_debug_mode(true)
    .build()?;

let result = detector.detect(data)?;
info!("探测结果: {:?}", result);
```

## 📈 性能优化建议

### 1. 选择合适的探测策略

- **被动探测**: 适用于大多数场景，安全且高效
- **主动探测**: 适用于需要主动发起连接的场景
- **混合模式**: 平衡准确率和性能

### 2. 调整配置参数

```rust
// 高性能配置
let detector = DetectorBuilder::new()
    .with_strategy(ProbeStrategy::Passive)
    .with_timeout(Duration::from_millis(10))
    .with_min_confidence(0.8)
    .with_min_probe_size(16)
    .enable_simd_optimization()
    .build()?;
```

### 3. 并发处理优化

```rust
use std::sync::Arc;
use std::thread;

let detector = Arc::new(detector);
let handles: Vec<_> = (0..num_cpus::get())
    .map(|_| {
        let detector = Arc::clone(&detector);
        thread::spawn(move || {
            // 并发处理逻辑
        })
    })
    .collect();
```

## 🔗 集成指南

### 与现有网络栈集成

```rust
use tokio::net::TcpStream;
use psi_detector::DetectorBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .build()?;
    
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    
    // 读取初始数据进行协议探测
    let mut buffer = vec![0u8; 1024];
    let n = stream.try_read(&mut buffer)?;
    buffer.truncate(n);
    
    let result = detector.detect(&buffer)?;
    
    match result.protocol_type() {
        ProtocolType::HTTP1_1 => {
            // 处理 HTTP/1.1 连接
        }
        ProtocolType::TLS => {
            // 处理 TLS 连接
        }
        _ => {
            // 处理其他协议
        }
    }
    
    Ok(())
}
```

### 与 Web 框架集成

```rust
use axum::{extract::Request, middleware::Next, response::Response};
use psi_detector::DetectorBuilder;

// 协议探测中间件
async fn protocol_detection_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let detector = DetectorBuilder::new()
        .enable_http()
        .enable_http2()
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // 从请求中提取协议信息
    // ...
    
    let response = next.run(request).await;
    Ok(response)
}
```

## 📋 版本历史

### v0.1.0 (当前版本)

- ✅ 核心协议探测功能
- ✅ HTTP/1.1, HTTP/2, TLS, SSH 支持
- ✅ 插件系统架构，支持自定义协议探测器
- ✅ DNS 和 MQTT 协议支持
- ✅ UDP/TCP 双栈协议支持
- ✅ SIMD 优化实现
- ✅ 被动探测策略
- ✅ 基础性能测试
- ✅ 示例程序和文档

### 计划功能

- 🔄 HTTP/3 完整支持
- 🔄 更多协议支持 (FTP, SMTP, POP3, IMAP, etc.)
- 🔄 插件热加载机制
- 🔄 机器学习增强探测
- 🔄 协议指纹识别
- 🔄 实时流量分析
- 🔄 插件市场和生态系统

## 🤝 贡献指南

### 开发环境设置

```bash
# 克隆项目
git clone <repository-url>
cd psi_detector

# 安装依赖
cargo build

# 运行测试
cargo test

# 运行示例
cargo run --example basic_detection
```

### 代码规范

- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查代码质量
- 编写充分的测试用例
- 更新相关文档

### 提交规范

```
feat: 添加新功能
fix: 修复 bug
docs: 更新文档
test: 添加测试
perf: 性能优化
refactor: 代码重构
```

## 📄 许可证

本项目为内部项目，版权所有。未经授权不得复制、分发或修改。

## 📞 联系方式

如有问题或建议，请联系开发团队。

---

**PSI-Detector** - 让协议探测变得简单而强大 🚀