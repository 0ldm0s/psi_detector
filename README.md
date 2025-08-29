# PSI-Detector 🧙‍♂️

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Performance](https://img.shields.io/badge/performance-2.3x_faster-green.svg)](examples/protocol_filtering_performance.rs)

**PSI-Detector** (Protocol Stream Identifier Detector) 是一个高性能的协议检测和升级框架，专为现代网络应用设计。通过智能的协议识别、魔法包特征检测和严格的过滤机制，为您的网络服务提供企业级的性能和安全保障。

## ✨ 核心特性

### 🚀 超高性能
- **2.3倍性能提升** - 严格协议过滤机制
- **魔法包检测** - 前几个字节的启发式快速判断  
- **SIMD加速** - 利用现代CPU指令集优化
- **零拷贝设计** - 最小化内存分配和拷贝

### 🛡️ 企业级安全
- **攻击面缩小** - 只响应配置的协议，其他流量被静默丢弃
- **扫描器欺骗** - 让端口扫描器误认为端口关闭
- **严格模式** - 强制配置验证，防止意外暴露
- **协议隔离** - 不同服务类型完全隔离

### 🎯 智能检测
- **15+ 预置协议** - HTTP/1.1, HTTP/2, HTTP/3, TLS, QUIC, SSH, WebSocket等
- **自定义协议** - 轻松添加游戏、IoT或专有协议
- **双向框架** - 支持服务器和客户端模式
- **协议升级** - 智能协议协商和升级

### 🔧 开发者友好
- **链式API** - 直观的构建器模式
- **预设配置** - 针对不同场景的优化配置
- **详细错误** - 清晰的配置指导和错误信息
- **丰富示例** - 涵盖各种使用场景

---

## 🚀 快速开始

### 安装

```toml
[dependencies]
psi_detector = "0.1.1"
```

### 基础用法

```rust
use psi_detector::{DetectorBuilder, ProtocolType};

// 创建HTTP服务器检测器
let detector = DetectorBuilder::new()
    .enable_http()
    .enable_websocket()
    .enable_tls()
    .high_performance()
    .build()?;

// 检测协议
let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
let result = detector.detect(data)?;

println!("检测到协议: {} (置信度: {:.1}%)", 
         result.protocol_type(), 
         result.confidence() * 100.0);
```

---

## 📋 应用场景配置

### 🌐 HTTP/Web服务器
**适用于**：Web应用、API服务、微服务网关

```rust
let detector = DetectorBuilder::new()
    .enable_http()       // HTTP/1.1 支持
    .enable_http2()      // HTTP/2 支持  
    .enable_websocket()  // WebSocket 支持
    .enable_tls()        // HTTPS 支持
    .high_performance()  // 性能优化
    .build()?;
```

**效果**：
- ✅ 检测 HTTP/HTTPS/WebSocket 流量
- ❌ 过滤 SSH、数据库、游戏协议
- 🛡️ 对扫描器隐藏真实服务类型

### 🎮 游戏服务器
**适用于**：游戏后端、实时应用、IoT设备

```rust
// 定义自定义游戏协议
let game_probe = create_game_protocol_probe(); // 您的实现

let detector = DetectorBuilder::new()
    .enable_custom()                    // 启用自定义协议
    .add_custom_probe(Box::new(game_probe))
    .high_performance()
    .build()?;
```

**效果**：
- ✅ 只检测游戏协议数据包
- ❌ 100%过滤HTTP、SSH等协议
- 🚀 最高2.3倍性能提升
- 🔒 对网络扫描完全隐身

### 🔐 SSH/远程访问服务器
**适用于**：堡垒机、远程管理、安全隧道

```rust
let detector = DetectorBuilder::new()
    .enable_ssh()        // SSH协议支持
    .enable_tls()        // 安全隧道支持
    .high_accuracy()     // 高精度模式
    .build()?;
```

**效果**：
- ✅ 检测SSH和安全连接
- ❌ 忽略Web攻击和扫描
- 🔍 高精度识别避免误判

### 🌍 多协议网关
**适用于**：API网关、代理服务、协议转换

```rust
let detector = DetectorBuilder::new()
    .enable_http()
    .enable_http2() 
    .enable_grpc()      // gRPC支持
    .enable_quic()      // QUIC/HTTP3支持
    .enable_tls()
    .balanced()         // 平衡性能和精度
    .build()?;
```

**效果**：
- ✅ 支持现代Web协议栈
- ❌ 过滤传统和专有协议
- ⚖️ 性能与功能平衡

---

## 🎯 Agent模式（双向框架）

PSI-Detector支持服务器和客户端双向检测：

### 服务器Agent（被动检测）
```rust
use psi_detector::core::detector::{Role, Agent};

let server_agent = DetectorBuilder::new()
    .enable_http()
    .enable_tls()
    .with_role(Role::Server)           // 服务器角色
    .with_instance_id("web-server-01") // 实例标识
    .build_agent()?;

// 被动检测传入连接
let result = server_agent.detect(incoming_data)?;
```

### 客户端Agent（主动探测）
```rust
let client_agent = DetectorBuilder::new()
    .enable_http2()
    .enable_quic()
    .with_role(Role::Client)           // 客户端角色
    .build_agent()?;

// 主动探测服务器能力
let supported_protocols = client_agent.probe_capabilities(&mut transport)?;
```

### 负载均衡配置
```rust
let lb_agent = DetectorBuilder::new()
    .enable_http()
    .with_role(Role::Server)
    .with_load_balancer(
        LoadBalanceStrategy::RoundRobin,
        vec!["backend-1".to_string(), "backend-2".to_string()]
    )
    .build_agent()?;
```

---

## 🔮 魔法包特征检测

PSI-Detector内置超高速魔法包检测，可在前几个字节内识别协议：

### 预置协议特征

| 协议 | 魔法字节 | 置信度 | 检测速度 |
|------|----------|--------|----------|
| HTTP/1.1 | `GET `, `POST `, `HTTP/` | 95%-98% | ~1800 ns |
| HTTP/2 | `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` | 100% | ~1700 ns |
| TLS | `0x16, 0x03` | 90% | ~3400 ns |
| SSH | `SSH-` | 99% | ~1500 ns |
| QUIC | `0x80` (长头部) | 70% | ~1600 ns |

### 自定义协议特征
```rust
use psi_detector::core::magic::{MagicDetector, CustomSignatureBuilder};

let mut detector = MagicDetector::new();

// 添加自定义协议特征
let custom_sig = CustomSignatureBuilder::new(ProtocolType::Custom, "My Game Protocol")
    .with_magic_string("GAME")     // 魔法字符串
    .with_confidence(0.95)         // 置信度
    .with_offset(0)                // 偏移位置
    .case_insensitive()            // 不区分大小写
    .build();

detector.add_signature(custom_sig);

// 快速检测
let result = detector.quick_detect(b"GAME v1.0 login request");
```

---

## ⚡ 性能配置

### 高性能模式
**适用于**：高并发场景、实时应用

```rust
let detector = DetectorBuilder::new()
    .enable_http()
    .high_performance()    // 性能优先配置
    .build()?;
```

**特点**：
- ✅ 启用SIMD加速
- ✅ 被动探测策略（50ms超时）
- ✅ 大缓冲区（8KB）
- ✅ CPU保护机制

### 高精度模式  
**适用于**：安全要求高、误判成本大的场景

```rust
let detector = DetectorBuilder::new()
    .enable_all()
    .high_accuracy()       // 精度优先配置
    .build()?;
```

**特点**：
- ✅ 启用启发式探测
- ✅ 较长超时时间（200ms）
- ✅ 高置信度阈值（90%）
- ✅ 深度特征分析

### 平衡模式
**适用于**：一般应用场景

```rust
let detector = DetectorBuilder::new()
    .enable_http()
    .enable_tls()
    .balanced()           // 平衡配置
    .build()?;
```

**特点**：
- ⚖️ SIMD + 启发式
- ⚖️ 中等超时（100ms）
- ⚖️ 平衡置信度（80%）

### 自定义配置
```rust
let detector = DetectorBuilder::new()
    .enable_http()
    .with_strategy(ProbeStrategy::Passive)
    .with_timeout(Duration::from_millis(50))
    .with_min_confidence(0.85)
    .enable_simd()
    .enable_heuristic()
    .with_buffer_size(4096)
    .build()?;
```

---

## 🧙‍♂️ 尤里主题（特殊模式）

致敬经典，PSI-Detector提供特殊的"心灵"检测模式：

### 心灵探测模式
```rust
let detector = DetectorBuilder::new()
    .enable_http()
    .psychic_detection()   // 高精度被动探测
    .build()?;
```

### 心灵控制模式  
```rust
let detector = DetectorBuilder::new()
    .enable_all()
    .mind_control()        // 高性能被动探测
    .build()?;
```

### 心灵风暴模式
```rust
let detector = DetectorBuilder::new()
    .psychic_storm()       // 全面被动探测
    .build()?;
```

---

## 📊 性能基准测试

运行性能测试：

```bash
# 基础性能测试
cargo run --example magic_bytes_performance

# 协议过滤性能对比
cargo run --example protocol_filtering_performance

# 实际场景模拟
cargo run --example real_world_scenarios
```

### 基准数据

| 测试场景 | 检测时间 | 吞吐量 | 性能提升 |
|---------|---------|--------|----------|
| 魔法包检测 | 1,108 ns | 902K/秒 | 2.08x |
| 游戏服务器 | 4,420 ns | 226K/秒 | 2.30x |
| HTTP服务器 | 7,880 ns | 127K/秒 | 1.29x |
| 标准检测 | 2,303 ns | 434K/秒 | 1.00x |

---

## 🛠️ 进阶功能

### 异步支持
```rust
#[cfg(feature = "runtime-tokio")]
use psi_detector::core::detector::AsyncProtocolDetector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = DetectorBuilder::new()
        .enable_http()
        .build()?;
    
    let result = detector.detect_async(data).await?;
    Ok(())
}
```

### 批量检测
```rust
let data_chunks = vec![
    http_request.as_slice(),
    tls_handshake.as_slice(),
    ssh_banner.as_slice(),
];

let results = detector.detect_batch(&data_chunks)?;
for result in results {
    println!("协议: {}", result.protocol_type());
}
```

### 统计信息
```rust
use psi_detector::core::detector::DetectionStats;

let mut stats = DetectionStats::new();

// 检测并记录统计
let result = detector.detect(data)?;
stats.record_success(result.protocol_type(), result.detection_time);

// 查看统计
println!("成功率: {:.1}%", stats.success_rate() * 100.0);
println!("最常见协议: {:?}", stats.most_common_protocol());
println!("平均检测时间: {:?}", stats.avg_detection_time);
```

---

## 🔧 集成示例

### 与 Tokio 集成
```rust
use tokio::net::TcpListener;
use psi_detector::{DetectorBuilder, ProtocolType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = DetectorBuilder::new()
        .enable_http()
        .enable_tls()
        .high_performance()
        .build()?;
    
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    
    loop {
        let (mut socket, _) = listener.accept().await?;
        let detector = detector.clone(); // 需要实现Clone
        
        tokio::spawn(async move {
            let mut buf = [0; 1024];
            if let Ok(n) = socket.read(&mut buf).await {
                if let Ok(result) = detector.detect(&buf[..n]) {
                    match result.protocol_type() {
                        ProtocolType::HTTP1_1 => {
                            // 处理HTTP请求
                        }
                        ProtocolType::TLS => {
                            // 处理HTTPS请求
                        }
                        _ => {
                            // 其他协议或拒绝连接
                        }
                    }
                }
            }
        });
    }
}
```

### 与 mammoth_transport 集成
```rust
use mammoth_transport::{TransportBuilder, ProtocolRouter};
use psi_detector::DetectorBuilder;

let detector = DetectorBuilder::new()
    .enable_http()
    .enable_quic()
    .enable_tls()
    .build()?;

let transport = TransportBuilder::new()
    .with_protocol_detector(detector)
    .with_auto_routing()
    .build()?;
```

---

## 🚨 安全最佳实践

### 1. 最小权限原则
```rust
// ❌ 错误：启用所有协议
let detector = DetectorBuilder::new().enable_all().build()?;

// ✅ 正确：只启用需要的协议
let detector = DetectorBuilder::new()
    .enable_http()
    .enable_tls()
    .build()?;
```

### 2. 严格配置验证
```rust
// PSI-Detector 强制配置验证
let result = DetectorBuilder::new().build(); // 将失败

match result {
    Err(e) => {
        // 会收到详细的配置指导
        println!("配置错误: {}", e);
    }
    Ok(_) => unreachable!(),
}
```

### 3. 监控和日志
```rust
use psi_detector::utils::logger;

// 启用详细日志
logger::init_logger(log::LevelFilter::Debug);

let result = detector.detect(data)?;
// 自动记录检测过程和结果
```

### 4. 错误处理
```rust
match detector.detect(suspicious_data) {
    Ok(result) => {
        if result.confidence() < 0.5 {
            // 低置信度，可能是攻击
            log::warn!("检测到可疑流量: {:?}", result);
        }
    }
    Err(e) => {
        // 检测失败，记录并拒绝连接
        log::error!("协议检测失败: {}", e);
        // 静默拒绝连接
    }
}
```

---

## 🐛 故障排除

### 常见问题

#### Q: 编译错误："至少需要启用一个协议"
```rust
// ❌ 问题代码
let detector = DetectorBuilder::new().build()?;

// ✅ 解决方案
let detector = DetectorBuilder::new()
    .enable_http()  // 至少启用一个协议
    .build()?;
```

#### Q: 性能不如预期
```rust
// ✅ 使用高性能配置
let detector = DetectorBuilder::new()
    .enable_http()
    .high_performance()    // 关键！
    .build()?;

// ✅ 避免启用过多协议
// ❌ 不要: .enable_all()
// ✅ 推荐: 只启用需要的协议
```

#### Q: 误检率高
```rust
// ✅ 使用高精度模式
let detector = DetectorBuilder::new()
    .enable_http()
    .enable_tls()
    .high_accuracy()       // 提高精度
    .build()?;
```

#### Q: 自定义协议无法检测
```rust
// ✅ 确保启用自定义协议
let detector = DetectorBuilder::new()
    .enable_custom()       // 必须启用！
    .add_custom_probe(your_probe)
    .build()?;
```

### 调试技巧

#### 启用详细日志
```rust
// 在main函数开始添加
env_logger::init();
std::env::set_var("RUST_LOG", "psi_detector=debug");
```

#### 性能分析
```rust
use std::time::Instant;

let start = Instant::now();
let result = detector.detect(data)?;
let duration = start.elapsed();

if duration.as_millis() > 10 {
    println!("检测耗时过长: {:?}", duration);
}
```

---

## 📚 API 参考

### 核心类型

#### `DetectorBuilder`
构建器模式配置探测器
- `enable_*()` - 启用特定协议
- `with_*()` - 设置配置参数  
- `high_performance()` - 性能优化预设
- `build()` - 构建探测器实例

#### `ProtocolDetector`
协议检测核心接口
- `detect(&self, data: &[u8]) -> Result<DetectionResult>` - 检测协议
- `confidence(&self, data: &[u8]) -> Result<f32>` - 获取置信度
- `supported_protocols(&self) -> Vec<ProtocolType>` - 支持的协议

#### `DetectionResult`
检测结果
- `protocol_type(&self) -> ProtocolType` - 协议类型
- `confidence(&self) -> f32` - 置信度(0.0-1.0)
- `detection_time(&self) -> Duration` - 检测耗时
- `is_high_confidence(&self) -> bool` - 是否高置信度

#### `ProtocolType`
支持的协议类型
- `HTTP1_1`, `HTTP2`, `HTTP3` - HTTP协议族
- `TLS`, `QUIC` - 安全协议
- `SSH`, `FTP`, `SMTP` - 传统协议  
- `WebSocket`, `GRPC` - 现代协议
- `Custom` - 自定义协议

---

## 🤝 贡献指南

我们欢迎各种形式的贡献！

### 报告Bug
1. 使用 [GitHub Issues](https://github.com/your-org/psi-detector/issues)
2. 提供详细的重现步骤
3. 包含系统信息和错误日志

### 功能请求
1. 先检查是否有类似的Issue
2. 详细描述用例和预期行为
3. 考虑向后兼容性

### 代码贡献
1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 开发环境设置
```bash
# 克隆项目
git clone https://github.com/your-org/psi-detector.git
cd psi-detector

# 运行测试
cargo test

# 运行示例
cargo run --example magic_bytes_performance

# 代码格式化
cargo fmt

# 代码检查  
cargo clippy
```

---

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

---

## 🙏 致谢

- 感谢 Rust 社区的优秀生态
- 灵感来源于经典游戏《红色警戒2》中的尤里
- 参考了现代网络协议检测的最佳实践

---

## 📞 联系我们

- 📧 Email: [your-email@example.com](mailto:your-email@example.com)
- 💬 讨论: [GitHub Discussions](https://github.com/your-org/psi-detector/discussions)
- 🐛 问题: [GitHub Issues](https://github.com/your-org/psi-detector/issues)
- 📖 文档: [docs.rs](https://docs.rs/psi-detector)

---

**让我们一起构建更快、更安全的网络应用！** 🚀

---

<div align="center">

**PSI-Detector** - 心灵感应般的协议检测 🧙‍♂️

[快速开始](#-快速开始) • [性能测试](#-性能基准测试) • [API文档](https://docs.rs/psi-detector) • [示例代码](examples/)

</div>