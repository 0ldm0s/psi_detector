//! PSI-Detector 客户端-服务端完整示例
//!
//! 本示例展示了一个完整的客户端-服务端架构，其中：
//! - 服务端监听多个端口，接收不同协议的连接
//! - 客户端发送各种协议的数据包
//! - 使用 PSI-Detector 进行实时协议探测和识别
//!
//! 支持的协议：HTTP/1.1, HTTP/2, HTTP/3, TLS, SSH, WebSocket, gRPC

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy,
    core::detector::DetectionResult,
};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

/// 服务端配置
#[derive(Debug, Clone)]
struct ServerConfig {
    /// 监听的端口列表
    ports: Vec<u16>,
    /// 每个端口对应的预期协议
    expected_protocols: HashMap<u16, ProtocolType>,
}

/// 协议探测统计信息
#[derive(Debug, Default)]
struct DetectionStats {
    total_connections: u32,
    successful_detections: u32,
    protocol_counts: HashMap<ProtocolType, u32>,
    average_detection_time: Duration,
}

/// 多协议服务端
struct MultiProtocolServer {
    config: ServerConfig,
    detector: Arc<dyn ProtocolDetector>,
    stats: Arc<Mutex<DetectionStats>>,
}

impl MultiProtocolServer {
    /// 创建新的多协议服务端
    fn new(config: ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let detector = DetectorBuilder::new()
            .enable_http()
            .enable_http2()
            .enable_http3()
            .enable_tls()
            .enable_ssh()
            .with_strategy(ProbeStrategy::Passive)
            .with_timeout(Duration::from_millis(100))
            .with_min_confidence(0.8)
            .with_min_probe_size(16)
            .build()?;

        Ok(Self {
            config,
            detector: Arc::new(detector),
            stats: Arc::new(Mutex::new(DetectionStats::default())),
        })
    }

    /// 启动服务端，监听所有配置的端口
    fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 启动多协议服务端...");
        println!("监听端口: {:?}", self.config.ports);
        println!("支持协议: HTTP/1.1, HTTP/2, HTTP/3, TLS, SSH, WebSocket, gRPC");
        println!();

        let mut handles = Vec::new();

        for &port in &self.config.ports {
            let detector = Arc::clone(&self.detector);
            let stats = Arc::clone(&self.stats);
            let expected_protocol = self.config.expected_protocols.get(&port).copied();

            let handle = thread::spawn(move || {
                if let Err(e) = Self::listen_on_port(port, detector, stats, expected_protocol) {
                    eprintln!("❌ 端口 {} 监听失败: {}", port, e);
                }
            });
            handles.push(handle);
        }

        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }

        Ok(())
    }

    /// 在指定端口监听连接
    fn listen_on_port(
        port: u16,
        detector: Arc<dyn ProtocolDetector>,
        stats: Arc<Mutex<DetectionStats>>,
        expected_protocol: Option<ProtocolType>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        println!("📡 端口 {} 开始监听...", port);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let detector = Arc::clone(&detector);
                    let stats = Arc::clone(&stats);
                    
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(
                            &mut stream, 
                            port, 
                            detector, 
                            stats, 
                            expected_protocol
                        ) {
                            eprintln!("❌ 处理连接失败: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("❌ 接受连接失败: {}", e);
                }
            }
        }

        Ok(())
    }

    /// 处理单个客户端连接
    fn handle_connection(
        stream: &mut TcpStream,
        port: u16,
        detector: Arc<dyn ProtocolDetector>,
        stats: Arc<Mutex<DetectionStats>>,
        expected_protocol: Option<ProtocolType>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let peer_addr = stream.peer_addr()?;
        println!("🔗 新连接来自 {} -> 端口 {}", peer_addr, port);

        // 读取初始数据进行协议探测
        let mut buffer = vec![0u8; 1024];
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            println!("⚠️  连接 {} 没有发送数据", peer_addr);
            return Ok(());
        }

        buffer.truncate(bytes_read);
        
        // 执行协议探测
        let start_time = Instant::now();
        let detection_result = detector.detect(&buffer).ok();
        let detection_time = start_time.elapsed();

        // 更新统计信息
        {
            let mut stats = stats.lock().unwrap();
            stats.total_connections += 1;
            
            if let Some(result) = &detection_result {
                stats.successful_detections += 1;
                *stats.protocol_counts.entry(result.protocol_type()).or_insert(0) += 1;
                
                // 更新平均探测时间
                let prev_total = stats.average_detection_time.as_nanos() * (stats.successful_detections - 1) as u128;
                let new_total = prev_total + detection_time.as_nanos();
                stats.average_detection_time = Duration::from_nanos((new_total / stats.successful_detections as u128) as u64);
            }
        }

        // 输出探测结果
        match &detection_result {
            Some(result) => {
                let status = if let Some(expected) = expected_protocol {
                    if result.protocol_type() == expected {
                        "✅ 匹配"
                    } else {
                        "⚠️  不匹配"
                    }
                } else {
                    "ℹ️  探测"
                };
                
                println!(
                    "{} 端口 {} | 协议: {:?} | 置信度: {:.2}% | 时间: {:.2}µs | 数据: {} bytes",
                    status,
                    port,
                    result.protocol_type(),
                    result.confidence() * 100.0,
                    detection_time.as_micros(),
                    bytes_read
                );
                
                if let Some(expected) = expected_protocol {
                    if result.protocol_type() != expected {
                        println!("   期望: {:?}, 实际: {:?}", expected, result.protocol_type());
                    }
                }
            }
            None => {
                println!(
                    "❓ 端口 {} | 协议: 未知 | 时间: {:.2}µs | 数据: {} bytes",
                    port,
                    detection_time.as_micros(),
                    bytes_read
                );
            }
        }

        // 发送简单响应
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nProtocol detected: {:?}\n",
            detection_result.as_ref().map(|r| r.protocol_type()).unwrap_or(ProtocolType::Unknown)
        );
        let _ = stream.write_all(response.as_bytes());

        Ok(())
    }

    /// 打印统计信息
    fn print_stats(&self) {
        let stats = self.stats.lock().unwrap();
        println!("\n📊 服务端统计信息:");
        println!("总连接数: {}", stats.total_connections);
        println!("成功探测: {}", stats.successful_detections);
        println!("探测成功率: {:.2}%", 
            if stats.total_connections > 0 {
                (stats.successful_detections as f64 / stats.total_connections as f64) * 100.0
            } else {
                0.0
            }
        );
        println!("平均探测时间: {:.2}µs", stats.average_detection_time.as_micros());
        println!("\n协议分布:");
        for (protocol, count) in &stats.protocol_counts {
            println!("  {:?}: {} 次", protocol, count);
        }
    }
}

/// 协议客户端
struct ProtocolClient;

impl ProtocolClient {
    /// 发送 HTTP/1.1 请求
    fn send_http1_request(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes())?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// 发送 HTTP/2 连接前言
    fn send_http2_preface(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        stream.write_all(preface)?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// 发送 TLS ClientHello
    fn send_tls_hello(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        let tls_hello = [
            0x16, 0x03, 0x01, 0x00, 0x2a, // TLS Handshake, version 3.1, length 42
            0x01, 0x00, 0x00, 0x26, // Client Hello, length 38
            0x03, 0x03, // Version TLS 1.2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (8 bytes)
            0x00, // Session ID length
            0x00, 0x02, // Cipher suites length
            0x00, 0x35, // Cipher suite
            0x01, 0x00, // Compression methods
        ];
        stream.write_all(&tls_hello)?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// 发送 SSH 协议标识
    fn send_ssh_ident(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        let ssh_ident = b"SSH-2.0-OpenSSH_8.0\r\n";
        stream.write_all(ssh_ident)?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// 发送 WebSocket 升级请求
    fn send_websocket_upgrade(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        let upgrade_request = concat!(
            "GET /chat HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "\r\n"
        );
        stream.write_all(upgrade_request.as_bytes())?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// 发送 gRPC 请求
    fn send_grpc_request(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        // gRPC over HTTP/2 with content-type
        let grpc_request = concat!(
            "POST /grpc.service/Method HTTP/2.0\r\n",
            "Content-Type: application/grpc+proto\r\n",
            "TE: trailers\r\n",
            "\r\n"
        );
        stream.write_all(grpc_request.as_bytes())?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// 运行所有客户端测试
    fn run_all_tests(ports: &[u16]) {
        println!("\n🔄 开始客户端测试...");
        
        let test_cases: Vec<(&str, fn(u16) -> Result<(), Box<dyn std::error::Error>>)> = vec![
            ("HTTP/1.1 请求", Self::send_http1_request as fn(u16) -> Result<(), Box<dyn std::error::Error>>),
            ("HTTP/2 连接前言", Self::send_http2_preface as fn(u16) -> Result<(), Box<dyn std::error::Error>>),
            ("TLS ClientHello", Self::send_tls_hello as fn(u16) -> Result<(), Box<dyn std::error::Error>>),
            ("SSH 协议标识", Self::send_ssh_ident as fn(u16) -> Result<(), Box<dyn std::error::Error>>),
            ("WebSocket 升级", Self::send_websocket_upgrade as fn(u16) -> Result<(), Box<dyn std::error::Error>>),
            ("gRPC 请求", Self::send_grpc_request as fn(u16) -> Result<(), Box<dyn std::error::Error>>),
        ];

        for (i, &port) in ports.iter().enumerate() {
            if i < test_cases.len() {
                let (test_name, test_fn) = &test_cases[i];
                println!("📤 发送 {} 到端口 {}", test_name, port);
                
                if let Err(e) = test_fn(port) {
                    eprintln!("❌ {} 失败: {}", test_name, e);
                } else {
                    println!("✅ {} 发送成功", test_name);
                }
                
                thread::sleep(Duration::from_millis(200));
            }
        }
        
        println!("\n✅ 客户端测试完成");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 PSI-Detector 客户端-服务端完整示例");
    println!("========================================\n");

    // 配置服务端
    let ports = vec![8080, 8081, 8082, 8083, 8084, 8085];
    let mut expected_protocols = HashMap::new();
    expected_protocols.insert(8080, ProtocolType::HTTP1_1);
    expected_protocols.insert(8081, ProtocolType::HTTP2);
    expected_protocols.insert(8082, ProtocolType::TLS);
    expected_protocols.insert(8083, ProtocolType::SSH);
    expected_protocols.insert(8084, ProtocolType::WebSocket);
    expected_protocols.insert(8085, ProtocolType::GRPC);

    let config = ServerConfig {
        ports: ports.clone(),
        expected_protocols,
    };

    // 创建服务端
    let server = MultiProtocolServer::new(config)?;
    let server_stats = Arc::clone(&server.stats);

    // 在单独线程中启动服务端
    let server_handle = {
        let server = Arc::new(server);
        let server_clone = Arc::clone(&server);
        thread::spawn(move || {
            if let Err(e) = server_clone.start() {
                eprintln!("❌ 服务端启动失败: {}", e);
            }
        })
    };

    // 等待服务端启动
    thread::sleep(Duration::from_secs(2));

    // 运行客户端测试
    ProtocolClient::run_all_tests(&ports);

    // 等待所有连接处理完成
    thread::sleep(Duration::from_secs(1));

    // 打印最终统计信息
    {
        let stats = server_stats.lock().unwrap();
        println!("\n📊 最终统计信息:");
        println!("总连接数: {}", stats.total_connections);
        println!("成功探测: {}", stats.successful_detections);
        println!("探测成功率: {:.2}%", 
            if stats.total_connections > 0 {
                (stats.successful_detections as f64 / stats.total_connections as f64) * 100.0
            } else {
                0.0
            }
        );
        println!("平均探测时间: {:.2}µs", stats.average_detection_time.as_micros());
        println!("\n协议分布:");
        for (protocol, count) in &stats.protocol_counts {
            println!("  {:?}: {} 次", protocol, count);
        }
    }

    println!("\n🎉 示例运行完成！");
    println!("\n💡 提示:");
    println!("- 服务端在多个端口监听不同协议");
    println!("- 客户端发送各种协议的测试数据");
    println!("- PSI-Detector 实时识别协议类型");
    println!("- 统计信息显示探测性能和准确性");

    // 注意：在实际应用中，你可能需要优雅地关闭服务端
    // 这里为了演示简单，让程序自然结束
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_creation() {
        let mut expected_protocols = HashMap::new();
        expected_protocols.insert(8080, ProtocolType::HTTP1_1);
        
        let config = ServerConfig {
            ports: vec![8080],
            expected_protocols,
        };
        
        assert_eq!(config.ports.len(), 1);
        assert_eq!(config.expected_protocols.get(&8080), Some(&ProtocolType::HTTP1_1));
    }

    #[test]
    fn test_detection_stats_default() {
        let stats = DetectionStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.successful_detections, 0);
        assert!(stats.protocol_counts.is_empty());
    }

    #[test]
    fn test_multi_protocol_server_creation() {
        let config = ServerConfig {
            ports: vec![8080],
            expected_protocols: HashMap::new(),
        };
        
        let server = MultiProtocolServer::new(config);
        assert!(server.is_ok());
    }
}