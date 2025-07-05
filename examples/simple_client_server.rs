//! PSI-Detector 简化客户端-服务端示例
//!
//! 这是一个更简洁的示例，展示如何在实际应用中集成协议探测功能
//! 适合快速理解和集成到现有项目中

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

/// 简单的协议感知服务器
struct ProtocolAwareServer {
    detector: Box<dyn ProtocolDetector>,
    port: u16,
}

impl ProtocolAwareServer {
    /// 创建新的协议感知服务器
    fn new(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let detector = DetectorBuilder::new()
            .enable_http()
            .enable_http2()
            .enable_tls()
            .enable_ssh()
            .with_strategy(ProbeStrategy::Passive)
            .with_min_confidence(0.7)
            .build()?;

        Ok(Self {
            detector: Box::new(detector),
            port,
        })
    }

    /// 启动服务器
    fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))?;
        println!("🚀 协议感知服务器启动在端口 {}", self.port);
        println!("等待客户端连接...");

        for (i, stream) in listener.incoming().enumerate() {
            match stream {
                Ok(mut stream) => {
                    println!("\n🔗 连接 #{} 来自 {:?}", i + 1, stream.peer_addr()?);
                    
                    if let Err(e) = self.handle_client(&mut stream) {
                        eprintln!("❌ 处理客户端失败: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("❌ 接受连接失败: {}", e);
                }
            }

            // 为了演示，只处理前5个连接
            if i >= 4 {
                break;
            }
        }

        println!("\n✅ 服务器演示完成");
        Ok(())
    }

    /// 处理单个客户端连接
    fn handle_client(&self, stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // 设置读取超时
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        
        // 读取客户端数据
        let mut buffer = vec![0u8; 512];
        let bytes_read = stream.read(&mut buffer)?;
        
        if bytes_read == 0 {
            println!("⚠️  客户端没有发送数据");
            return Ok(());
        }

        buffer.truncate(bytes_read);
        println!("📦 接收到 {} 字节数据", bytes_read);

        // 执行协议探测
        match self.detector.detect(&buffer) {
            Ok(result) => {
                println!("✅ 协议探测成功!");
                println!("   🎯 协议: {:?}", result.protocol_type());
                println!("   📊 置信度: {:.1}%", result.confidence() * 100.0);
                println!("   ⏱️  探测时间: {:?}", result.detection_time);
                
                // 根据协议类型发送不同的响应
                let response = self.generate_response(&result);
                stream.write_all(response.as_bytes())?;
                
                println!("   📤 已发送协议特定响应");
            }
            Err(e) => {
                println!("❌ 协议探测失败: {}", e);
                
                // 发送通用响应
                let response = "HTTP/1.1 200 OK\r\n\r\nProtocol detection failed";
                stream.write_all(response.as_bytes())?;
            }
        }

        Ok(())
    }

    /// 根据探测到的协议生成相应的响应
    fn generate_response(&self, result: &psi_detector::core::detector::DetectionResult) -> String {
        match result.protocol_type() {
            ProtocolType::HTTP1_1 => {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Server: PSI-Detector-Demo\r\n\r\n\
                     {{\"protocol\": \"HTTP/1.1\", \"confidence\": {:.2}}}\n",
                    result.confidence()
                )
            }
            ProtocolType::HTTP2 => {
                "HTTP/2 detected - Connection established\n".to_string()
            }
            ProtocolType::TLS => {
                "TLS handshake detected - Secure connection\n".to_string()
            }
            ProtocolType::SSH => {
                "SSH-2.0-PSI-Detector-Demo\r\n".to_string()
            }
            _ => {
                format!(
                    "HTTP/1.1 200 OK\r\n\r\n\
                     Protocol: {:?}\n\
                     Confidence: {:.2}%\n",
                    result.protocol_type(),
                    result.confidence() * 100.0
                )
            }
        }
    }
}

/// 简单的测试客户端
struct TestClient;

impl TestClient {
    /// 发送测试请求
    fn send_test_requests(server_port: u16) {
        println!("\n🔄 开始发送测试请求...");
        
        let test_cases = vec![
            ("HTTP/1.1 GET 请求", b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nUser-Agent: TestClient/1.0\r\n\r\n".as_slice()),
            ("HTTP/2 连接前言", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()),
            ("TLS ClientHello", &[
                0x16, 0x03, 0x01, 0x00, 0x2f, // TLS Record Header
                0x01, 0x00, 0x00, 0x2b, // Handshake Header
                0x03, 0x03, // Version TLS 1.2
                // Random (32 bytes)
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                0x00, // Session ID Length
                0x00, 0x02, // Cipher Suites Length
                0x00, 0x35, // Cipher Suite
                0x01, 0x00, // Compression Methods
            ]),
            ("SSH 协议标识", b"SSH-2.0-OpenSSH_8.9\r\n"),
            ("未知数据", &[0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78]),
        ];

        for (name, data) in test_cases {
            println!("\n📤 发送: {}", name);
            
            match Self::send_data(server_port, data) {
                Ok(response) => {
                    println!("✅ 发送成功");
                    if !response.is_empty() {
                        println!("📥 服务器响应: {}", 
                            String::from_utf8_lossy(&response[..response.len().min(100)])
                        );
                    }
                }
                Err(e) => {
                    println!("❌ 发送失败: {}", e);
                }
            }
            
            // 短暂延迟
            thread::sleep(Duration::from_millis(500));
        }
    }

    /// 发送数据到服务器
    fn send_data(port: u16, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        
        // 发送数据
        stream.write_all(data)?;
        
        // 读取响应
        let mut response = Vec::new();
        stream.set_read_timeout(Some(Duration::from_millis(1000)))?;
        
        match stream.read_to_end(&mut response) {
            Ok(_) => Ok(response),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // 超时是正常的，返回已读取的数据
                Ok(response)
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 PSI-Detector 简化客户端-服务端示例");
    println!("==========================================\n");

    let server_port = 9090;
    
    // 在单独线程中启动服务器
    let server_handle = {
        let port = server_port;
        thread::spawn(move || {
            let server = ProtocolAwareServer::new(port).expect("创建服务器失败");
            if let Err(e) = server.start() {
                eprintln!("❌ 服务器运行失败: {}", e);
            }
        })
    };

    // 等待服务器启动
    thread::sleep(Duration::from_millis(1000));

    // 发送测试请求
    TestClient::send_test_requests(server_port);

    // 等待服务器处理完成
    thread::sleep(Duration::from_millis(1000));

    println!("\n🎉 演示完成!");
    println!("\n💡 关键特性:");
    println!("- 🔍 自动协议探测和识别");
    println!("- 🎯 基于协议类型的智能响应");
    println!("- ⚡ 高性能实时处理");
    println!("- 🛡️  安全的被动探测");
    println!("- 🔧 易于集成到现有项目");

    // 注意：在实际应用中，你可能需要优雅地关闭服务器
    // 这里为了演示简单，让程序自然结束
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let server = ProtocolAwareServer::new(0);
        assert!(server.is_ok());
    }

    #[test]
    fn test_response_generation() {
        let server = ProtocolAwareServer::new(0).unwrap();
        
        // 创建一个模拟的探测结果
        // 注意：这里需要根据实际的 DetectionResult 结构进行调整
        // let result = ...; // 创建测试用的 DetectionResult
        // let response = server.generate_response(&result);
        // assert!(!response.is_empty());
    }
}