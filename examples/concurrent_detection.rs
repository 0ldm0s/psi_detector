//! 并发协议探测示例
//!
//! 演示如何使用 PSI-Detector 进行多线程并发协议探测

use psi_detector::{
    DetectorBuilder, ProtocolDetector, ProtocolType,
    core::ProbeStrategy
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use rayon::prelude::*;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 PSI-Detector 并发协议探测示例");
    
    // 创建共享探测器（线程安全）
    let detector = Arc::new(
        DetectorBuilder::new()
            .enable_http()
            .enable_tls()
            .enable_ssh()
            .with_strategy(ProbeStrategy::Passive)
            .build()?
    );
    
    println!("\n🔧 探测器配置:");
    println!("   策略: Passive (被动模式)");
    println!("   协议: HTTP, TLS, SSH");
    
    // 准备测试数据集
    let test_datasets = create_test_datasets();
    println!("\n📊 测试数据集: {} 个样本", test_datasets.len());
    
    // 1. 基础多线程探测
    println!("\n🧵 1. 基础多线程探测");
    run_basic_multithreading(&detector, &test_datasets)?;
    
    // 2. 使用 Rayon 并行处理
    println!("\n⚡ 2. Rayon 并行处理");
    run_rayon_parallel(&detector, &test_datasets)?;
    
    // 3. 工作池模式
    println!("\n🏭 3. 工作池模式");
    run_worker_pool(&detector, &test_datasets)?;
    
    // 4. 流水线处理
    println!("\n🔄 4. 流水线处理");
    run_pipeline_processing(&detector, &test_datasets)?;
    
    // 5. 性能对比
    println!("\n📈 5. 性能对比");
    run_performance_comparison(&detector, &test_datasets)?;
    
    println!("\n🎉 并发协议探测示例完成!");
    Ok(())
}

#[derive(Debug, Clone)]
struct TestSample {
    id: usize,
    name: String,
    data: Vec<u8>,
    expected_protocol: ProtocolType,
}

fn create_test_datasets() -> Vec<TestSample> {
    vec![
        // HTTP 样本
        TestSample {
            id: 1,
            name: "HTTP GET".to_string(),
            data: b"GET /api/users HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n".to_vec(),
            expected_protocol: ProtocolType::HTTP1_1,
        },
        TestSample {
            id: 2,
            name: "HTTP POST".to_string(),
            data: b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"username\":\"user\",\"password\":\"pass\"}".to_vec(),
            expected_protocol: ProtocolType::HTTP1_1,
        },
        // HTTPS/TLS 样本
        TestSample {
            id: 3,
            name: "TLS ClientHello".to_string(),
            data: vec![
                0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03,
                // Random bytes
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                0x1f, 0x20, 0x00, 0x00, 0x02, 0x00, 0x35, 0x01, 0x00
            ],
            expected_protocol: ProtocolType::TLS,
        },
        // SSH 样本
        TestSample {
            id: 4,
            name: "SSH Protocol".to_string(),
            data: b"SSH-2.0-OpenSSH_8.0\r\n".to_vec(),
            expected_protocol: ProtocolType::SSH,
        },
        // 更多 HTTP 样本
        TestSample {
            id: 5,
            name: "HTTP POST JSON".to_string(),
            data: b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"key\": \"value\", \"id\": 123}".to_vec(),
            expected_protocol: ProtocolType::HTTP1_1,
        },
    ]
}

fn run_basic_multithreading(
    detector: &Arc<impl ProtocolDetector + Send + Sync + 'static>,
    datasets: &[TestSample]
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];
    
    // 为每个样本创建一个线程
    for sample in datasets {
        let detector_clone = Arc::clone(detector);
        let results_clone = Arc::clone(&results);
        let sample_clone = sample.clone();
        
        let handle = thread::spawn(move || {
            let thread_id = thread::current().id();
            println!("   🧵 线程 {:?} 处理样本: {}", thread_id, sample_clone.name);
            
            let detection_start = Instant::now();
            let result = detector_clone.detect(&sample_clone.data);
            let detection_time = detection_start.elapsed();
            
            let detection_result = DetectionResult {
                sample_id: sample_clone.id,
                sample_name: sample_clone.name,
                expected: sample_clone.expected_protocol,
                detected: result.as_ref().map(|r| r.protocol_info.protocol_type).unwrap_or(ProtocolType::Unknown),
                confidence: result.as_ref().map(|r| r.confidence() as f64).unwrap_or(0.0),
                success: result.is_ok(),
                detection_time,
                thread_id: format!("{:?}", thread_id),
            };
            
            results_clone.lock().unwrap().push(detection_result);
        });
        
        handles.push(handle);
    }
    
    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }
    
    let total_time = start_time.elapsed();
    let results = results.lock().unwrap();
    
    print_detection_results(&results, "基础多线程", total_time);
    Ok(())
}

fn run_rayon_parallel(
    detector: &Arc<impl ProtocolDetector + Send + Sync + 'static>,
    datasets: &[TestSample]
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    
    // 使用 Rayon 并行处理
    let results: Vec<DetectionResult> = datasets
        .par_iter()
        .map(|sample| {
            let thread_id = rayon::current_thread_index().unwrap_or(0);
            println!("   ⚡ Rayon 线程 {} 处理样本: {}", thread_id, sample.name);
            
            let detection_start = Instant::now();
            let result = detector.detect(&sample.data);
            let detection_time = detection_start.elapsed();
            
            DetectionResult {
                sample_id: sample.id,
                sample_name: sample.name.clone(),
                expected: sample.expected_protocol,
                detected: result.as_ref().map(|r| r.protocol_info.protocol_type).unwrap_or(ProtocolType::Unknown),
                confidence: result.as_ref().map(|r| r.confidence() as f64).unwrap_or(0.0),
                success: result.is_ok(),
                detection_time,
                thread_id: format!("rayon-{}", thread_id),
            }
        })
        .collect();
    
    let total_time = start_time.elapsed();
    print_detection_results(&results, "Rayon 并行", total_time);
    Ok(())
}

fn run_worker_pool(
    detector: &Arc<impl ProtocolDetector + Send + Sync + 'static>,
    datasets: &[TestSample]
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::mpsc;
    
    let start_time = Instant::now();
    let worker_count = 4;
    let (tx, rx) = mpsc::channel::<TestSample>();
    let rx = Arc::new(Mutex::new(rx));
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // 创建工作线程池
    let mut workers = vec![];
    for worker_id in 0..worker_count {
        let detector_clone = Arc::clone(detector);
        let rx_clone = Arc::clone(&rx);
        let results_clone = Arc::clone(&results);
        
        let worker = thread::spawn(move || {
            loop {
                let sample = {
                    let receiver = rx_clone.lock().unwrap();
                    receiver.recv()
                };
                
                match sample {
                    Ok(sample) => {
                        println!("   🏭 工作线程 {} 处理样本: {}", worker_id, sample.name);
                        
                        let detection_start = Instant::now();
                        let result = detector_clone.detect(&sample.data);
                        let detection_time = detection_start.elapsed();
                        
                        let detection_result = DetectionResult {
                            sample_id: sample.id,
                            sample_name: sample.name,
                            expected: sample.expected_protocol,
                            detected: result.as_ref().map(|r| r.protocol_info.protocol_type).unwrap_or(ProtocolType::Unknown),
                            confidence: result.as_ref().map(|r| r.confidence() as f64).unwrap_or(0.0),
                            success: result.is_ok(),
                            detection_time,
                            thread_id: format!("worker-{}", worker_id),
                        };
                        
                        results_clone.lock().unwrap().push(detection_result);
                    }
                    Err(_) => break, // 通道关闭，退出工作线程
                }
            }
        });
        
        workers.push(worker);
    }
    
    // 发送任务到工作池
    for sample in datasets {
        tx.send(sample.clone()).unwrap();
    }
    
    // 关闭发送端，让工作线程知道没有更多任务
    drop(tx);
    
    // 等待所有工作线程完成
    for worker in workers {
        worker.join().unwrap();
    }
    
    let total_time = start_time.elapsed();
    let results = results.lock().unwrap();
    
    print_detection_results(&results, "工作池模式", total_time);
    Ok(())
}

fn run_pipeline_processing(
    detector: &Arc<impl ProtocolDetector + Send + Sync + 'static>,
    datasets: &[TestSample]
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::mpsc;
    
    let start_time = Instant::now();
    
    // 创建流水线：预处理 -> 探测 -> 后处理
    let (preprocess_tx, preprocess_rx) = mpsc::channel::<TestSample>();
    let (detect_tx, detect_rx) = mpsc::channel::<TestSample>();
    let (postprocess_tx, postprocess_rx) = mpsc::channel::<DetectionResult>();
    
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // 预处理阶段
    let preprocess_handle = {
        let detect_tx = detect_tx.clone();
        thread::spawn(move || {
            while let Ok(sample) = preprocess_rx.recv() {
                println!("   🔧 预处理: {}", sample.name);
                
                // 模拟预处理（数据清理、格式化等）
                let mut processed_sample = sample;
                if processed_sample.data.len() > 1024 {
                    processed_sample.data.truncate(1024); // 限制数据大小
                }
                
                detect_tx.send(processed_sample).unwrap();
            }
        })
    };
    
    // 探测阶段
    let detect_handle = {
        let detector_clone = Arc::clone(detector);
        let postprocess_tx = postprocess_tx.clone();
        thread::spawn(move || {
            while let Ok(sample) = detect_rx.recv() {
                println!("   🎯 探测: {}", sample.name);
                
                let detection_start = Instant::now();
                let result = detector_clone.detect(&sample.data);
                let detection_time = detection_start.elapsed();
                
                let detection_result = DetectionResult {
                    sample_id: sample.id,
                    sample_name: sample.name,
                    expected: sample.expected_protocol,
                    detected: result.as_ref().map(|r| r.protocol_info.protocol_type).unwrap_or(ProtocolType::Unknown),
                    confidence: result.as_ref().map(|r| r.confidence() as f64).unwrap_or(0.0),
                    success: result.is_ok(),
                    detection_time,
                    thread_id: "pipeline-detect".to_string(),
                };
                
                postprocess_tx.send(detection_result).unwrap();
            }
        })
    };
    
    // 后处理阶段
    let postprocess_handle = {
        let results_clone = Arc::clone(&results);
        thread::spawn(move || {
            while let Ok(mut result) = postprocess_rx.recv() {
                println!("   📊 后处理: {}", result.sample_name);
                
                // 模拟后处理（结果验证、统计等）
                if result.confidence < 0.5 {
                    println!("      ⚠️  低置信度警告: {:.1}%", result.confidence * 100.0);
                }
                
                results_clone.lock().unwrap().push(result);
            }
        })
    };
    
    // 发送数据到流水线
    for sample in datasets {
        preprocess_tx.send(sample.clone()).unwrap();
    }
    
    // 关闭通道
    drop(preprocess_tx);
    drop(detect_tx);
    drop(postprocess_tx);
    
    // 等待所有阶段完成
    preprocess_handle.join().unwrap();
    detect_handle.join().unwrap();
    postprocess_handle.join().unwrap();
    
    let total_time = start_time.elapsed();
    let results = results.lock().unwrap();
    
    print_detection_results(&results, "流水线处理", total_time);
    Ok(())
}

fn run_performance_comparison(
    detector: &Arc<impl ProtocolDetector + Send + Sync + 'static>,
    datasets: &[TestSample]
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n   📊 性能对比测试");
    
    // 创建大量测试数据
    let mut large_dataset = Vec::new();
    for i in 0..100 {
        for sample in datasets {
            let mut new_sample = sample.clone();
            new_sample.id = i * datasets.len() + sample.id;
            new_sample.name = format!("{}-{}", sample.name, i);
            large_dataset.push(new_sample);
        }
    }
    
    println!("   📈 测试数据量: {} 个样本", large_dataset.len());
    
    // 1. 单线程处理
    let start_time = Instant::now();
    let mut sequential_results = Vec::new();
    
    for sample in &large_dataset {
        let result = detector.detect(&sample.data);
        sequential_results.push(result.is_ok());
    }
    
    let sequential_time = start_time.elapsed();
    let sequential_success = sequential_results.iter().filter(|&&x| x).count();
    
    // 2. 并行处理
    let start_time = Instant::now();
    
    let parallel_results: Vec<bool> = large_dataset
        .par_iter()
        .map(|sample| detector.detect(&sample.data).is_ok())
        .collect();
    
    let parallel_time = start_time.elapsed();
    let parallel_success = parallel_results.iter().filter(|&&x| x).count();
    
    // 输出对比结果
    println!("\n   🏁 性能对比结果:");
    println!("   ┌─────────────┬──────────────┬──────────────┬──────────────┐");
    println!("   │    模式     │   处理时间   │   成功率     │   吞吐量     │");
    println!("   ├─────────────┼──────────────┼──────────────┼──────────────┤");
    println!("   │ 单线程      │ {:>10.2?} │ {:>9.1}%  │ {:>9.0}/s │", 
        sequential_time, 
        sequential_success as f64 / large_dataset.len() as f64 * 100.0,
        large_dataset.len() as f64 / sequential_time.as_secs_f64());
    println!("   │ 并行处理    │ {:>10.2?} │ {:>9.1}%  │ {:>9.0}/s │", 
        parallel_time, 
        parallel_success as f64 / large_dataset.len() as f64 * 100.0,
        large_dataset.len() as f64 / parallel_time.as_secs_f64());
    println!("   └─────────────┴──────────────┴──────────────┴──────────────┘");
    
    let speedup = sequential_time.as_secs_f64() / parallel_time.as_secs_f64();
    println!("   🚀 加速比: {:.2}x", speedup);
    
    if speedup > 1.0 {
        println!("   ✅ 并行处理显著提升性能!");
    } else {
        println!("   ⚠️  并行处理未显著提升性能，可能受限于数据量或线程开销");
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
struct DetectionResult {
    sample_id: usize,
    sample_name: String,
    expected: ProtocolType,
    detected: ProtocolType,
    confidence: f64,
    success: bool,
    detection_time: Duration,
    thread_id: String,
}

fn print_detection_results(results: &[DetectionResult], mode: &str, total_time: Duration) {
    println!("\n   📋 {} 结果:", mode);
    
    let mut success_count = 0;
    let mut total_confidence = 0.0;
    let mut total_detection_time = Duration::new(0, 0);
    
    for result in results {
        let status = if result.success && result.expected == result.detected {
            success_count += 1;
            "✅"
        } else {
            "❌"
        };
        
        println!("   {} {} | 期望: {:?} | 检测: {:?} | 置信度: {:.1}% | 时间: {:?} | 线程: {}",
            status,
            result.sample_name,
            result.expected,
            result.detected,
            result.confidence * 100.0,
            result.detection_time,
            result.thread_id
        );
        
        total_confidence += result.confidence;
        total_detection_time += result.detection_time;
    }
    
    let accuracy = success_count as f64 / results.len() as f64 * 100.0;
    let avg_confidence = total_confidence / results.len() as f64 * 100.0;
    let avg_detection_time = total_detection_time / results.len() as u32;
    let throughput = results.len() as f64 / total_time.as_secs_f64();
    
    println!("\n   📊 {} 统计:", mode);
    println!("      准确率: {:.1}% ({}/{})", accuracy, success_count, results.len());
    println!("      平均置信度: {:.1}%", avg_confidence);
    println!("      总处理时间: {:?}", total_time);
    println!("      平均探测时间: {:?}", avg_detection_time);
    println!("      吞吐量: {:.1} 样本/秒", throughput);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_concurrent_detection() {
        let detector = Arc::new(
            DetectorBuilder::new()
                .enable_http()
                .build()
                .expect("Failed to build detector")
        );
        
        let test_data = vec![
            TestSample {
                id: 1,
                name: "Test HTTP".to_string(),
                data: b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n".to_vec(),
                expected_protocol: ProtocolType::HTTP1_1,
            },
        ];
        
        // 测试基础多线程
        run_basic_multithreading(&detector, &test_data)
            .expect("Basic multithreading test failed");
    }
    
    #[test]
    fn test_rayon_parallel() {
        let detector = Arc::new(
            DetectorBuilder::new()
                .enable_http()
                .build()
                .expect("Failed to build detector")
        );
        
        let test_data = create_test_datasets();
        
        // 测试 Rayon 并行处理
        run_rayon_parallel(&detector, &test_data)
            .expect("Rayon parallel test failed");
    }
}