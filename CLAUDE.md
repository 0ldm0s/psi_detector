# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PSI-Detector is a high-performance protocol detection and upgrade framework written in Rust, inspired by Yuri's PSI Detector from Red Alert. It provides SIMD-accelerated protocol detection, zero-copy protocol upgrades, and unified stream abstractions for modern network applications.

## Common Commands

### Building and Testing
```bash
# Build the project
cargo build

# Build with release optimizations
cargo build --release

# Run all tests
cargo test

# Run specific test modules
cargo test core_detector_tests
cargo test simd_tests
cargo test lib_tests

# Run tests with output
cargo test -- --nocapture

# Run tests with release optimizations
cargo test --release

# Run specific tests with patterns
cargo test test_http_detection
cargo test test_simd_optimization
cargo test test_protocol_upgrade

# Run examples
cargo run --example basic_detection
cargo run --example client_server_demo
cargo run --example concurrent_detection
cargo run --example simd_performance
cargo run --example h2_h3_advanced
cargo run --example protocol_upgrade
```

### Code Quality
```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Check for documentation
cargo doc --no-deps
```

### Performance Testing
```bash
# Run benchmarks
cargo bench

# Run with specific benchmark
cargo bench --bench detection_performance

# Run benchmarks with custom output
cargo bench -- --output-format html

# Run specific benchmark tests
cargo bench bench_http_detection
cargo bench bench_simd_performance
cargo bench bench_concurrent_throughput

# Run benchmarks with release optimizations
cargo bench --release
```

## Architecture Overview

### Core Components

1. **DetectorBuilder** (`src/builder.rs`): Fluent API for configuring and building protocol detectors with support for multiple protocols, custom probes, and performance tuning.

2. **ProtocolDetector** (`src/core/detector.rs`): Core trait for protocol detection with both sync and async support. The `DefaultProtocolDetector` provides the main implementation.

3. **Protocol Types** (`src/core/protocol.rs`): Comprehensive protocol type definitions including HTTP/1.1, HTTP/2, HTTP/3, TLS, SSH, WebSocket, gRPC, QUIC, MQTT, TCP, and UDP.

4. **Probe System** (`src/probe/`): Modular probe system with:
   - Passive probes for analyzing existing traffic
   - Active probes for initiating protocol detection
   - Custom probe registration via `ProbeRegistry`

5. **SIMD Optimization** (`src/simd/`): Platform-specific SIMD optimizations for x86_64, AArch64, and WASM32 targets.

6. **Protocol Upgrade** (`src/upgrade/`): Zero-copy protocol upgrade pipeline supporting HTTP to HTTP/2, WebSocket upgrades, and TLS handshakes.

7. **Stream Processing** (`src/stream/`): Unified stream abstraction for handling different protocol types with buffer management and processing pipelines.

### Key Design Patterns

- **Builder Pattern**: Used extensively in `DetectorBuilder` for fluent configuration
- **Registry Pattern**: `ProbeRegistry` manages custom protocol detectors
- **Strategy Pattern**: Different detection strategies (Passive, Active, Hybrid)
- **Zero-Copy**: Efficient memory management for high-performance scenarios
- **Plugin Architecture**: Extensible system for custom protocol detectors

### Protocol Support Matrix

| Protocol | Detection | Upgrade | SIMD Optimized |
|----------|-----------|---------|----------------|
| HTTP/1.1 | ✅ | ✅ | ✅ |
| HTTP/2 | ✅ | ✅ | ✅ |
| HTTP/3 | ✅ | ⚠️ | ✅ |
| TLS | ✅ | ✅ | ✅ |
| SSH | ✅ | ❌ | ✅ |
| WebSocket | ✅ | ✅ | ✅ |
| gRPC | ✅ | ✅ | ✅ |
| QUIC | ✅ | ⚠️ | ✅ |
| MQTT | ✅ | ❌ | ✅ |
| TCP/UDP | ✅ | ✅ | ✅ |

## Configuration Profiles

The `DetectorBuilder` provides several pre-configured profiles:

```rust
// High performance configuration
let detector = DetectorBuilder::new()
    .high_performance()
    .build()?;

// High accuracy configuration  
let detector = DetectorBuilder::new()
    .high_accuracy()
    .build()?;

// Balanced configuration
let detector = DetectorBuilder::new()
    .balanced()
    .build()?;
```

## Agent System

The framework includes a sophisticated agent system supporting:

- **Dual Role Operation**: Server (passive detection) and Client (active probing)
- **Load Balancing**: Multiple strategies including round-robin, least connections, and consistent hashing
- **Protocol Negotiation**: Intelligent protocol selection and fallback mechanisms
- **Statistics Tracking**: Comprehensive metrics for detection performance and reliability

### Agent Configuration
```rust
// Server mode configuration
let server_agent = Agent::new(Role::Server)
    .with_load_balancer(LoadBalanceStrategy::RoundRobin)
    .with_max_connections(1000)
    .build()?;

// Client mode configuration
let client_agent = Agent::new(Role::Client)
    .with_protocol_negotiation(true)
    .with_fallback_protocols(vec![ProtocolType::HTTP1_1])
    .build()?;
```

## Error Handling

The framework uses a comprehensive error system in `src/error.rs` with specific error types for:
- Insufficient data errors
- Timeout errors  
- Configuration validation errors
- Protocol upgrade errors
- Transport layer errors

## Performance Characteristics

- **Detection Latency**: 2-5 μs average
- **Throughput**: 289,503 detections/second
- **Memory Usage**: < 1MB runtime footprint
- **SIMD Acceleration**: 2-4x performance improvement over scalar implementations

## Testing Strategy

The project includes comprehensive tests organized by:
- **Unit Tests**: Individual component testing in each module
- **Integration Tests**: End-to-end protocol detection scenarios
- **Performance Tests**: Benchmarking and throughput validation
- **Example Tests**: Real-world usage scenarios

## Dependencies

Key dependencies include:
- `tokio`/`async-std`: Async runtime support (optional)
- `bytes`: Efficient byte buffer handling
- `http`/`h2`: HTTP protocol support
- `wide`: SIMD operations
- `serde`: Serialization support
- `thiserror`/`anyhow`: Error handling
- `zerg_creep`: Internal logging framework

## Development Notes

- The project uses feature flags for optional components
- SIMD optimizations are platform-specific and conditionally compiled
- The framework is designed to be extensible with custom protocol detectors
- All components are thread-safe and support concurrent usage
- Memory safety is prioritized with zero-copy patterns where possible

### Feature Flags
```bash
# Basic protocol support
cargo build --features "basic,http,tcp"

# Full feature set
cargo build --features "basic,http,tcp,grpc,http2,websocket,quic,mqtt,simd-accel,zero-copy"

# Runtime support
cargo build --features "runtime-tokio"        # Tokio async runtime
cargo build --features "runtime-async-std"   # Async-std runtime

# Advanced features
cargo build --features "heuristic-detection,active-probing,transport-integration"

# Red Alert theme
cargo build --features "redalert-theme"
```

### Performance Tuning
```rust
// High-performance configuration
let detector = DetectorBuilder::new()
    .with_min_probe_size(16)              // Reduce minimum data size
    .with_timeout(Duration::from_millis(10))  // Reduce timeout
    .with_min_confidence(0.7)              # Lower confidence threshold
    .enable_simd_optimization()           // Enable SIMD acceleration
    .with_buffer_size(2048)                // Optimal buffer size
    .build()?;

// High-accuracy configuration
let detector = DetectorBuilder::new()
    .with_min_probe_size(64)               // More data for accuracy
    .with_timeout(Duration::from_millis(100)) // Longer timeout
    .with_min_confidence(0.9)              // Higher confidence threshold
    .enable_heuristic_detection()          // Enable heuristic analysis
    .build()?;
```

### Build Targets
```bash
# Build for specific target
cargo build --target x86_64-pc-windows-msvc
cargo build --target x86_64-unknown-linux-gnu
cargo build --target aarch64-unknown-linux-gnu

# Build with optimizations
cargo build --release --features "simd-accel,zero-copy"

# Build with debug info
cargo build --profile=dev
```