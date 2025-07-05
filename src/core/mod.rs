//! 核心抽象模块
//!
//! 包含协议探测的核心接口和协议定义。

pub mod detector;
pub mod protocol;
pub mod fingerprint;
pub mod probe;

pub use detector::{ProtocolDetector, DetectionResult};
pub use protocol::{ProtocolType, ProtocolInfo};
pub use probe::{ProbeStrategy, ProbeConfig, ProbeContext, ProtocolProbe, ProbeRegistry};