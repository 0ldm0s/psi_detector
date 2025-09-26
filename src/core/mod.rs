//! 核心抽象模块
//!
//! 包含协议探测的核心接口和协议定义。

pub mod detector;
pub mod protocol;
pub mod fingerprint;
pub mod probe;
pub mod magic;
pub mod tls_alpn;

pub use detector::{ProtocolDetector, DetectionResult};
pub use protocol::{ProtocolType, ProtocolInfo};
pub use probe::{ProbeStrategy, ProbeConfig, ProbeContext, ProtocolProbe, ProbeRegistry};
pub use magic::{MagicDetector, MagicSignature, CustomSignatureBuilder};
pub use tls_alpn::{TlsAlpnDetector, AlpnDetectionResult, TlsRecordType, TlsHandshakeType, TlsExtensionType};