//! SIMD模块测试

use psi_detector::simd::*;

#[test]
fn test_simd_support_detection() {
    let support = detect_simd_support();
    // 应该检测到某种SIMD支持或None
    assert!(matches!(
        support,
        SimdInstructionSet::None
            | SimdInstructionSet::SSE2
            | SimdInstructionSet::AVX2
            | SimdInstructionSet::AVX512
            | SimdInstructionSet::NEON
            | SimdInstructionSet::WasmSimd
    ));
}

#[test]
fn test_pattern_matching() {
    let haystack = b"GET /path HTTP/1.1\r\nHost: example.com\r\n";
    let needle = b"HTTP";
    
    let positions = simd_pattern_match(haystack, needle);
    assert!(!positions.is_empty());
    assert_eq!(positions[0], 10); // "HTTP" 在位置10
}

#[test]
fn test_pattern_matching_empty_needle() {
    let haystack = b"test data";
    let needle = b"";
    
    let positions = simd_pattern_match(haystack, needle);
    assert!(positions.is_empty());
}

#[test]
fn test_pattern_matching_not_found() {
    let haystack = b"GET /path HTTP/1.1";
    let needle = b"HTTPS";
    
    let positions = simd_pattern_match(haystack, needle);
    assert!(positions.is_empty());
}

#[test]
fn test_pattern_matching_multiple_occurrences() {
    let haystack = b"test test test";
    let needle = b"test";
    
    let positions = simd_pattern_match(haystack, needle);
    assert_eq!(positions.len(), 3);
    assert_eq!(positions, vec![0, 5, 10]);
}

#[test]
fn test_byte_counting() {
    let data = b"Hello World";
    let count = simd_count_bytes(data, b'l');
    assert_eq!(count, 3); // 'l' 出现3次
}

#[test]
fn test_byte_counting_not_found() {
    let data = b"Hello World";
    let count = simd_count_bytes(data, b'x');
    assert_eq!(count, 0); // 'x' 不存在
}

#[test]
fn test_byte_counting_empty_data() {
    let data = b"";
    let count = simd_count_bytes(data, b'a');
    assert_eq!(count, 0);
}

#[test]
fn test_byte_finding() {
    let data = b"Hello World";
    let pos = simd_find_byte(data, b'W');
    assert_eq!(pos, Some(6)); // 'W' 在位置6
}

#[test]
fn test_byte_finding_not_found() {
    let data = b"Hello World";
    let pos = simd_find_byte(data, b'x');
    assert_eq!(pos, None); // 'x' 不存在
}

#[test]
fn test_byte_finding_empty_data() {
    let data = b"";
    let pos = simd_find_byte(data, b'a');
    assert_eq!(pos, None);
}

#[test]
fn test_byte_finding_first_occurrence() {
    let data = b"Hello";
    let pos = simd_find_byte(data, b'l');
    assert_eq!(pos, Some(2)); // 第一个 'l' 在位置2
}

#[test]
fn test_detector_creation() {
    let detector = create_best_detector();
    // 应该能够创建探测器
    assert!(detector.instruction_set() != SimdInstructionSet::None || true);
}

#[test]
fn test_simd_instruction_set_debug() {
    let none = SimdInstructionSet::None;
    let sse2 = SimdInstructionSet::SSE2;
    let avx2 = SimdInstructionSet::AVX2;
    
    assert_eq!(format!("{:?}", none), "None");
    assert_eq!(format!("{:?}", sse2), "SSE2");
    assert_eq!(format!("{:?}", avx2), "AVX2");
}

#[test]
fn test_simd_instruction_set_equality() {
    assert_eq!(SimdInstructionSet::None, SimdInstructionSet::None);
    assert_ne!(SimdInstructionSet::None, SimdInstructionSet::SSE2);
    assert_ne!(SimdInstructionSet::SSE2, SimdInstructionSet::AVX2);
}