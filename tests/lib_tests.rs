use psi_detector::*;

#[test]
fn test_version_info() {
    assert!(!VERSION.is_empty());
    assert_eq!(NAME, "psi_detector");
    assert!(!DESCRIPTION.is_empty());
}

#[test]
fn test_basic_detector_creation() {
    let _detector = DetectorBuilder::new();
}

#[cfg(feature = "redalert-theme")]
#[test]
fn test_yuri_theme() {
    let _detector = yuri::psychic_detection();
    let _upgrade = yuri::mind_control();
}