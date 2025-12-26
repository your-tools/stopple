use crate::{nvd::CveVulnerability, vulnerabilities::Severity};

#[test]
fn test_parse_cve() {
    let json = include_str!("../tests/cve.json");
    let actual: CveVulnerability = serde_json::from_str(json).unwrap();

    let actual_severity = actual.severity().unwrap();
    assert_eq!(actual_severity, Some(Severity::Medium));

    let actual_ranges = actual.ranges();
    let actual_ranges: Vec<_> = actual_ranges
        .iter()
        .map(|r| [r.start.to_string(), r.end.to_string()])
        .collect();
    assert_eq!(&actual_ranges, &[["5.0", "5.0.14"], ["5.1", "5.1.8"]]);
}
