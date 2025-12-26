use crate::{
    tests::{make_dependency, make_upgrade, make_vulnerability},
    vulnerabilities::Severity,
};

use super::*;

#[test]
fn test_find_updates() {
    let django_dependency = make_dependency("Django", "5.2");
    let vulnerabilities = &[
        make_vulnerability(1, Severity::Critical, &[["5.0", "5.3"]]),
        make_vulnerability(2, Severity::Critical, &[["5.1", "5.4"]]),
    ];

    let actual = find_upgrade(&django_dependency, vulnerabilities).unwrap();
    let expected = make_upgrade("Django", "5.2", "5.4");
    assert_eq!(actual, expected)
}
