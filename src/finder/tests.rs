use versions::Versioning;

use crate::{
    dependencies::Dependency,
    vulnerabilities::{Range, Severity, Vulnerability},
};

use super::*;

fn make_dependency(name: &str, version: &str) -> Dependency {
    let version = Versioning::new(version).unwrap();
    Dependency {
        name: name.to_owned(),
        version,
    }
}

fn make_vulnerability(severity: Severity, ranges: &[[&str; 2]]) -> Vulnerability {
    let id = "test id".to_owned();
    let description = "test description".to_owned();
    let severity = Some(severity);
    let ranges: Vec<_> = ranges
        .iter()
        .map(|r| {
            let [start, end] = r;
            let start = Versioning::new(start).unwrap();
            let end = Versioning::new(end).unwrap();
            Range { start, end }
        })
        .collect();

    Vulnerability {
        id,
        description,
        severity,
        ranges,
    }
}

fn make_upgrade(name: &str, from: &str, to: &str) -> Upgrade {
    Upgrade {
        package: name.to_owned(),
        from_version: Versioning::new(from).unwrap(),
        to_version: Versioning::new(to).unwrap(),
    }
}

#[test]
fn test_find_updates() {
    let django_dependency = make_dependency("Django", "5.2");
    let vulnerabilities = &[
        make_vulnerability(Severity::Critical, &[["5.0", "5.3"]]),
        make_vulnerability(Severity::Critical, &[["5.1", "5.4"]]),
    ];

    let actual = find_upgrade(&django_dependency, vulnerabilities);
    let expected = make_upgrade("Django", "5.2", "5.4");
    assert_eq!(actual, expected)
}
