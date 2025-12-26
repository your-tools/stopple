use versions::Versioning;

use crate::{
    dependencies::Dependency,
    finder::Upgrade,
    vulnerabilities::{Range, Severity, Vulnerability},
};

pub(crate) fn make_dependency(name: &str, version: &str) -> Dependency {
    let version = Versioning::new(version).unwrap();
    Dependency {
        name: name.to_owned(),
        version,
    }
}

pub(crate) fn make_vulnerability(
    id: usize,
    severity: Severity,
    ranges: &[[&str; 2]],
) -> Vulnerability {
    let description = format!("description #{id}");
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
        id: id.to_string(),
        description,
        severity,
        ranges,
    }
}

pub(crate) fn make_upgrade(name: &str, from: &str, to: &str) -> Upgrade {
    Upgrade {
        package: name.to_owned(),
        from_version: Versioning::new(from).unwrap(),
        to_version: Versioning::new(to).unwrap(),
    }
}
