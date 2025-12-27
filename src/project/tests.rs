use std::collections::HashMap;

use crate::{
    tests::{make_dependency, make_upgrade, make_vulnerability},
    vulnerabilities::{Severity, Vulnerability, VulnerabilityRepository},
};

use super::*;

#[derive(Default)]
struct FakeVulnerabilityRepository {
    vulnerabilities: HashMap<String, Vec<Vulnerability>>,
    last_id: usize,
}

impl FakeVulnerabilityRepository {
    fn new() -> Self {
        Default::default()
    }

    fn add_vulnerability(&mut self, package: &str, severity: Severity, start: &str, end: &str) {
        self.last_id += 1;
        let id = self.last_id;
        let vulnerability = make_vulnerability(id, severity, &[[start, end]]);
        let values = self.vulnerabilities.entry(package.to_owned()).or_default();
        values.push(vulnerability);
    }
}

impl VulnerabilityRepository for FakeVulnerabilityRepository {
    async fn get_vulnerabilities(&mut self, package: &str) -> anyhow::Result<Vec<Vulnerability>> {
        let values = self
            .vulnerabilities
            .get(package)
            .cloned()
            .unwrap_or_default();
        Ok(values)
    }
}

#[tokio::test]
async fn test_find_upgrades_for_vulnerable_dependencies() {
    let mut repository = FakeVulnerabilityRepository::new();
    repository.add_vulnerability("django", Severity::Critical, "5.0", "5.1");
    repository.add_vulnerability("django", Severity::Critical, "5.3", "5.4");
    repository.add_vulnerability("requests", Severity::Critical, "2.3.0", "2.31.0");

    let dependencies = vec![
        make_dependency("django", "5.0"),
        make_dependency("requests", "2.31.0"),
    ];

    let mut project = Project::new(repository);
    project.set_dependencies(dependencies);

    project.scan().await.unwrap();

    let upgrades = project.upgrades();

    assert_eq!(upgrades, &[make_upgrade("django", "5.0", "5.1")])
}
