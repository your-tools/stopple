use crate::{
    tests::{make_dependency, make_upgrade, make_vulnerability},
    vulnerabilities::{Severity, Vulnerability, VulnerabilityRepository},
};

use super::*;

#[derive(Default)]
struct FakeVulnerabilityRepository {
    vulnerabilities: Vec<Vulnerability>,
    last_id: usize,
}

impl FakeVulnerabilityRepository {
    fn new() -> Self {
        Default::default()
    }

    fn add_vulnerability(&mut self, severity: Severity, start: &str, end: &str) {
        self.last_id += 1;
        let id = self.last_id;
        let vulnerability = make_vulnerability(id, severity, &[[start, end]]);
        self.vulnerabilities.push(vulnerability);
    }
}

impl VulnerabilityRepository for FakeVulnerabilityRepository {
    async fn get_vulnerabilities(&mut self, _package: &str) -> anyhow::Result<Vec<Vulnerability>> {
        Ok(self.vulnerabilities.to_vec())
    }
}

#[tokio::test]
async fn test_find_upgrades_for_vulnerable_dependencies() {
    let mut repository = FakeVulnerabilityRepository::new();
    repository.add_vulnerability(Severity::Critical, "5.0", "5.1");

    let dependencies = vec![make_dependency("django", "5.0")];

    let mut project = Project::new(repository);
    project.set_dependencies(dependencies);

    project.scan().await.unwrap();

    let upgrades = project.upgrades();

    assert_eq!(upgrades, &[make_upgrade("django", "5.0", "5.1")])
}
