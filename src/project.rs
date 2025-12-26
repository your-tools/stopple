use crate::{
    dependencies::Dependency,
    finder::{Upgrade, find_upgrade},
    vulnerabilities::VulnerabilityRepository,
};
use anyhow::{Ok, Result};

pub(crate) struct Project<VR: VulnerabilityRepository> {
    vulnerability_repository: VR,
    dependencies: Vec<Dependency>,
    upgrades: Vec<Upgrade>,
}

impl<VR: VulnerabilityRepository> Project<VR> {
    pub(crate) fn new(vulnerability_repository: VR) -> Self {
        Self {
            vulnerability_repository,
            dependencies: Vec::new(),
            upgrades: Vec::new(),
        }
    }

    pub(crate) fn set_dependencies(&mut self, dependencies: Vec<Dependency>) {
        self.dependencies = dependencies;
    }

    pub(crate) async fn scan(&mut self) -> Result<()> {
        for dependency in &self.dependencies {
            let vulnerabilities = self
                .vulnerability_repository
                .get_vulnerabilities(&dependency.name)
                .await?;

            let upgrade = find_upgrade(dependency, &vulnerabilities);
            if let Some(upgrade) = upgrade {
                self.upgrades.push(upgrade);
            }
        }

        Ok(())
    }

    pub(crate) fn upgrades(&self) -> &[Upgrade] {
        &self.upgrades
    }
}

#[cfg(test)]
mod tests;
