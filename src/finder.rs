use std::cmp::max;

use versions::Versioning;

use crate::{
    dependencies::Dependency,
    vulnerabilities::{Range, Vulnerability},
};

#[derive(PartialEq, Eq)]
pub struct Upgrade {
    pub(crate) package: String,
    pub(crate) from_version: Versioning,
    pub(crate) to_version: Versioning,
}

impl std::fmt::Debug for Upgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upgrade")
            .field("package", &self.package)
            .field("from_version", &self.from_version.to_string())
            .field("to_version", &self.to_version.to_string())
            .finish()
    }
}

pub fn find_upgrade(dependency: &Dependency, vulnerabilities: &[Vulnerability]) -> Option<Upgrade> {
    let Dependency { name, version } = dependency;
    let mut first_non_vulnerable_version = version.clone();
    let mut found_match = false;
    for Vulnerability { ranges, .. } in vulnerabilities {
        for Range { start, end } in ranges {
            if start <= &dependency.version && &dependency.version < end {
                found_match = true;
                first_non_vulnerable_version = max(end.clone(), first_non_vulnerable_version);
            }
        }
    }

    if !found_match {
        return None;
    }

    Some(Upgrade {
        package: name.to_owned(),
        from_version: version.clone(),
        to_version: first_non_vulnerable_version,
    })
}

#[cfg(test)]
mod tests;
