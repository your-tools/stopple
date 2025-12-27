use std::collections::HashSet;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use versions::Versioning;

use crate::vulnerabilities::{Range, Severity, Vulnerability};

mod client;

pub(crate) use client::NvdClient;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NvdVulnerability {
    cve: CveVulnerability,
}

impl NvdVulnerability {
    pub(crate) fn to_domain(&self) -> Result<Vulnerability> {
        self.cve.to_domain()
    }

    fn matches(&self, package: &str) -> bool {
        self.cve.matches(package)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct CveVulnerability {
    id: String,
    descriptions: Vec<CveDescription>,
    metrics: CveMetrics,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

impl CveVulnerability {
    fn description(&self) -> Result<String> {
        let descriptions = &self.descriptions;
        let en_description = descriptions.iter().find(|d| d.lang == "en");
        match en_description {
            Some(v) => Ok(v.value.clone()),
            None => bail!("No description found"),
        }
    }

    fn severity(&self) -> Result<Option<Severity>> {
        let severity = self.metrics.severity();

        if let Some(s) = severity {
            let severity = s.parse::<Severity>().map_err(|e| anyhow!(e))?;
            return Ok(Some(severity));
        }

        Ok(None)
    }

    pub(crate) fn package_ids(&self) -> Vec<String> {
        let mut package_ids = HashSet::new();
        for configuration in &self.configurations {
            for node in &configuration.nodes {
                for cpe_match in &node.cpe_match {
                    let criteria = cpe_match.criteria.to_lowercase();
                    let parts: Vec<_> = criteria.split(':').collect();
                    if parts.len() < 5 {
                        continue;
                    }
                    let package_id = format!("{}:{}", parts[3], parts[4]);
                    package_ids.insert(package_id);
                }
            }
        }

        package_ids.into_iter().collect()
    }

    pub(crate) fn matches(&self, package: &str) -> bool {
        let package_ids = self.package_ids();
        for package_id in &package_ids {
            let substring = format!(":{package}");
            if package_id.ends_with(&substring) {
                return true;
            }
        }

        false
    }

    pub(crate) fn to_domain(&self) -> Result<Vulnerability> {
        let id = self.id.to_string();

        let description = self.description()?;
        let severity = self.severity()?;
        let ranges = self.ranges();

        Ok(Vulnerability {
            id,
            description,
            severity,
            ranges,
        })
    }

    fn ranges(&self) -> Vec<Range> {
        let mut ranges = vec![];
        for configuration in &self.configurations {
            for node in &configuration.nodes {
                let operator = &node.operator;
                if operator != "OR" {
                    continue;
                }
                for cpe_match in &node.cpe_match {
                    if let Some(range) = cpe_match.range() {
                        ranges.push(range);
                    }
                }
            }
        }
        ranges
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CveDescription {
    lang: String,
    value: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CveMetrics {
    #[serde(default)]
    cvss_metric_v2: Vec<CvssMetricsV2>,
    #[serde(default)]
    cvss_metric_v30: Vec<CvssMetricsV30>,
    #[serde(default)]
    cvss_metric_v31: Vec<CvssMetricsV31>,
    #[serde(default)]
    cvss_metric_v40: Vec<CvssMetricsV40>,
}

impl CveMetrics {
    fn severity(&self) -> Option<&str> {
        let v4_or_v3_metrics = self
            .cvss_metric_v40
            .first()
            .or_else(|| self.cvss_metric_v31.first())
            .or_else(|| self.cvss_metric_v30.first());

        if let Some(m) = v4_or_v3_metrics {
            return Some(&m.cvss_data.base_severity);
        }

        if let Some(m) = self.cvss_metric_v2.first() {
            return Some(&m.base_severity);
        }

        None
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CvssMetricsV2 {
    base_severity: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CvssMetricsV40 {
    cvss_data: CvssData,
}

// As far as we're concerned, V30, V31 and V40 are the same type
type CvssMetricsV31 = CvssMetricsV40;
type CvssMetricsV30 = CvssMetricsV40;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    base_severity: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Configuration {
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Node {
    operator: String,
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    vulnerable: bool,
    version_start_including: Option<String>,
    version_end_excluding: Option<String>,
    criteria: String,
}

impl CpeMatch {
    fn range(&self) -> Option<Range> {
        let CpeMatch {
            vulnerable,
            version_start_including,
            version_end_excluding,
            ..
        } = &self;

        if !vulnerable {
            return None;
        }

        let start = version_start_including.as_ref().and_then(Versioning::new);
        let end = version_end_excluding.as_ref().and_then(Versioning::new);

        match (start, end) {
            (Some(s), Some(e)) => Some(Range { start: s, end: e }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
