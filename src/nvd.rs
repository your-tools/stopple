use anyhow::{Context, Result, anyhow, bail};
use chrono::prelude::*;
use reqwest::StatusCode;
use serde::Deserialize;
use versions::Versioning;

use crate::{
    database::Cve,
    vulnerabilities::{Range, Severity, Vulnerability, VulnerabilityRepository},
};

const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DATE_FORMAT: &str = "%Y-%m-%dT00:00:00.000";

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: usize,
    results_per_page: usize,
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
        let package = package.to_lowercase();
        for configuration in &self.cve.configurations {
            for node in &configuration.nodes {
                for cpe_match in &node.cpe_match {
                    let criteria = cpe_match.criteria.to_lowercase();
                    let substring = format!(":{package}:");
                    if criteria.contains(&substring) {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CveVulnerability {
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

    fn to_domain(&self) -> Result<Vulnerability> {
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

pub(crate) struct NvdClient {
    client: reqwest::Client,
    start_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pagination {
    total_results: usize,
    results_per_page: usize,
}

pub(crate) struct PaginatedData<T> {
    pagination: Pagination,
    data: Vec<T>,
}

impl<T> PaginatedData<T> {
    pub(crate) fn total_results(&self) -> usize {
        self.pagination.total_results
    }

    pub(crate) fn results_per_page(&self) -> usize {
        self.pagination.results_per_page
    }

    pub(crate) fn data(&self) -> &[T] {
        &self.data
    }
}

impl NvdClient {
    pub(crate) fn new() -> Self {
        let disclaimer = "Disclaimer: this product uses the NVD API but is not endorsed or certified by the NVD.";
        println!("{disclaimer}");
        Self {
            client: reqwest::Client::new(),
            start_date: None,
        }
    }

    pub(crate) fn set_start_date(&mut self, date: DateTime<Utc>) {
        self.start_date = Some(date);
    }

    async fn make_query(
        &mut self,
        start_date: Option<DateTime<Utc>>,
        package: Option<&str>,
        start_index: Option<usize>,
    ) -> Result<String> {
        let api_key =
            std::env::var("NVD_API_KEY").context("NVD_API_KEY not found in environment")?;

        let mut params = vec![];

        if let Some(p) = package {
            params.push(("keywordSearch", p.to_owned()));
        }

        if let Some(s) = start_date {
            let start_date = format!("{}", s.format(DATE_FORMAT));
            params.push(("lastModStartDate", start_date));

            let end_date = Utc::now();
            let end_date = format!("{}", end_date.format(DATE_FORMAT));

            params.push(("lastModEndDate", end_date));
        }

        if let Some(s) = start_index {
            params.push(("startIndex", s.to_string()));
        }

        println!("GET {} {:?}", NVD_BASE_URL, params);

        let response = self
            .client
            .get(NVD_BASE_URL)
            .query(&params)
            .header("apiKey", api_key)
            .send()
            .await?;
        let status_code = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        if status_code != StatusCode::OK {
            let message = headers
                .get("message")
                .map(|v| format!("{v:?}"))
                .unwrap_or("<no message header>".to_owned());
            bail!("Request failed wit status {status_code}\nmessage: {message}\n{body}")
        }

        // NOTE: uncomment me if JSON parsing fails
        // tokio::fs::write("nvd.json", &body).await?;

        Ok(body)
    }

    pub(crate) async fn get_cves(
        &mut self,
        start_date: Option<DateTime<Utc>>,
        start_index: Option<usize>,
    ) -> Result<PaginatedData<Cve>> {
        let body = self.make_query(start_date, None, start_index).await?;

        let response: serde_json::Value =
            serde_json::from_str(&body).context("Could not parse response body")?;

        let results_per_page = response
            .get("resultsPerPage")
            .context("missing key: 'resultsPerPage'")?;
        let results_per_page = results_per_page
            .as_i64()
            .context("'resultsPerPage' should be an int")?;

        let total_results = response
            .get("totalResults")
            .context("missing key: 'totalResults'")?;
        let total_results = total_results
            .as_i64()
            .context("'totalResults' should be an int")?;

        let pagination = Pagination {
            total_results: total_results as usize,
            results_per_page: results_per_page as usize,
        };

        let mut data = vec![];
        let vulnerabilities = response
            .get("vulnerabilities")
            .context("missing key: 'vulnerabilitities'")?;
        for vulnerability in vulnerabilities
            .as_array()
            .context("missing key: 'vulnerabilities'")?
        {
            let cve = vulnerability.get("cve").context("missing key: 'cve'")?;
            let details = serde_json::to_string_pretty(cve)?;
            let id = cve
                .get("id")
                .context("missing key: 'id'")?
                .as_str()
                .context("'id' should be a string")?;
            let cve = Cve {
                id: id.to_owned(),
                raw_json: details,
            };

            data.push(cve);
        }

        Ok(PaginatedData { pagination, data })
    }

    async fn find_vulnerabilities(&mut self, package: &str) -> Result<Vec<NvdVulnerability>> {
        let body = self.make_query(self.start_date, None, None).await?;

        let response: NvdResponse =
            serde_json::from_str(&body).context("Could not parse response body")?;

        if response.total_results > response.results_per_page {
            panic!("You need to handle pagination")
        }

        let vulnerabilities = response.vulnerabilities;
        let matching_vulnerabilities: Vec<_> = vulnerabilities
            .into_iter()
            .filter(|v| v.matches(package))
            .collect();
        Ok(matching_vulnerabilities)
    }
}

impl VulnerabilityRepository for NvdClient {
    async fn get_vulnerabilities(&mut self, package: &str) -> Result<Vec<Vulnerability>> {
        let cves = self.find_vulnerabilities(package).await?;
        let vulnerabilities: Vec<Result<Vulnerability>> =
            cves.iter().map(|cve| cve.to_domain()).collect();

        let mut error = String::new();
        let mut res = vec![];
        for vulnerability in vulnerabilities {
            match vulnerability {
                Ok(v) => res.push(v),
                Err(e) => {
                    error.push_str(&format!("{e:?}"));
                    error.push('\n');
                }
            }
        }

        if !error.is_empty() {
            bail!(error);
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests;
