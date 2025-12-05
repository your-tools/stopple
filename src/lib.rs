#![allow(dead_code)]

use anyhow::Result;
use serde::Deserialize;

struct Vulnerability {}

struct NvdClient {
    client: reqwest::Client,
}

const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    start_index: usize,
    total_results: usize,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NvdVulnerability {
    cve: CveVulnerability,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CveVulnerability {
    id: String,
}

impl NvdClient {
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn find_vulnerabilities(&mut self, query: &str) -> Result<Vec<NvdVulnerability>> {
        let api_key = std::env::var("NVD_API_KEY")?;

        let response = self
            .client
            .get(NVD_BASE_URL)
            .query(&[("keywordSearch", query), ("resultsPerPage", "2")])
            .header("apiKey", api_key)
            .send()
            .await?;
        let json = response.text().await?;
        let response: NvdResponse = serde_json::from_str(&json)?;
        Ok(response.vulnerabilities)
    }
}

#[cfg(test)]
mod tests;
