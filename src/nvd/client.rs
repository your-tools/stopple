use anyhow::{Context, Result, bail};
use chrono::prelude::*;
use reqwest::StatusCode;

use crate::{
    database::Cve,
    nvd::response::{NvdResponse, NvdVulnerability},
    vulnerabilities::{Vulnerability, VulnerabilityRepository},
};

const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DATE_FORMAT: &str = "%Y-%m-%dT00:00:00.000";

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

pub(crate) struct PaginatedBody {
    pagination: Pagination,
    body: String,
}

pub(crate) struct NvdClient {
    client: reqwest::Client,
}

impl NvdClient {
    pub(crate) fn new() -> Self {
        let disclaimer = "Disclaimer: this product uses the NVD API but is not endorsed or certified by the NVD.";
        println!("{disclaimer}");
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn make_query(
        &mut self,
        start_date: Option<DateTime<Utc>>,
        package: Option<&str>,
        start_index: Option<usize>,
    ) -> Result<PaginatedBody> {
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

        let response: serde_json::Value = serde_json::from_str(&body)?;

        let results_per_page = response
            .get("resultsPerPage")
            .context("missing key: 'resultsPerPage'")?;
        let results_per_page = results_per_page
            .as_i64()
            .context("'resultsPerPage' should be an int")? as usize;

        let total_results = response
            .get("totalResults")
            .context("missing key: 'totalResults'")?;
        let total_results = total_results
            .as_i64()
            .context("'totalResults' should be an int")? as usize;

        let pagination = Pagination {
            total_results,
            results_per_page,
        };
        Ok(PaginatedBody { pagination, body })
    }

    pub(crate) async fn get_cves(
        &mut self,
        start_date: Option<DateTime<Utc>>,
        start_index: Option<usize>,
    ) -> Result<PaginatedData<Cve>> {
        let PaginatedBody { pagination, body } =
            self.make_query(start_date, None, start_index).await?;

        let response: serde_json::Value =
            serde_json::from_str(&body).context("Could not parse response body")?;

        let mut data = vec![];
        let vulnerabilities = response
            .get("vulnerabilities")
            .context("missing key: 'vulnerabilities'")?;
        for vulnerability in vulnerabilities
            .as_array()
            .context("missing key: 'vulnerabilities'")?
        {
            let cve = vulnerability.get("cve").context("missing key: 'cve'")?;
            let details = serde_json::to_string(cve)?;
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

    async fn find_vulnerabilities(
        &mut self,
        package: &str,
        start_index: Option<usize>,
    ) -> Result<PaginatedData<NvdVulnerability>> {
        let response = self.make_query(None, Some(package), start_index).await?;

        let PaginatedBody { pagination, body } = response;

        let response: NvdResponse =
            serde_json::from_str(&body).context("Could not parse response body")?;

        let vulnerabilities = response.vulnerabilities;
        let matching_vulnerabilities: Vec<_> = vulnerabilities
            .into_iter()
            .filter(|v| v.matches(package))
            .collect();
        Ok(PaginatedData {
            pagination,
            data: matching_vulnerabilities,
        })
    }
}

impl VulnerabilityRepository for NvdClient {
    async fn get_vulnerabilities(&mut self, package: &str) -> Result<Vec<Vulnerability>> {
        let mut all_cves = vec![];

        let mut paginated_cves = self.find_vulnerabilities(package, None).await?;
        all_cves.append(&mut paginated_cves.data);

        if paginated_cves.results_per_page() < paginated_cves.total_results() {
            let mut start_index = 0;

            while start_index <= paginated_cves.total_results() {
                start_index += paginated_cves.results_per_page();
                let mut paginated_cves = self
                    .find_vulnerabilities(package, Some(start_index))
                    .await?;
                all_cves.append(&mut paginated_cves.data);
            }
        }

        let vulnerabilities: Vec<Result<Vulnerability>> =
            all_cves.iter().map(|cve| cve.to_domain()).collect();

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
