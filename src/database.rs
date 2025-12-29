use std::path::Path;

use anyhow::{Context, Ok, Result};

use chrono::prelude::*;
use sqlx::migrate::Migrator;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};

use crate::nvd::response::CveVulnerability;
use crate::vulnerabilities::{Vulnerability, VulnerabilityRepository};

static MIGRATOR: Migrator = sqlx::migrate!();

pub(crate) struct Database {
    pool: SqlitePool,
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct Cve {
    pub(crate) id: String,
    pub(crate) raw_json: String,
}

impl Database {
    pub(crate) async fn open(url: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new().connect(url).await?;
        Ok(Self { pool })
    }

    pub(crate) async fn open_from_path(path: &Path) -> Result<Self> {
        let path_str = path.to_str().context("path should be valid utf-8")?;
        let url = format!("sqlite:{path_str}");
        Self::open(&url).await
    }

    pub(crate) async fn migrate(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub(crate) async fn cve_count(&self) -> Result<usize> {
        let query = sqlx::query_as::<_, (i64,)>(
            "
            SELECT count(id) FROM cve
            ",
        );

        let count = query.fetch_one(&self.pool).await?.0;
        Ok(count as usize)
    }

    pub(crate) async fn save_cves(&self, cves: &[Cve]) -> Result<()> {
        let transaction = self.pool.begin().await?;

        for cve in cves {
            self.save_cve(&cve.id, &cve.raw_json).await?;
        }

        transaction.commit().await?;

        Ok(())
    }

    async fn save_cve(&self, id: &str, json: &str) -> Result<()> {
        let query = sqlx::query!(
            "
            INSERT INTO cve (id, raw_json) VALUES (?, ?)
            ON CONFLICT(id) DO UPDATE SET raw_json=excluded.raw_json
            ",
            id,
            json
        );

        query.execute(&self.pool).await?;

        let cve: CveVulnerability = serde_json::from_str(json)?;
        let package_ids = cve.package_ids();
        for package_id in package_ids {
            self.record_package_vulnerability(&package_id, id).await?;
        }
        Ok(())
    }

    pub(crate) async fn search(&self, package: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = vec![];
        let pattern = format!("%:{package}");
        let rows = sqlx::query(
            "
            SELECT raw_json, cve, package 
            FROM vulnerability 
            JOIN cve on cve.id = cve 
            WHERE package like ?
            ",
        )
        .bind(pattern)
        .fetch_all(&self.pool)
        .await?;
        for row in rows {
            let raw_json = row.get("raw_json");
            let cve: CveVulnerability = serde_json::from_str(raw_json)?;
            let vulnerability = cve.to_domain()?;
            vulnerabilities.push(vulnerability);
        }
        Ok(vulnerabilities)
    }

    async fn record_package_vulnerability(&self, package_id: &str, cve_id: &str) -> Result<()> {
        let query = sqlx::query!(
            "
            INSERT INTO package(id) VALUES (?) ON CONFLICT DO NOTHING
            ",
            package_id
        );
        query.execute(&self.pool).await?;

        let query = sqlx::query!(
            "
            INSERT INTO vulnerability(cve, package) VALUES (?, ?)
            ",
            cve_id,
            package_id,
        );

        query
            .execute(&self.pool)
            .await
            .context("when inserting vulnerability")?;

        Ok(())
    }

    pub(crate) async fn save_last_mod_date(&self) -> Result<()> {
        let date = Utc::now();
        let date = date.to_rfc3339();

        let query = sqlx::query!(
            "
            INSERT INTO meta(name, value) VALUES ('last_mod_date', ?) 
            ON CONFLICT(name) DO UPDATE SET value=excluded.value
            ",
            date
        );

        query.execute(&self.pool).await?;

        Ok(())
    }

    pub(crate) async fn last_mod_date(&self) -> Result<Option<DateTime<Utc>>> {
        let query = sqlx::query(
            "
            SELECT value FROM meta WHERE name = 'last_mod_date'
            ",
        );

        let row = query.fetch_optional(&self.pool).await?;

        let row = match row {
            None => return Ok(None),
            Some(r) => r,
        };
        let value: String = row.get(0);

        let date = DateTime::parse_from_rfc3339(&value)
            .expect("saved values should have the correct format");

        Ok(Some(date.to_utc()))
    }
}

impl VulnerabilityRepository for Database {
    async fn get_vulnerabilities(&mut self, package: &str) -> Result<Vec<Vulnerability>> {
        self.search(package).await
    }
}

#[cfg(test)]
mod tests;
