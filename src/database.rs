use futures_util::TryStreamExt;
use std::path::Path;

use anyhow::{Context, Ok, Result};

use chrono::prelude::*;
use sqlx::migrate::Migrator;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};

use crate::nvd::CveVulnerability;
use crate::vulnerabilities::Vulnerability;

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

        self.clear_cache().await?;

        transaction.commit().await?;

        Ok(())
    }

    pub(crate) async fn search(&self, package: &str) -> Result<Vec<Vulnerability>> {
        if self.in_cache(package).await? {
            self.get_from_cache(package).await
        } else {
            let vulnerabilities = self.full_search(package).await?;
            self.save_cache(package, &vulnerabilities).await?;
            Ok(vulnerabilities)
        }
    }

    async fn full_search(&self, package: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = vec![];

        let query = sqlx::query!(
            "
            SELECT id, raw_json FROM cve
            "
        );
        let mut rows = query.fetch(&self.pool);

        while let Some(row) = rows.try_next().await? {
            let cve: CveVulnerability = serde_json::from_str(&row.raw_json)?;
            if cve.matches(package) {
                let vulnerability = cve.to_domain()?;
                vulnerabilities.push(vulnerability);
            }
        }

        Ok(vulnerabilities)
    }

    async fn in_cache(&self, package: &str) -> Result<bool> {
        let row = sqlx::query(
            "
            SELECT name FROM package WHERE name = ?
            ",
        )
        .bind(package)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    async fn save_cache(&self, package: &str, vulnerabilities: &[Vulnerability]) -> Result<()> {
        let ids: Vec<_> = vulnerabilities.iter().map(|v| v.id.clone()).collect();
        let transaction = self.pool.begin().await?;

        let query = sqlx::query!(
            "
            INSERT INTO package(name) VALUES (?)
            ",
            package
        );
        query.execute(&self.pool).await?;

        for id in ids {
            let query = sqlx::query!(
                "
                INSERT INTO vulnerability(cve, package) VALUES (?, ?)
                ",
                id,
                package,
            );

            query.execute(&self.pool).await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    async fn clear_cache(&self) -> Result<()> {
        let transaction = self.pool.begin().await?;

        let query = sqlx::query!(
            "
            DELETE FROM vulnerability;
            DELETE FROM package;
            "
        );
        query.execute(&self.pool).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn get_from_cache(&self, package: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = vec![];
        let rows = sqlx::query(
            "
        SELECT raw_json, cve, package 
        FROM vulnerability 
        JOIN cve on cve.id = cve 
        WHERE package = ?
            ",
        )
        .bind(package)
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

#[cfg(test)]
mod tests;
