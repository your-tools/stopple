use std::{cmp::min, path::PathBuf};

use anyhow::{Context, Ok, Result};
use chrono::prelude::*;
use clap::Parser;
use versions::Versioning;

use crate::{
    dependencies::Dependency,
    finder::Upgrade,
    nvd::NvdClient,
    project::Project,
    vulnerabilities::{Range, Severity, Vulnerability, VulnerabilityRepository},
};

#[derive(Parser)]
#[clap(version)]
struct Arguments {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    #[clap(about = "query vulnerabilities")]
    Query(QueryArguments),
    #[clap(about = "scan project")]
    Scan(ScanArguments),
}

#[derive(Parser)]
struct QueryArguments {
    package: String,
    #[clap(long)]
    long: bool,
    #[clap(long)]
    severity: Option<Severity>,
    #[clap(long)]
    start_date: Option<String>,
}

#[derive(Parser)]
struct ScanArguments {
    #[clap(long)]
    lock_path: PathBuf,
}

pub async fn run() -> Result<()> {
    let args = Arguments::parse();
    match args.command {
        Command::Query(args) => run_query(args).await?,
        Command::Scan(args) => run_scan(args).await?,
    }
    Ok(())
}

async fn run_query(args: QueryArguments) -> Result<()> {
    let QueryArguments {
        package,
        long,
        severity: min_severity,
        start_date,
    } = args;

    let mut nvd_client = NvdClient::new();

    if let Some(s) = start_date {
        let start_date =
            NaiveDate::parse_from_str(&s, "%Y-%m-%d").context("could not parse start date")?;
        let time = NaiveTime::from_hms_opt(0, 0, 0).expect("midnight is a valid time");
        nvd_client.set_start_date(start_date.and_time(time).and_utc());
    }

    let mut vulnerabilities = nvd_client.get_vulnerabilities(&package).await?;

    if let Some(min_severity) = min_severity {
        filter(&mut vulnerabilities, min_severity);
    }

    print_vulnerabilities(vulnerabilities, long);

    Ok(())
}

async fn run_scan(args: ScanArguments) -> Result<()> {
    let ScanArguments { lock_path } = args;
    let lock_name = lock_path
        .file_name()
        .context("lock path must have a file name")?;
    let lock_name = lock_name.to_string_lossy();
    let lock_contents = tokio::fs::read_to_string(&lock_path).await?;

    let packages = lockdiff::parse_lock(&lock_name, &lock_contents)?;

    let dependencies: Vec<_> = packages
        .into_iter()
        .map(|p| {
            let name = p.name().to_owned();
            let version = Versioning::new(p.version()).expect("version in locks should be valid");
            Dependency { name, version }
        })
        .collect();

    let client = NvdClient::new();
    let mut project = Project::new(client);
    project.set_dependencies(dependencies);
    project.scan().await?;

    let upgrades = project.upgrades();

    for Upgrade {
        package,
        from_version,
        to_version,
    } in upgrades
    {
        println!("{package}: {from_version} -> {to_version}")
    }

    Ok(())
}

fn filter(vulnerabilities: &mut Vec<Vulnerability>, min_severity: Severity) {
    vulnerabilities.retain(|v| {
        let s = match v.severity {
            None => return false,
            Some(s) => s,
        };

        s >= min_severity
    });
}

fn print_vulnerabilities(vulnerabilities: Vec<Vulnerability>, long: bool) {
    for vulnerability in vulnerabilities {
        let Vulnerability {
            id,
            severity,
            ranges,
            description,
            ..
        } = vulnerability;
        print!("{id}");
        if let Some(s) = severity {
            print!(" ({s})")
        }
        println!();
        if !ranges.is_empty() {
            println!("Affected versions:")
        }
        for Range { start, end } in ranges {
            println!("* {start} -> {end}");
        }

        if long {
            let termwidth = textwrap::termwidth();
            let width = min(termwidth, 80);
            let lines = textwrap::wrap(&description, width);
            for line in lines {
                println!("  {line}");
            }
        }

        println!();
    }
}
