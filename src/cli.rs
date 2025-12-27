use std::{cmp::min, path::PathBuf, time::Duration};

use anyhow::{Context, Ok, Result};
use clap::Parser;
use versions::Versioning;

use crate::{
    database::{Cve, Database},
    dependencies::Dependency,
    finder::Upgrade,
    nvd::NvdClient,
    project::Project,
    vulnerabilities::{Range, Severity, Vulnerability, VulnerabilityRepository},
};

#[derive(Parser)]
#[clap(version)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    #[clap(about = "query vulnerabilities")]
    Query(QueryArgs),
    #[clap(about = "scan project")]
    Scan(ScanArgs),
    #[clap(about = "manage stopple database")]
    Database(DatabaseArgs),
}

#[derive(Parser)]
struct QueryArgs {
    package: String,
    #[clap(long)]
    long: bool,
    #[clap(long)]
    severity: Option<Severity>,
}

#[derive(Parser)]
struct ScanArgs {
    #[clap(long)]
    lock_path: PathBuf,
}

#[derive(Parser)]
struct DatabaseArgs {
    #[clap(long)]
    path: PathBuf,
    #[clap(subcommand)]
    command: DatabaseCommand,
}

#[derive(Parser)]
enum DatabaseCommand {
    #[clap(about = "create a new database")]
    Create,
    #[clap(about = "refresh the database")]
    Refresh,
    #[clap(about = "search the database for known vulnerabilities about a package")]
    Search(SearchArgs),
}

#[derive(Parser)]
struct SearchArgs {
    package: String,
    #[clap(long)]
    long: bool,
}

pub async fn run() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Query(args) => run_query(args).await?,
        Command::Scan(args) => run_scan(args).await?,
        Command::Database(args) => run_database(args).await?,
    }
    Ok(())
}

async fn run_query(args: QueryArgs) -> Result<()> {
    let QueryArgs {
        package,
        long,
        severity: min_severity,
    } = args;

    let mut nvd_client = NvdClient::new();

    let mut vulnerabilities = nvd_client.get_vulnerabilities(&package).await?;

    if let Some(min_severity) = min_severity {
        filter(&mut vulnerabilities, min_severity);
    }

    print_vulnerabilities(vulnerabilities, long);

    Ok(())
}

async fn run_scan(args: ScanArgs) -> Result<()> {
    let ScanArgs { lock_path } = args;
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

    let url = std::env::var("DATABASE_URL")?;
    let database = Database::open(&url).await?;

    let mut project = Project::new(database);
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

async fn run_database(args: DatabaseArgs) -> Result<()> {
    let DatabaseArgs { path, command } = args;
    match command {
        DatabaseCommand::Create => create_database(path).await,
        DatabaseCommand::Refresh => refresh_database(path).await,
        DatabaseCommand::Search(args) => search_database(path, args).await,
    }
}

async fn create_database(path: PathBuf) -> Result<()> {
    if !path.exists() {
        tokio::fs::write(&path, "").await?;
    }
    let database = Database::open_from_path(&path).await?;

    database.migrate().await?;
    Ok(())
}

async fn refresh_database(path: PathBuf) -> Result<()> {
    let database = Database::open_from_path(&path).await?;

    let last_mode_date = database.last_mod_date().await?;
    let mut client = NvdClient::new();

    let paginated_cves = client.get_cves(last_mode_date, None).await?;

    if paginated_cves.data().is_empty() {
        println!("No new CVEs");
        return Ok(());
    }

    save_cves(&database, paginated_cves.data()).await?;

    let mut start_index = 0;
    while start_index < paginated_cves.total_results() {
        start_index += paginated_cves.results_per_page();
        let paginated_cves = client.get_cves(last_mode_date, Some(start_index)).await?;
        save_cves(&database, paginated_cves.data()).await?;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    database.save_last_mod_date().await?;

    let count = database.cve_count().await?;

    println!("Database contains {count} CVEs");
    Ok(())
}

async fn save_cves(database: &Database, cves: &[Cve]) -> Result<()> {
    database.save_cves(cves).await?;
    println!("Stored {} new CVEs in the database", cves.len());
    Ok(())
}

async fn search_database(path: PathBuf, args: SearchArgs) -> Result<()> {
    let SearchArgs { package, long } = args;

    let database = Database::open_from_path(&path).await?;

    let vulnerabilities = database.search(&package).await?;

    print_vulnerabilities(vulnerabilities, long);
    Ok(())
}
