use std::cmp::min;

use anyhow::{Ok, Result};
use clap::Parser;

use crate::{
    nvd::NvdClient,
    vulnerabilities::{Range, Severity, Vulnerability},
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
}

#[derive(Parser)]
struct QueryArguments {
    search_terms: String,
    #[clap(long)]
    num_results: Option<usize>,
    #[clap(long)]
    long: bool,
    #[clap(long)]
    severity: Option<Severity>,
}

pub async fn run() -> Result<()> {
    let args = Arguments::parse();
    match args.command {
        Command::Query(args) => run_query(args).await?,
    }
    Ok(())
}

async fn run_query(args: QueryArguments) -> Result<()> {
    let QueryArguments {
        search_terms,
        num_results,
        long,
        severity: min_severity,
    } = args;

    let mut nvd_client = NvdClient::new();

    let mut vulnerabilities = nvd_client
        .get_vulnerabilities(&search_terms, num_results)
        .await?;

    if let Some(min_severity) = min_severity {
        filter(&mut vulnerabilities, min_severity);
    }

    print_vulnerabilities(vulnerabilities, long);

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
