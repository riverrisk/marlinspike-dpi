use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fm_dpi::{
    CorpusManifest, CorpusValidationOptions, FixtureResultStatus, validate_corpus_manifest,
};

#[derive(Debug, Parser)]
#[command(
    name = "ics-defense-corpus",
    about = "Validate the active fm-dpi decoder set against the ICS Defense corpus manifest"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate(ValidateArgs),
}

#[derive(Debug, Parser)]
struct ValidateArgs {
    /// Root directory of a local ICS-Pcaps checkout.
    #[arg(long, env = "ICS_DEFENSE_PCAP_ROOT")]
    corpus_root: Option<PathBuf>,

    /// Optional manifest override. Uses the embedded manifest by default.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Filter fixtures by id, archive dir, normalized family, or relative path.
    #[arg(long)]
    filter: Option<String>,

    /// Skip missing optional fixtures instead of treating them as failures.
    #[arg(long, default_value_t = false)]
    allow_missing: bool,
}

fn load_manifest(path: Option<&PathBuf>) -> Result<CorpusManifest> {
    match path {
        Some(path) => CorpusManifest::from_path(path)
            .with_context(|| format!("failed to load manifest from {}", path.display())),
        None => CorpusManifest::default_ics_defense()
            .context("failed to load embedded ICS Defense manifest"),
    }
}

fn validate(args: &ValidateArgs) -> Result<()> {
    let corpus_root = args.corpus_root.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "missing --corpus-root and ICS_DEFENSE_PCAP_ROOT is not set; point this tool at a local ICS-Pcaps checkout"
        )
    })?;
    let manifest = load_manifest(args.manifest.as_ref())?;
    let summary = validate_corpus_manifest(
        &manifest,
        corpus_root,
        &CorpusValidationOptions {
            filter: args.filter.clone(),
            allow_missing_fixtures: args.allow_missing,
        },
    );

    if summary.selected_fixtures == 0 {
        bail!("no fixtures matched the current manifest/filter selection");
    }

    println!(
        "ICS Defense manifest {} ({})",
        summary.manifest_version, summary.snapshot_date
    );
    println!("Corpus root: {}", summary.corpus_root);
    println!(
        "Fixtures: {} selected, {} passed, {} failed, {} skipped",
        summary.selected_fixtures, summary.passed, summary.failed, summary.skipped
    );

    for result in &summary.results {
        let label = match result.status {
            FixtureResultStatus::Passed => "PASS",
            FixtureResultStatus::Failed => "FAIL",
            FixtureResultStatus::Skipped => "SKIP",
        };
        println!(
            "[{label}] {} ({}) {}",
            result.id, result.normalized_family, result.relative_path
        );
        println!("  {}", result.message);

        if let Some(observation) = &result.observation {
            println!(
                "  events={}, anomalies={}, protocols=[{}], families=[{}]",
                observation.event_count,
                observation.parse_anomalies,
                observation.protocols_seen.join(", "),
                observation.event_families_seen.join(", ")
            );
        }
    }

    if summary.has_failures() {
        bail!("one or more corpus fixtures failed validation");
    }

    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate(args) => validate(&args),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ics-defense-corpus: {error:#}");
        process::exit(1);
    }
}
