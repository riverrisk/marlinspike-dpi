use std::fs;
use std::io::{BufWriter, Cursor, Write};
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::Parser;
use fm_dpi::{DpiEngine, DpiSegmentOutput, SegmentMeta};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "marlinspike-dpi",
    about = "CLI wrapper for the shared MarlinSpike DPI engine"
)]
struct Cli {
    /// Input capture path. Supports classic PCAP and PCAPNG.
    #[arg(long)]
    input: PathBuf,

    /// Stable capture identifier to stamp into Bronze events.
    #[arg(long)]
    capture_id: Option<String>,

    /// Optional JSON output path. Defaults to stdout when omitted.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Pretty-print JSON output.
    #[arg(long, default_value_t = false)]
    pretty: bool,
}

#[derive(Debug, Serialize)]
struct InputMeta<'a> {
    path: String,
    capture_id: &'a str,
    size_bytes: usize,
}

#[derive(Debug, Serialize)]
struct OutputEnvelope<'a> {
    engine: &'static str,
    version: &'static str,
    input: InputMeta<'a>,
    output: &'a DpiSegmentOutput,
}

fn capture_id_from_path(path: &PathBuf) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("capture")
        .to_string()
}

fn build_output(cli: &Cli) -> Result<(String, DpiSegmentOutput, usize)> {
    let capture_id = cli
        .capture_id
        .clone()
        .unwrap_or_else(|| capture_id_from_path(&cli.input));
    let bytes = fs::read(&cli.input)
        .with_context(|| format!("failed to read input capture: {}", cli.input.display()))?;
    let mut engine = DpiEngine::new();
    let output = engine
        .process_segment_to_vec(&SegmentMeta::new(capture_id.clone()), Cursor::new(&bytes))
        .with_context(|| format!("failed to process capture: {}", cli.input.display()))?;
    Ok((capture_id, output, bytes.len()))
}

fn write_json(cli: &Cli, payload: &str) -> Result<()> {
    if let Some(path) = &cli.output {
        fs::write(path, format!("{payload}\n"))
            .with_context(|| format!("failed to write output: {}", path.display()))?;
        return Ok(());
    }

    let stdout = std::io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    writer
        .write_all(payload.as_bytes())
        .context("failed to write JSON to stdout")?;
    writer.write_all(b"\n").context("failed to flush newline")?;
    writer.flush().context("failed to flush stdout")?;
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let (capture_id, output, size_bytes) = build_output(&cli)?;
    let envelope = OutputEnvelope {
        engine: "marlinspike-dpi",
        version: env!("CARGO_PKG_VERSION"),
        input: InputMeta {
            path: cli.input.display().to_string(),
            capture_id: &capture_id,
            size_bytes,
        },
        output: &output,
    };

    let json = if cli.pretty {
        serde_json::to_string_pretty(&envelope)?
    } else {
        serde_json::to_string(&envelope)?
    };
    write_json(&cli, &json)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("marlinspike-dpi: {error:?}");
        process::exit(1);
    }
}
