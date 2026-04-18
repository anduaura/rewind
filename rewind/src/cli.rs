use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rewind",
    about = "Deterministic replay of distributed system incidents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Record inter-service traffic and syscalls to a .rwd snapshot
    Record(RecordArgs),
    /// Flush the in-memory ring buffer to disk (triggered capture)
    Flush(FlushArgs),
    /// Replay a .rwd snapshot deterministically against a local Docker Compose setup
    Replay(ReplayArgs),
    /// Print the contents of a .rwd snapshot
    Inspect(InspectArgs),
}

#[derive(Args)]
pub struct RecordArgs {
    /// Comma-separated list of service names to watch
    #[arg(long, value_delimiter = ',')]
    pub services: Vec<String>,

    /// Output file path
    #[arg(long, short, default_value = "incident.rwd")]
    pub output: PathBuf,

    /// Capture request/response bodies (increases snapshot size significantly)
    #[arg(long)]
    pub capture_bodies: bool,
}

#[derive(Args)]
pub struct FlushArgs {
    /// How far back to include (e.g. "5m", "30s")
    #[arg(long, default_value = "5m")]
    pub window: String,

    /// Output file path
    #[arg(long, short, default_value = "incident.rwd")]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Docker Compose file to replay against
    #[arg(long, default_value = "docker-compose.yml")]
    pub compose: PathBuf,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,
}
