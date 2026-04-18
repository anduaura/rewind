// Copyright 2026 The rewind Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
