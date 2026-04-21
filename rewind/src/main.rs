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

use anyhow::Result;
use clap::Parser;
use rewind::cli::{Cli, Command};
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging(format: &str, default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    match format {
        "json" => fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .init(),
        _ => fmt().with_env_filter(filter).with_target(false).init(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_format, &cli.log_level);

    match cli.command {
        Command::Attach(args) => rewind::capture::agent::attach(args).await,
        Command::Record(args) => rewind::capture::agent::run(args).await,
        Command::Flush(args) => rewind::capture::agent::flush(args).await,
        Command::Replay(args) => rewind::replay::engine::run(args).await,
        Command::Inspect(args) => rewind::store::snapshot::inspect(args).await,
        Command::Export(args) => rewind::export::run(args).await,
        Command::Push(args) => rewind::push::run(args).await,
        Command::Webhook(args) => rewind::webhook::run(args).await,
        Command::Server(args) => rewind::server::run(args).await,
        Command::PushAgent(args) => rewind::server::push_agent(args).await,
        Command::Retention(args) => rewind::retention::run(args).await,
        Command::Diff(args) => rewind::diff::run(args).await,
        Command::Scrub(args) => rewind::scrub::run(args).await,
        Command::Verify(args) => rewind::verify::run(args).await,
        Command::Report(args) => rewind::report::run(args).await,
        Command::Timeline(args) => rewind::timeline::run(args).await,
        Command::Notify(args) => rewind::notify::run(args).await,
    }
}
