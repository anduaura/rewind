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
use rewind::secrets;
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
        Command::Attach(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::capture::agent::attach(args).await
        }
        Command::Record(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::capture::agent::run(args).await
        }
        Command::Flush(args) => rewind::capture::agent::flush(args).await,
        Command::Replay(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::replay::engine::run(args).await
        }
        Command::Inspect(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::store::snapshot::inspect(args).await
        }
        Command::Export(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::export::run(args).await
        }
        Command::Push(args) => rewind::push::run(args).await,
        Command::Webhook(args) => rewind::webhook::run(args).await,
        Command::Server(args) => rewind::server::run(args).await,
        Command::PushAgent(args) => rewind::server::push_agent(args).await,
        Command::Retention(args) => rewind::retention::run(args).await,
        Command::Diff(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::diff::run(args).await
        }
        Command::Scrub(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::scrub::run(args).await
        }
        Command::Verify(args) => rewind::verify::run(args).await,
        Command::Report(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::report::run(args).await
        }
        Command::Timeline(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::timeline::run(args).await
        }
        Command::Notify(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::notify::run(args).await
        }
        Command::Search(mut args) => {
            args.key = secrets::resolve_key_opt(args.key).await?;
            rewind::search::run(args).await
        }
        Command::Compliance(args) => rewind::compliance::run(args).await,
    }
}
