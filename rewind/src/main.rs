use anyhow::Result;
use clap::Parser;

mod capture;
mod cli;
mod replay;
mod store;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Record(args) => capture::agent::run(args).await,
        Command::Replay(args) => replay::engine::run(args).await,
        Command::Inspect(args) => store::snapshot::inspect(args).await,
        Command::Flush(args) => capture::agent::flush(args).await,
    }
}
