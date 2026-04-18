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

mod capture;
mod cli;
mod replay;
mod store;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Attach(args) => capture::agent::attach(args).await,
        Command::Record(args) => capture::agent::run(args).await,
        Command::Replay(args) => replay::engine::run(args).await,
        Command::Inspect(args) => store::snapshot::inspect(args).await,
        Command::Flush(args) => capture::agent::flush(args).await,
    }
}
