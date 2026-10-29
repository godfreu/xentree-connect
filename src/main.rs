use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use secrecy::SecretString;
use xentree_connect::{
    commands::{
        health::{self, HealthArgs, HealthInputs},
        init::{self, InitArgs},
    },
    gateway::{self, GatewayArgs},
    lang::{tr, Lang},
};

const TOKEN_ENV: &str = "XENTREE_ADMIN_TOKEN";

#[derive(Parser)]
#[command(
    name = "xentree-connect",
    version,
    about = "Set up and operate Xentree Connect integrations"
)]
struct Cli {
    /// Output language (default: detected from $LC_ALL / $LC_MESSAGES / $LANG).
    #[arg(long, global = true, value_enum)]
    lang: Option<Lang>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Interactive setup: generate a key and register the integration.
    Init(InitArgs),
    /// Check the system clock, key file permissions and API access.
    Health(HealthArgs),
    /// Run the gateway for closed SaaS platforms (SSO launch, webhooks, deprovisioning).
    Gateway(GatewayArgs),
}

fn admin_token() -> Option<SecretString> {
    std::env::var(TOKEN_ENV)
        .ok()
        .filter(|t| !t.trim().is_empty())
        .map(SecretString::from)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let lang = Lang::detect(cli.lang, |k| std::env::var(k).ok());

    match cli.command {
        Command::Init(args) => match init::run(&args, admin_token(), lang).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{}", tr(lang, "cli.error", &[("error", &format!("{e:#}"))]));
                ExitCode::from(1)
            }
        },
        Command::Health(args) => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let inputs = HealthInputs {
                args,
                token: admin_token(),
                lang,
                search_dirs: HealthInputs::default_search_dirs(&cwd),
                clock: None,
            };
            let report = health::run(&inputs).await;
            print!("{}", report.render());
            ExitCode::from(report.exit_code())
        }
        Command::Gateway(args) => match gateway::run(args, lang).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{}", tr(lang, "cli.error", &[("error", &format!("{e:#}"))]));
                ExitCode::from(1)
            }
        },
    }
}
