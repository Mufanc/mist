use android_logger::Config;
use clap::{Parser, Subcommand};
use log::LevelFilter;
use mist_common::idmap::IdmapWriter;
use nix::unistd::Pid;
use std::env;

mod daemon;
mod ext;
mod inject;
mod monitor;
mod properties;
mod ptrace;
mod resolver;
mod selinux;

use crate::daemon::WhitelistCommands;

#[derive(Parser)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Inject into servicemanager and start daemon (for internal use only)")]
    Inject {
        #[arg(help = "Path to the library file")]
        file: String,
    },
    #[command(about = "Manage whitelist")]
    Whitelist {
        #[command(subcommand)]
        command: WhitelistCommands,
    },
}

fn main() -> anyhow::Result<()> {
    if env::var("LOGCAT").is_ok() {
        android_logger::init_once(
            Config::default()
                .with_tag("Mist")
                .with_max_level(LevelFilter::Debug),
        );
    } else {
        env_logger::init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Inject { file } => {
            let pid: i32 = properties::get("init.svc_debug_pid.servicemanager")?.parse()?;
            let (idmap_rw, idmap_ro) = daemon::prepare_idmap()?;

            unsafe {
                inject::ptrace_inject(Pid::from_raw(pid), file, idmap_ro)?;
            }

            let idmap_writer = unsafe { IdmapWriter::from_fd(&idmap_rw)? };

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                monitor::init(idmap_writer)?;
                daemon::run().await
            })?;
        }
        Commands::Whitelist { command } => {
            daemon::handle_whitelist_command(command)?;
        }
    }

    Ok(())
}
