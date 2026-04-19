use crate::daemon::mist::IMistService::{BnMistService, IMistService, IMistServiceAsyncService};
use crate::monitor::PackageMonitor;
use crate::selinux::fsetcon;
use anyhow::{anyhow, bail};
use clap::Subcommand;
use log::warn;
use mist_common::binder::AddServiceEx;
use mist_common::constants::{DUMP_FLAG_PRIORITY_HIDE, MIST_SERVICE_NAME};
use mist_common::idmap::IDMAP_SIZE;
use rsbinder::TokioRuntime;
use rsbinder::thread_state::CallingContext;
use rsbinder::{Interface, ProcessState, StatusCode, hub};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::{fs, future};
use tokio::runtime::Handle;

include!(concat!(env!("OUT_DIR"), "/mist.rs"));

static MIST_IDMAP_DIR: LazyLock<PathBuf> = LazyLock::new(|| "/data/adb/mist".into());
static MIST_IDMAP_FILE: LazyLock<PathBuf> = LazyLock::new(|| MIST_IDMAP_DIR.join("idmap"));

fn current_rt() -> TokioRuntime<Handle> {
    TokioRuntime(Handle::current())
}

struct MistService;

fn check_permission() -> rsbinder::status::Result<()> {
    let ctx = CallingContext::default();

    if ctx.uid > 1000 {
        warn!("Permission denied for uid {}", ctx.uid);
        return Err(StatusCode::PermissionDenied.into());
    }

    Ok(())
}

impl Interface for MistService {
    fn dump(&self, writer: &mut dyn Write, _args: &[String]) -> rsbinder::Result<()> {
        let _ = writer.write("Hello, World!\n".as_bytes());
        Ok(())
    }
}

#[allow(non_snake_case)]
#[async_trait::async_trait]
impl IMistServiceAsyncService for MistService {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "xyz.mufanc.IMistService"
    }

    async fn whitelistList(&self) -> rsbinder::status::Result<Vec<String>> {
        check_permission()?;
        Ok(PackageMonitor::instance().list())
    }

    async fn whitelistGet(&self, pkg: &str) -> rsbinder::status::Result<bool> {
        check_permission()?;
        PackageMonitor::instance()
            .get(pkg)
            .ok_or_else(|| StatusCode::BadValue.into())
    }

    async fn whitelistSet(&self, pkg: &str, value: bool) -> rsbinder::status::Result<()> {
        check_permission()?;
        PackageMonitor::instance()
            .set(pkg, value)
            .map_err(|_| StatusCode::BadValue.into())
    }
}

pub fn prepare_idmap() -> anyhow::Result<(File, File)> {
    fs::create_dir_all(&*MIST_IDMAP_DIR)?;

    let file_rw = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&*MIST_IDMAP_FILE)?;

    file_rw.set_len(IDMAP_SIZE)?;
    fsetcon(&file_rw, "u:object_r:system_file:s0")?;

    let file_ro = File::options().read(true).open(&*MIST_IDMAP_FILE)?;

    Ok((file_rw, file_ro))
}

pub async fn run() -> anyhow::Result<()> {
    ProcessState::init_default();
    ProcessState::start_thread_pool();

    let service = BnMistService::new_async_binder(MistService, current_rt());

    hub::default().add_service(
        MIST_SERVICE_NAME,
        service.as_binder(),
        false,
        DUMP_FLAG_PRIORITY_HIDE,
    )?;

    future::pending::<()>().await;
    bail!("wtf??")
}

#[derive(Subcommand)]
pub enum WhitelistCommands {
    #[command(about = "List all enabled packages")]
    List,
    #[command(about = "Check if a package is enabled")]
    Get {
        #[arg(help = "Package name")]
        pkg: String,
    },
    #[command(about = "Enable or disable a package")]
    Set {
        #[arg(help = "Package name")]
        pkg: String,
        #[arg(help = "Enable or disable")]
        value: String,
    },
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "y" | "yes" | "on" | "true" => Some(true),
        "0" | "n" | "no" | "off" | "false" => Some(false),
        _ => None,
    }
}

pub fn handle_whitelist_command(command: WhitelistCommands) -> anyhow::Result<()> {
    ProcessState::init_default();

    let service = match hub::get_interface::<dyn IMistService>(MIST_SERVICE_NAME) {
        Ok(service) => service,
        Err(_) => bail!("Service not found, is the daemon running?"),
    };

    if service.as_binder().ping_binder().is_err() {
        bail!("Service is not responding")
    }

    match command {
        WhitelistCommands::List => {
            let list = service.whitelistList()?;
            for pkg in list {
                println!("{pkg}");
            }
        }
        WhitelistCommands::Get { pkg } => {
            let value = service.whitelistGet(&pkg)?;
            println!("{value}");
        }
        WhitelistCommands::Set { pkg, value } => {
            let value = parse_bool(&value).ok_or_else(|| anyhow!("invalid value: {value}"))?;
            service.whitelistSet(&pkg, value)?;
        }
    }

    Ok(())
}
