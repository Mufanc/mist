use crate::cxx_string::CxxStr;
use android_logger::Config;
use anyhow::Context;
use core::slice;
use log::{LevelFilter, debug, error};
use mist_common::constants::{DUMP_FLAG_PRIORITY_HIDE, MIST_SERVICE_NAME};
use mist_common::idmap::{IdmapReader, UID_MAX, UID_MIN};
use nix::libc::{c_char, uid_t};
use procfs::process::{MMapPath, MemoryMaps, Process};
use r3solvr::{BasicResolver, Query, SymbolResolver};
use std::ffi::{c_long, c_void};
use std::mem;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::OnceLock;
use uds::UnixSeqpacketConn;
use wisp::{Wisp, orig_fn};

pub const SERVICE_MANAGER_PATH: &str = "/system/bin/servicemanager";
pub const MIST_SERVICE_PREFIX: &str = "mist/";

static IPC_THREAD_STATE_SELF_OR_NULL: OnceLock<extern "C" fn() -> *const c_void> = OnceLock::new();
static IPC_THREAD_STATE_GET_CALLING_UID: OnceLock<extern "C" fn(handle: *const c_void) -> uid_t> =
    OnceLock::new();

static IDMAP: OnceLock<IdmapReader> = OnceLock::new();

struct LibraryFinder {
    maps: MemoryMaps,
}

impl LibraryFinder {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            maps: Process::myself()?.maps()?,
        })
    }

    fn find_library(
        &self,
        pattern: &str,
        suffix: bool,
    ) -> anyhow::Result<(PathBuf, *const c_void)> {
        let matches = |pathname: &PathBuf| {
            if suffix {
                pathname.to_string_lossy().ends_with(pattern)
            } else {
                pathname.to_string_lossy() == pattern
            }
        };

        self.maps
            .iter()
            .find_map(|map| {
                if let MMapPath::Path(pathname) = &map.pathname
                    && matches(pathname)
                {
                    Some((pathname.to_owned(), map.address.0 as *const c_void))
                } else {
                    None
                }
            })
            .context("cannot find library")
    }
}

fn make_query(symbol: &'static str) -> Query<'static> {
    Query::new(symbol).with_debugdata(true).with_prefix(true)
}

fn can_access(uid: uid_t) -> bool {
    if uid < UID_MIN {
        return true;
    }

    if uid >= UID_MAX {
        return false;
    }

    IDMAP
        .get()
        .is_some_and(|idmap| idmap.get(uid).unwrap_or(false))
}

fn get_calling_uid() -> Option<uid_t> {
    if let (Some(ipc_thread_state_self_or_null), Some(ipc_thread_state_get_calling_uid)) = (
        IPC_THREAD_STATE_SELF_OR_NULL.get(),
        IPC_THREAD_STATE_GET_CALLING_UID.get(),
    ) {
        let ipc_thread_state = ipc_thread_state_self_or_null();

        if !ipc_thread_state.is_null() {
            return Some(ipc_thread_state_get_calling_uid(ipc_thread_state));
        }
    }

    None
}

extern "C" fn intercept_list_service(args: *mut c_long) {
    let args = unsafe { slice::from_raw_parts_mut(args, 3) };
    let dump_priority = args[1] as i32;

    #[cfg(debug_assertions)]
    debug!("ServiceManager::listServices: dump priority = {dump_priority:0>32b}");

    if dump_priority & DUMP_FLAG_PRIORITY_HIDE != 0 {
        let mut keep = false;

        if let Some(uid) = get_calling_uid()
            && can_access(uid)
        {
            debug!("ServiceManager::listServices: allow uid={uid}");
            keep = true;
        }

        if !keep {
            args[1] = (dump_priority & !DUMP_FLAG_PRIORITY_HIDE) as _;
        }
    }
}

extern "C" fn hook_action_allowed_from_lookup(
    this: *const c_void,
    ctx: *const c_void,
    name: *const c_void,
    perm: *const c_char,
) -> bool {
    let orig_fn = orig_fn!();
    let orig_fn: extern "C" fn(*const c_void, *const c_void, *const c_void, *const c_char) -> bool =
        unsafe { mem::transmute(orig_fn) };

    #[cfg(debug_assertions)]
    debug!(
        "Access::actionAllowedFromLookup: this = {this:p}, ctx = {ctx:p}, name = {name:?}, perm = {perm:p}"
    );

    if let Ok(name) = unsafe { CxxStr::from_ptr(name) } {
        let name = name.to_str();

        #[cfg(debug_assertions)]
        debug!("Access::actionAllowedFromLookup: name = {name:?}");

        if let Some(uid) = get_calling_uid() {
            if name == MIST_SERVICE_NAME {
                return uid == 0;
            }

            if name.starts_with(MIST_SERVICE_PREFIX) && can_access(uid) {
                debug!("Access::actionAllowedFromLookup: allow uid={uid}, name={name:?}");
                return true;
            }
        }
    }

    orig_fn(this, ctx, name, perm)
}

fn run_catching(seqpacket_fd: RawFd, library_fd: RawFd) -> anyhow::Result<()> {
    let connection = unsafe {
        OwnedFd::from_raw_fd(library_fd); // close library_fd
        UnixSeqpacketConn::from_raw_fd(seqpacket_fd)
    };

    let mut fds = [0; 1];

    connection.recv_fds(&mut [], &mut fds)?;

    let idmap_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let idmap = unsafe { IdmapReader::from_fd(&idmap_fd)? };

    IDMAP.get_or_init(|| idmap);

    let finder = LibraryFinder::new()?;

    let (_, executable_base) = finder.find_library(SERVICE_MANAGER_PATH, false)?;

    {
        let (libbinder_pathname, libbinder_base) = finder.find_library("/libbinder.so", true)?;
        let resolver = BasicResolver::from_file(libbinder_pathname)?;

        let ipc_thread_state_self_or_null_fn =
            resolver.lookup_symbol("_ZN7android14IPCThreadState10selfOrNullEv")?;

        let ipc_thread_state_get_calling_uid_fn =
            resolver.lookup_symbol("_ZNK7android14IPCThreadState13getCallingUidEv")?;

        unsafe {
            IPC_THREAD_STATE_SELF_OR_NULL.get_or_init(|| {
                mem::transmute(libbinder_base.byte_add(ipc_thread_state_self_or_null_fn.addr))
            });

            IPC_THREAD_STATE_GET_CALLING_UID.get_or_init(|| {
                mem::transmute(libbinder_base.byte_add(ipc_thread_state_get_calling_uid_fn.addr))
            });
        }
    }

    let resolver = BasicResolver::from_file("/proc/self/exe")?;

    {
        let list_service_fn =
            resolver.lookup_symbol(make_query("_ZN7android14ServiceManager12listServicesE"))?;

        unsafe {
            Wisp::intercept_fn(
                executable_base.byte_add(list_service_fn.addr),
                intercept_list_service,
            )
        }
        .context("failed to intercept `ServiceManager::listServices`")?;
    }

    {
        let action_allowed_from_lookup_fn =
            resolver.lookup_symbol(make_query("_ZN7android6Access23actionAllowedFromLookupE"))?;

        unsafe {
            Wisp::hook_fn(
                executable_base.byte_add(action_allowed_from_lookup_fn.addr),
                hook_action_allowed_from_lookup as _,
                None,
            )
        }
        .context("failed to hook `Access::actionAllowedFromLookup`")?;
    }

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn init_mist(seqpacket_fd: RawFd, library_fd: RawFd) {
    android_logger::init_once(
        Config::default()
            .with_tag("Mist")
            .with_max_level(LevelFilter::Debug),
    );

    if let Err(err) = run_catching(seqpacket_fd, library_fd) {
        error!("{err:?}");
    }
}
