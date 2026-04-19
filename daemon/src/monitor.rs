use futures_util::StreamExt;
use inotify::{Event, Inotify, WatchMask};
use log::{debug, error, info, trace, warn};
use mist_common::idmap::IdmapWriter;
use nix::libc::uid_t;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock, RwLock};

const PACKAGES_LIST: &str = "/data/system/packages.list";

static INSTANCE: OnceLock<PackageMonitor> = OnceLock::new();

struct PackageData {
    by_name: HashMap<Box<str>, uid_t>,
    by_uid: HashMap<uid_t, HashSet<Box<str>>>,
}

impl PackageData {
    fn new() -> Self {
        Self {
            by_name: HashMap::new(),
            by_uid: HashMap::new(),
        }
    }

    fn update(&mut self, packages: Vec<(Box<str>, uid_t)>) -> Vec<uid_t> {
        let before: HashSet<_> = self.by_uid.keys().copied().collect();

        self.by_name.clear();
        self.by_uid.clear();

        self.by_name.reserve(packages.len());

        for (name, uid) in packages {
            self.by_name.insert(name.clone(), uid);
            self.by_uid.entry(uid).or_default().insert(name);
        }

        before
            .into_iter()
            .filter(|uid| !self.by_uid.contains_key(uid))
            .collect()
    }

    fn uid2pkg(&self, uid: uid_t) -> Option<&HashSet<Box<str>>> {
        self.by_uid.get(&uid)
    }

    fn pkg2uid(&self, pkg: &str) -> Option<uid_t> {
        self.by_name.get(pkg).copied()
    }
}

fn parse_packages_list() -> anyhow::Result<Vec<(Box<str>, uid_t)>> {
    let content = std::fs::read_to_string(PACKAGES_LIST)?;
    let mut packages = Vec::new();

    for line in content.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(name), Some(uid_str)) = (fields.next(), fields.next()) else {
            continue;
        };

        match uid_str.parse::<uid_t>() {
            Ok(uid) => packages.push((Box::from(name), uid)),
            Err(_) => warn!("skip malformed line: {line}"),
        }
    }

    Ok(packages)
}

pub struct PackageMonitor {
    data: RwLock<PackageData>,
    idmap: Mutex<IdmapWriter>,
}

impl PackageMonitor {
    fn new(idmap: IdmapWriter) -> anyhow::Result<Self> {
        let monitor = Self {
            data: RwLock::new(PackageData::new()),
            idmap: Mutex::new(idmap),
        };
        monitor.reload();
        Ok(monitor)
    }

    pub fn instance() -> &'static Self {
        INSTANCE.get().expect("PackageMonitor not initialized")
    }

    fn reload(&self) {
        let packages = match parse_packages_list() {
            Ok(p) => p,
            Err(err) => {
                warn!("failed to parse packages.list: {err}");
                return;
            }
        };

        let removed = self.data.write().unwrap().update(packages);

        if !removed.is_empty() {
            let mut idmap = self.idmap.lock().unwrap();
            for uid in &removed {
                if let Err(err) = idmap.set(*uid, false) {
                    error!("failed to clear idmap for uid {uid}: {err}");
                }
            }
        }
    }

    fn start(&'static self) {
        let inotify = match Inotify::init() {
            Ok(i) => i,
            Err(err) => {
                error!("failed to init inotify: {err}");
                return;
            }
        };

        if let Err(err) = inotify.watches().add("/data/system", WatchMask::MOVED_TO) {
            error!("failed to add inotify watch: {err}");
            return;
        }

        tokio::task::spawn(async move {
            let mut buffer = [0; 0x4000];
            let mut stream = match inotify.into_event_stream(&mut buffer) {
                Ok(stream) => stream,
                Err(err) => {
                    error!("failed to create event stream: {err}");
                    return;
                }
            };

            // reload once after watch is registered to cover the gap
            self.reload();

            info!("package monitor started");

            while let Some(event_or_error) = stream.next().await {
                trace!("event: {event_or_error:?}");

                if let Ok(Event {
                    name: Some(name), ..
                }) = event_or_error
                    && name == "packages.list"
                {
                    debug!("packages.list changed");
                    self.reload();
                }
            }
        });
    }

    pub fn list(&self) -> Vec<String> {
        let data = self.data.read().unwrap();
        let idmap = self.idmap.lock().unwrap();

        idmap
            .get_all()
            .iter()
            .filter_map(|&uid| data.uid2pkg(uid))
            .flatten()
            .map(|s| s.to_string())
            .collect()
    }

    pub fn get(&self, pkg: &str) -> Option<bool> {
        let data = self.data.read().unwrap();
        let uid = data.pkg2uid(pkg)?;
        let idmap = self.idmap.lock().unwrap();

        idmap.get(uid)
    }

    pub fn set(&self, pkg: &str, value: bool) -> anyhow::Result<()> {
        let data = self.data.read().expect("lock poisoned");
        let uid = data
            .pkg2uid(pkg)
            .ok_or_else(|| anyhow::anyhow!("unknown package: {pkg}"))?;
        let mut idmap = self.idmap.lock().expect("lock poisoned");

        idmap.set(uid, value)
    }
}

pub fn init(idmap: IdmapWriter) -> anyhow::Result<()> {
    let monitor = PackageMonitor::new(idmap)?;

    INSTANCE
        .set(monitor)
        .map_err(|_| anyhow::anyhow!("already initialized"))?;

    PackageMonitor::instance().start();
    Ok(())
}
