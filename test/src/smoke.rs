use anyhow::{Context, bail, ensure};
use mist_common::binder::AddServiceEx;
use mist_common::constants::{DUMP_FLAG_PRIORITY_HIDE, MIST_SERVICE_NAME};
use rsbinder::hub::{DUMP_FLAG_PRIORITY_ALL, DUMP_FLAG_PRIORITY_DEFAULT};
use rsbinder::{
    Binder, Interface, Parcel, ProcessState, Remotable, SIBinder, StatusCode, TransactionCode, hub,
};
use std::io::Write;
use std::{env, process::Command};

const TEST_PACKAGE: &str = "xyz.mufanc.mist.test";
const CLIENT_PHASE_ENV: &str = "MIST_TEST_CLIENT_PHASE";
const BEFORE_WHITELIST: &str = "before_whitelist";
const AFTER_WHITELIST: &str = "after_whitelist";
const VISIBLE_SERVICE: &str = "mist/sample_visible";
const HIDDEN_SERVICE: &str = "mist/sample_hidden";

const fn transaction_code(a: char, b: char, c: char) -> u32 {
    (('_' as u32) << 24) | ((a as u32) << 16) | ((b as u32) << 8) | c as u32
}

const TRANSACTION_CODE_SAMPLE: u32 = transaction_code('S', 'P', 'L');

struct SampleService;

impl Interface for SampleService {
    fn dump(&self, writer: &mut dyn Write, _args: &[String]) -> rsbinder::Result<()> {
        let _ = writer.write(b"Hello from SampleService\n");
        Ok(())
    }
}

impl Remotable for SampleService {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "xyz.mufanc.mist.sample"
    }

    fn on_transact(
        &self,
        code: TransactionCode,
        _reader: &mut Parcel,
        reply: &mut Parcel,
    ) -> rsbinder::Result<()> {
        if code != TRANSACTION_CODE_SAMPLE {
            return Err(StatusCode::UnknownTransaction);
        }

        reply.write("Reply from SampleService")
    }

    fn on_dump(&self, writer: &mut dyn Write, args: &[String]) -> rsbinder::Result<()> {
        self.dump(writer, args)
    }
}

#[test]
fn smoke_test() -> anyhow::Result<()> {
    ProcessState::init_default();
    ProcessState::start_thread_pool();

    if let Ok(phase) = env::var(CLIENT_PHASE_ENV) {
        return match phase.as_str() {
            BEFORE_WHITELIST => test_before_whitelist(),
            AFTER_WHITELIST => test_after_whitelist(),
            _ => bail!("unknown client phase: {phase}"),
        };
    }

    test_as_root()
}

fn test_as_root() -> anyhow::Result<()> {
    check_mist_service().context("check mist service")?;
    set_whitelist(false)?;

    let _visible_service = add_sample_service(VISIBLE_SERVICE, false, DUMP_FLAG_PRIORITY_DEFAULT)?;
    let _hidden_service = add_sample_service(HIDDEN_SERVICE, true, DUMP_FLAG_PRIORITY_HIDE)?;

    assert_service_list(true);
    hub::check_service(HIDDEN_SERVICE).context("hidden service unavailable to root")?;

    run_client(BEFORE_WHITELIST)?;
    set_whitelist(true)?;
    run_client(AFTER_WHITELIST)?;
    set_whitelist(false)?;
    Ok(())
}

fn check_mist_service() -> anyhow::Result<()> {
    let mist = hub::check_service(MIST_SERVICE_NAME).context("mist service not found")?;
    mist.ping_binder()?;
    Ok(())
}

fn set_whitelist(enabled: bool) -> anyhow::Result<()> {
    let status = Command::new("/data/local/tmp/mist")
        .args([
            "whitelist",
            "set",
            TEST_PACKAGE,
            if enabled { "true" } else { "false" },
        ])
        .status()?;

    ensure!(status.success(), "failed to update test app whitelist");
    Ok(())
}

fn run_client(phase: &str) -> anyhow::Result<()> {
    let status = Command::new("run-as")
        .args([TEST_PACKAGE, "sh", "-c"])
        .arg(format!(
            "{CLIENT_PHASE_ENV}={phase} ./mist-test --exact smoke_test --nocapture"
        ))
        .status()?;

    ensure!(status.success(), "app client phase failed: {phase}");
    Ok(())
}

fn add_sample_service(
    name: &str,
    allow_isolated: bool,
    dump_priority: i32,
) -> rsbinder::Result<SIBinder> {
    let service = Binder::new(SampleService);
    let binder = service.as_binder();
    hub::default().add_service(name, binder.clone(), allow_isolated, dump_priority)?;
    Ok(binder)
}

fn assert_service_list(hidden: bool) {
    let services = hub::list_services(DUMP_FLAG_PRIORITY_ALL | DUMP_FLAG_PRIORITY_HIDE);
    assert!(
        services.iter().any(|service| service == VISIBLE_SERVICE),
        "{VISIBLE_SERVICE} not listed"
    );
    assert_eq!(
        services.iter().any(|service| service == HIDDEN_SERVICE),
        hidden,
        "unexpected visibility for {HIDDEN_SERVICE}"
    );
}

fn test_before_whitelist() -> anyhow::Result<()> {
    assert_service_list(false);
    ensure!(
        hub::check_service(HIDDEN_SERVICE).is_none(),
        "{HIDDEN_SERVICE} accessible before whitelisting"
    );
    Ok(())
}

fn test_after_whitelist() -> anyhow::Result<()> {
    assert_service_list(true);
    call_sample_service(VISIBLE_SERVICE)?;
    call_sample_service(HIDDEN_SERVICE)
}

fn call_sample_service(name: &str) -> anyhow::Result<()> {
    let binder = hub::check_service(name).with_context(|| format!("{name} not found"))?;
    let proxy = binder
        .as_proxy()
        .with_context(|| format!("{name} is not remote"))?;
    let data = proxy.prepare_transact(true)?;
    let mut reply = proxy
        .submit_transact(TRANSACTION_CODE_SAMPLE, &data, 0)?
        .with_context(|| format!("{name} returned no reply"))?;
    let message: String = reply.read()?;

    assert_eq!(message, "Reply from SampleService");
    Ok(())
}
