use crate::ext::AsBytes;
use crate::resolver::SystemLibraryResolver;
use anyhow::{Context, bail};
use log::{debug, trace, warn};
use nix::errno::Errno;
use nix::libc;
use nix::libc::{
    AF_UNIX, CMSG_DATA, CMSG_FIRSTHDR, CMSG_SPACE, PTRACE_EVENT_STOP, PTRACE_GETREGSET,
    PTRACE_SETREGSET, SOCK_SEQPACKET, c_long, iovec, msghdr, user_regs_struct,
};
use nix::sys::signal::Signal;
use nix::sys::socket::{ControlMessage, MsgFlags};
use nix::sys::uio::RemoteIoVec;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::{ptrace, signal, socket, uio, wait};
use nix::unistd::Pid;
use procfs::process::{MMapPath, MemoryMaps, ProcState, Process};
use std::ffi::{c_int, c_void};
use std::fmt::{Debug, Formatter};
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;
use std::{fmt, mem, ptr, thread};
use syscalls::{Sysno, syscall};

#[macro_export]
macro_rules! build_args {
    ($($args: expr),*) => {
        &[ $(($args) as _),* ]
    };
}

#[derive(Clone)]
pub struct RegSet(user_regs_struct);

impl RegSet {
    const SIZE: usize = size_of::<user_regs_struct>();

    fn new(regs: user_regs_struct) -> Self {
        Self(regs)
    }

    fn as_ptr(&self) -> *const c_void {
        &self.0 as *const user_regs_struct as _
    }

    pub fn align_sp(&mut self) {
        self.0.sp &= !0xf;
    }

    pub fn get_pc(&self) -> usize {
        self.0.pc as _
    }

    pub fn set_pc(&mut self, pc: usize) {
        self.0.pc = pc as _;
    }

    pub fn set_arg(&mut self, index: usize, value: c_long) {
        if index < 8 {
            self.0.regs[index] = value as _
        } else {
            unreachable!("up to 8 parameters can be passed through registers")
        }
    }

    pub fn set_lr(&mut self, address: usize) {
        self.0.regs[30] = address as _
    }

    pub fn return_value(&self) -> c_long {
        self.0.regs[0] as _
    }
}

pub trait WaitStatusExt {
    fn signal(&self) -> Option<Signal>;
}

impl WaitStatusExt for WaitStatus {
    fn signal(&self) -> Option<Signal> {
        match self {
            WaitStatus::Exited(_, _) => None,
            WaitStatus::Signaled(_, sig, _) => Some(*sig),
            WaitStatus::Stopped(_, sig) => Some(*sig),
            WaitStatus::PtraceEvent(_, sig, _) => Some(*sig),
            WaitStatus::PtraceSyscall(_) => None,
            WaitStatus::Continued(_) => None,
            WaitStatus::StillAlive => None,
        }
    }
}

pub struct RemoteFd {
    fd: RawFd,
    leak: bool,
}

impl Debug for RemoteFd {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("RemoteFd").field("fd", &self.fd).finish()
    }
}

impl RemoteFd {
    pub fn new(fd: RawFd) -> Self {
        Self { fd, leak: true }
    }

    pub fn close_for(mut self, tracee: &Tracee) -> anyhow::Result<()> {
        tracee.call_remote_func(tracee.resolve("libc.so", "__close")?, build_args!(self.fd))?;
        self.leak = false;
        Ok(())
    }

    pub fn forget(mut self) -> RawFd {
        self.leak = false;
        self.fd
    }
}

impl AsRawFd for RemoteFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RemoteFd {
    fn drop(&mut self) {
        if self.leak {
            warn!("remote fd leaked: {}", self.fd);
        }
    }
}

pub struct SocketConnection {
    pub local: OwnedFd,
    pub remote: RemoteFd,
}

impl SocketConnection {
    fn new(local_socket: OwnedFd, remote_socket: RemoteFd) -> Self {
        Self {
            local: local_socket,
            remote: remote_socket,
        }
    }
}

fn ptrace_raw(pid: Pid, request: c_int, addr: c_long, data: c_long) -> anyhow::Result<c_long> {
    Ok(Errno::result(unsafe {
        libc::ptrace(request, pid.as_raw(), addr, data)
    })?)
}

pub struct Tracee {
    pub pid: Pid,
    pub maps_cache: MemoryMaps,
    pub stack: usize,
}

impl Tracee {
    pub fn attach(pid: Pid) -> anyhow::Result<Self> {
        signal::kill(pid, Signal::SIGSTOP)?;

        let maps = {
            let sleep_duration = Duration::from_millis(10);

            loop {
                let proc = Process::new(pid.as_raw())?;
                let state = proc.stat().and_then(|stat| stat.state());

                debug!("process state: {state:?}");

                match state {
                    Ok(ProcState::Stopped) => break proc.maps()?,
                    Ok(_) => {}
                    Err(err) => bail!(err),
                }

                thread::sleep(sleep_duration);
            }
        };

        ptrace_raw(pid, 0x4206 /* PTRACE_SEIZE */, 0, 0)?;
        ptrace_raw(pid, 0x4207 /* PTRACE_INTERRUPT */, 0, 0)?;

        // Consume pending stop events until we reach a stable ptrace-stop state
        loop {
            let status = wait::waitpid(pid, Some(WaitPidFlag::__WALL))?;
            debug!("status: {status:?}");

            match status {
                // PTRACE_EVENT_STOP (event=128) from INTERRUPT or group-stop
                // Main thread is now in ptrace-stop, other threads remain in group-stop
                WaitStatus::PtraceEvent(_, _, ev) if ev == PTRACE_EVENT_STOP => break,

                // Signal-delivery-stop (e.g., pending SIGSTOP)
                // Do NOT reinject stopping signals to avoid retriggering group-stop
                WaitStatus::Stopped(_, sig) => {
                    let inject = match sig {
                        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU => {
                            None
                        }
                        _ => Some(sig),
                    };
                    debug!("signal-delivery-stop, inject = {inject:?}");
                    ptrace::cont(pid, inject)?;
                }

                _ => {
                    debug!("other stop, continue without signal");
                    ptrace::cont(pid, None)?;
                }
            }
        }

        let buffer = maps
            .iter()
            .find_map(|map| {
                if map.pathname == MMapPath::Stack {
                    Some(map.address.0 as usize)
                } else {
                    None
                }
            })
            .context("stack not found")?;

        Ok(Self {
            pid,
            maps_cache: maps,
            stack: buffer,
        })
    }

    pub fn kill(&self, sig: Signal) -> anyhow::Result<()> {
        signal::kill(self.pid, sig)?;
        Ok(())
    }

    pub fn cont<T: Into<Option<Signal>>>(&self, sig: T) -> anyhow::Result<()> {
        ptrace::cont(self.pid, sig)?;
        Ok(())
    }

    pub fn wait(&self) -> anyhow::Result<WaitStatus> {
        Ok(wait::waitpid(self.pid, Some(WaitPidFlag::__WALL))?)
    }

    fn ptrace_raw(&self, request: c_int, addr: c_long, data: c_long) -> anyhow::Result<c_long> {
        ptrace_raw(self.pid, request, addr, data)
    }

    fn get_regs(&self) -> anyhow::Result<RegSet> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();
        let iov = iovec {
            iov_base: regs.as_mut_ptr() as _,
            iov_len: RegSet::SIZE,
        };

        self.ptrace_raw(
            PTRACE_GETREGSET,
            1, /* NT_PRSTATUS */
            &iov as *const _ as _,
        )?;

        Ok(RegSet::new(unsafe { regs.assume_init() }))
    }

    fn set_regs(&self, regs: &RegSet) -> anyhow::Result<()> {
        let iov = iovec {
            iov_base: regs.as_ptr() as _,
            iov_len: RegSet::SIZE,
        };

        self.ptrace_raw(
            PTRACE_SETREGSET,
            1, /* NT_PRSTATUS */
            &iov as *const _ as _,
        )?;

        Ok(())
    }

    pub fn peek(&self, addr: usize) -> anyhow::Result<c_long> {
        Ok(ptrace::read(self.pid, addr as _)?)
    }

    pub fn peek_data(&self, addr: usize, data: &mut [u8]) -> anyhow::Result<()> {
        let iov_remote = RemoteIoVec {
            base: addr,
            len: data.len(),
        };
        let iov_local = IoSliceMut::new(data);

        uio::process_vm_readv(self.pid, &mut [iov_local], &[iov_remote])
            .context("failed to read memory")?;

        Ok(())
    }

    pub fn poke_data(&self, addr: usize, data: &[u8]) -> anyhow::Result<()> {
        let iov_remote = RemoteIoVec {
            base: addr,
            len: data.len(),
        };
        let iov_local = IoSlice::new(data);

        uio::process_vm_writev(self.pid, &[iov_local], &[iov_remote])
            .context("failed to write memory")?;

        Ok(())
    }

    pub fn take_fd(&self, fd_num: RawFd) -> anyhow::Result<OwnedFd> {
        unsafe {
            let pfd =
                OwnedFd::from_raw_fd(syscall!(Sysno::pidfd_open, self.pid.as_raw(), 0)? as RawFd);

            Ok(OwnedFd::from_raw_fd(
                syscall!(Sysno::pidfd_getfd, pfd.as_raw_fd(), fd_num, 0)? as RawFd,
            ))
        }
    }

    pub fn install_fd(
        &self,
        connection: &SocketConnection,
        fd: BorrowedFd,
    ) -> anyhow::Result<RemoteFd> {
        let buffer_len = unsafe { CMSG_SPACE(size_of::<i32>() as _) } as usize;

        let mut header = msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: self.stack as _,
            msg_controllen: buffer_len,
            msg_flags: 0,
        };

        let header_addr = (self.stack + buffer_len + 0xf) & !0xf; // align to 16 bytes

        socket::sendmsg::<()>(
            connection.local.as_raw_fd(),
            &[],
            &[ControlMessage::ScmRights(&[fd.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )?;

        self.poke_data(header_addr, header.as_bytes())?;

        self.call_remote_func(
            self.resolve("libc.so", "recvmsg")?,
            build_args!(connection.remote.as_raw_fd(), header_addr, 0),
        )?;

        if self.peek(header_addr + mem::offset_of!(msghdr, msg_controllen))? == 0 {
            bail!("failed to install fd, please check your sepolicy rules")
        }

        let mut buffer = vec![0; buffer_len as usize];

        self.peek_data(self.stack, &mut buffer)?;

        header.msg_control = buffer.as_ptr() as _;

        let cmsg = unsafe { CMSG_FIRSTHDR(&header) };
        let data = unsafe { CMSG_DATA(cmsg) };

        Ok(RemoteFd::new(unsafe { *(data as *const i32) }))
    }

    pub fn resolve(&self, library_name: &str, symbol_name: &str) -> anyhow::Result<usize> {
        let suffix = format!("/{library_name}");
        let base = self
            .maps_cache
            .iter()
            .find_map(|map| {
                if let MMapPath::Path(pathname) = &map.pathname
                    && pathname.to_string_lossy().ends_with(&suffix)
                {
                    Some(map.address.0 as usize)
                } else {
                    None
                }
            })
            .context(format!("couldn't find base address for {library_name}"))?;

        let symbol = SystemLibraryResolver::instance().resolve(library_name, symbol_name)?;

        Ok(symbol.addr + base)
    }

    pub fn call_remote_func(&self, func: usize, args: &[c_long]) -> anyhow::Result<c_long> {
        if args.len() > 8 {
            bail!("too many args")
        }

        let mut regs = self.get_regs()?;
        let backup = regs.clone();

        regs.align_sp();
        regs.set_pc(func);

        for (index, arg) in args.iter().copied().enumerate() {
            regs.set_arg(index, arg);
        }

        regs.set_lr(self.stack);

        self.set_regs(&regs)?;
        self.cont(None)?;

        let mut status = self.wait()?;

        loop {
            trace!("status = {status:?}");

            let inject = match status {
                WaitStatus::Stopped(_, Signal::SIGSEGV) => break,
                WaitStatus::PtraceEvent(_, Signal::SIGSTOP, ev) if ev == PTRACE_EVENT_STOP => {
                    status.signal()
                }
                WaitStatus::PtraceEvent(_, Signal::SIGCHLD, _) => status.signal(),
                _ => bail!("stopped by {status:?}, expected SIGSEGV"),
            };

            self.cont(inject)?;
            status = self.wait()?;
        }

        regs = self.get_regs()?;

        if regs.get_pc() != self.stack {
            let address = regs.get_pc() as u64;
            let map = self
                .maps_cache
                .iter()
                .find(|map| address >= map.address.0 && address < map.address.1);

            bail!("wrong return address: 0x{address:0>12x} in {map:?}");
        }

        self.set_regs(&backup)?;

        Ok(regs.return_value())
    }

    pub fn connect(&self) -> anyhow::Result<SocketConnection> {
        self.call_remote_func(
            self.resolve("libc.so", "socketpair")?,
            build_args!(AF_UNIX, SOCK_SEQPACKET, 0, self.stack),
        )?;

        let (local_socket, remote_socket) = {
            let pair = self.peek(self.stack)?;

            let local_fd_num = (pair & 0xffffffff) as i32;
            let remote_fd_num = (pair >> 32) as i32;

            let local_fd = self.take_fd(local_fd_num)?;

            RemoteFd::new(local_fd_num).close_for(self)?;

            (local_fd, RemoteFd::new(remote_fd_num))
        };

        debug!("local_fd: {local_socket:?}, remote_fd: {remote_socket:?}");

        Ok(SocketConnection::new(local_socket, remote_socket))
    }

    pub fn detach(&self) -> anyhow::Result<()> {
        ptrace::detach(self.pid, None)?;
        Ok(())
    }
}
