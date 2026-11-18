//! The microkernel proper: objects, scheduling, IPC and system calls.
//!
//! This module contains **no `unsafe` code**. It is written against the safe
//! interfaces of `arch` and `mm`, and all access-control decisions are delegated
//! to the tested, `unsafe`-free `kcore` crate.
//!
//! ## Execution model
//!
//! The kernel is event driven and non-preemptible: every entry from user mode
//! (system call, interrupt, exception) is handled to completion with interrupts
//! disabled, under one lock, and ends by selecting the thread to resume. Blocking
//! operations never block *in the kernel*; they only change thread states.

mod ipc;
pub mod loader;
pub mod object;
mod syscall;

use alloc::collections::VecDeque;
use alloc::string::String;

use kcore::abi;
use kcore::arena::Arena;
use kcore::chacha20::ChaChaRng;
use kcore::cspace::{CapDb, Capability};
use kcore::rights::Rights;

use self::object::*;
use crate::arch::entry::{SPURIOUS_VECTOR, SYSCALL_VECTOR, TIMER_VECTOR, TrapFrame};
use crate::arch::{self, apic};
use crate::sync::SpinLock;
use crate::{kprintln, mm};

/// Hard limits that bound kernel memory consumption regardless of user behaviour.
pub mod limits {
    pub const MAX_CAPS: usize = 4096;
    pub const MAX_CSPACES: usize = 64;
    pub const MAX_THREADS: usize = 64;
    pub const MAX_ENDPOINTS: usize = 256;
    pub const MAX_VSPACES: usize = 64;
    pub const MAX_FRAMES: usize = 8192;
    pub const MAX_UNTYPED: usize = 16;
    /// Memory budget handed to the root task (32 frames).
    pub const ROOT_UNTYPED_BYTES: u64 = 128 << 10;
}

/// Counters reported at shutdown.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub syscalls: u64,
    pub denied: u64,
    pub faults: u64,
    pub preemptions: u64,
    pub context_switches: u64,
    pub ipc_messages: u64,
}

/// What to do after handling a trap.
enum Next {
    Resume,
    Shutdown(bool),
}

/// All kernel state.
pub struct Kernel {
    pub(crate) caps: CapDb<Object>,
    pub(crate) threads: Arena<Thread>,
    pub(crate) endpoints: Arena<Endpoint>,
    pub(crate) vspaces: Arena<VSpace>,
    pub(crate) frames: Arena<Frame>,
    pub(crate) untypeds: Arena<Untyped>,
    run_queue: VecDeque<ThreadId>,
    current: Option<ThreadId>,
    root: Option<ThreadId>,
    need_resched: bool,
    pub(crate) rng: ChaChaRng,
    pub(crate) stats: Stats,
}

static KERNEL: SpinLock<Option<Kernel>> = SpinLock::new(None);

impl Kernel {
    pub fn new(rng: ChaChaRng) -> Self {
        Self {
            caps: CapDb::new(limits::MAX_CAPS, limits::MAX_CSPACES),
            threads: Arena::with_limit(limits::MAX_THREADS),
            endpoints: Arena::with_limit(limits::MAX_ENDPOINTS),
            vspaces: Arena::with_limit(limits::MAX_VSPACES),
            frames: Arena::with_limit(limits::MAX_FRAMES),
            untypeds: Arena::with_limit(limits::MAX_UNTYPED),
            run_queue: VecDeque::new(),
            current: None,
            root: None,
            need_resched: false,
            rng,
            stats: Stats::default(),
        }
    }

    // ----------------------------------------------------------------- objects

    /// Takes a reference on the object a new capability points to.
    pub(crate) fn retain(&mut self, obj: &Object) {
        match *obj {
            Object::Untyped(id) => {
                if let Some(u) = self.untypeds.get_mut(id) {
                    u.refs += 1;
                }
            }
            Object::Frame { id, .. } => {
                if let Some(f) = self.frames.get_mut(id) {
                    f.refs += 1;
                }
            }
            Object::VSpace(id) => {
                if let Some(v) = self.vspaces.get_mut(id) {
                    v.refs += 1;
                }
            }
            Object::Endpoint(id) => {
                if let Some(e) = self.endpoints.get_mut(id) {
                    e.refs += 1;
                }
            }
            Object::Thread(_) | Object::Console => {}
        }
    }

    /// Drops a reference; destroys the object when the last one goes away.
    pub(crate) fn release(&mut self, obj: Object) {
        match obj {
            Object::Untyped(id) => {
                if let Some(u) = self.untypeds.get_mut(id) {
                    u.refs -= 1;
                    if u.refs == 0 {
                        self.untypeds.remove(id);
                    }
                }
            }
            Object::Frame { id, .. } => {
                if let Some(f) = self.frames.get_mut(id) {
                    f.refs -= 1;
                    if f.refs == 0
                        && let Some(f) = self.frames.remove(id)
                    {
                        mm::frame::free(f.phys);
                        self.refund(f.charge);
                    }
                }
            }
            Object::VSpace(id) => self.release_vspace(id),
            Object::Endpoint(id) => {
                if let Some(e) = self.endpoints.get_mut(id) {
                    e.refs -= 1;
                    if e.refs == 0 {
                        self.destroy_endpoint(id);
                    }
                }
            }
            Object::Thread(_) | Object::Console => {}
        }
    }

    fn release_vspace(&mut self, id: VSpaceId) {
        if let Some(v) = self.vspaces.get_mut(id) {
            v.refs -= 1;
            if v.refs == 0 {
                // Dropping the VSpace frees its frames and page tables.
                self.vspaces.remove(id);
            }
        }
    }

    fn refund(&mut self, charge: Charge) {
        if let Some((ut, bytes)) = charge
            && let Some(u) = self.untypeds.get_mut(ut)
        {
            u.remaining += bytes;
        }
    }

    fn destroy_endpoint(&mut self, id: EndpointId) {
        let Some(ep) = self.endpoints.remove(id) else {
            return;
        };
        // Every thread still waiting on the endpoint is woken with EDEAD.
        for t in ep.senders.into_iter().chain(ep.receivers) {
            let fault = self.threads.get(t).is_some_and(|th| th.outgoing.fault);
            if fault {
                self.finish_thread(t);
            } else {
                self.complete(t, Err(abi::Error::Dead));
            }
        }
        self.refund(ep.charge);
    }

    /// Removes a frame mapping created through a frame capability.
    pub(crate) fn unmap_frame(&mut self, id: FrameId, m: Mapping) {
        if let Some(v) = self.vspaces.get_mut(m.vspace) {
            v.space.unmap(m.vaddr);
        }
        if let Some(f) = self.frames.get_mut(id) {
            f.writable_maps -= u32::from(m.writable);
            f.exec_maps -= u32::from(m.executable);
        }
    }

    /// Bookkeeping for a capability that was deleted or revoked.
    pub(crate) fn on_cap_removed(&mut self, cap: Capability<Object>) {
        if let Object::Frame {
            id,
            mapped: Some(m),
        } = cap.object
        {
            self.unmap_frame(id, m);
        }
        self.release(cap.object);
    }

    // ----------------------------------------------------------------- threads

    /// Makes a thread runnable with the given system call result.
    pub(crate) fn complete(&mut self, t: ThreadId, result: Result<(), abi::Error>) {
        if let Some(th) = self.threads.get_mut(t) {
            th.ctx.rax = match result {
                Ok(()) => 0,
                Err(e) => e as u64,
            };
            th.state = ThreadState::Ready;
            if self.current != Some(t) {
                self.run_queue.push_back(t);
            }
        }
    }

    pub(crate) fn make_ready(&mut self, t: ThreadId) {
        if let Some(th) = self.threads.get_mut(t) {
            th.state = ThreadState::Ready;
            if self.current != Some(t) {
                self.run_queue.push_back(t);
            }
        }
    }

    /// Terminates a thread and releases everything it owns.
    pub(crate) fn finish_thread(&mut self, t: ThreadId) {
        let Some(th) = self.threads.remove(t) else {
            return;
        };
        // Unlink from any endpoint queue it may still be in.
        match th.state {
            ThreadState::BlockedSend(ep) | ThreadState::BlockedRecv(ep) => {
                if let Some(e) = self.endpoints.get_mut(ep) {
                    e.senders.retain(|x| *x != t);
                    e.receivers.retain(|x| *x != t);
                }
            }
            _ => {}
        }
        // A caller waiting for this thread's reply must not wait forever.
        if let Some(caller) = th.reply_to
            && self
                .threads
                .get(caller)
                .is_some_and(|c| c.state == ThreadState::BlockedReply)
        {
            self.complete(caller, Err(abi::Error::Dead));
        }
        if let Ok(removed) = self.caps.destroy_space(th.cspace) {
            for cap in removed {
                self.on_cap_removed(cap);
            }
        }
        if let Some((ep, _)) = th.fault_ep {
            self.release(Object::Endpoint(ep));
        }
        self.release_vspace(th.vspace);
        self.run_queue.retain(|x| *x != t);
    }

    fn name(&self, t: ThreadId) -> &str {
        self.threads.get(t).map_or("?", |th| th.name.as_str())
    }

    /// Handles a CPU exception raised by user code.
    fn fault(&mut self, t: ThreadId, vector: u64, error: u64, addr: u64) {
        self.stats.faults += 1;
        let (rip, fault_ep) = match self.threads.get(t) {
            Some(th) => (th.ctx.rip, th.fault_ep),
            None => return,
        };
        let what = match vector {
            0 => "divide error",
            6 => "invalid opcode",
            7 => "FPU/SIMD use (disabled)",
            13 => "general protection fault",
            14 => "page fault",
            _ => "exception",
        };
        kprintln!(
            "[fault] thread '{}' killed: {} (vector {}) at rip={:#x} addr={:#x} err={:#x}",
            self.name(t),
            what,
            vector,
            rip,
            addr,
            error
        );
        if Some(t) == self.root {
            kprintln!("[fault] the root task faulted");
            self.finish_thread(t);
            return;
        }
        match fault_ep {
            Some((ep, badge)) if self.endpoints.contains(ep) => {
                let msg = Outgoing {
                    badge,
                    words: [vector, error, addr, rip],
                    cap_slot: None,
                    call: false,
                    fault: true,
                };
                self.ipc_send(t, ep, msg);
            }
            _ => self.finish_thread(t),
        }
    }

    // --------------------------------------------------------------- scheduling

    fn handle_trap(&mut self, frame: &mut TrapFrame) -> Next {
        let Some(cur) = self.current else {
            panic!("user trap without a current thread");
        };
        if let Some(th) = self.threads.get_mut(cur) {
            th.ctx = *frame;
        }
        match frame.vector {
            SYSCALL_VECTOR => {
                self.stats.syscalls += 1;
                if let Some(shutdown) = self.syscall(cur) {
                    return Next::Shutdown(shutdown);
                }
            }
            TIMER_VECTOR => {
                apic::eoi();
                self.stats.preemptions += 1;
                self.need_resched = true;
            }
            SPURIOUS_VECTOR => {}
            // Not caused by the interrupted thread: never blame (kill) it.
            2 => kprintln!("[kernel] NMI received while in user mode; ignored"),
            8 | 18 => panic!("unrecoverable machine exception (vector {})", frame.vector),
            v if v < 32 => {
                let addr = if v == 14 { arch::read_cr2() } else { 0 };
                self.fault(cur, v, frame.error_code, addr);
            }
            _ => apic::eoi(),
        }
        if self.root.is_some_and(|r| !self.threads.contains(r)) {
            kprintln!("[kernel] root task terminated abnormally");
            return Next::Shutdown(false);
        }
        self.dispatch(frame)
    }

    fn is_ready(&self, t: ThreadId) -> bool {
        self.threads
            .get(t)
            .is_some_and(|th| th.state == ThreadState::Ready)
    }

    /// Picks the next thread and loads its context into `frame`.
    fn dispatch(&mut self, frame: &mut TrapFrame) -> Next {
        let keep = self
            .current
            .filter(|&c| self.is_ready(c) && !self.need_resched);
        let next = match keep {
            Some(c) => Some(c),
            None => {
                if let Some(c) = self.current.filter(|&c| self.is_ready(c)) {
                    self.run_queue.push_back(c);
                }
                let mut found = None;
                while let Some(t) = self.run_queue.pop_front() {
                    if self.is_ready(t) {
                        found = Some(t);
                        break;
                    }
                }
                found
            }
        };
        self.need_resched = false;
        let Some(next) = next else {
            kprintln!("[kernel] no runnable threads left (deadlock)");
            return Next::Shutdown(false);
        };
        if self.current != Some(next) {
            self.stats.context_switches += 1;
        }
        self.current = Some(next);
        let th = self.threads.get(next).expect("ready thread exists");
        if let Some(v) = self.vspaces.get(th.vspace) {
            v.space.activate();
        }
        *frame = th.ctx;
        Next::Resume
    }

    fn print_stats(&self) {
        let s = self.stats;
        let (free, total) = mm::frame::stats();
        kprintln!(
            "[kernel] stats: {} syscalls ({} denied), {} IPC messages, {} faults contained, \
             {} preemptions, {} context switches",
            s.syscalls,
            s.denied,
            s.ipc_messages,
            s.faults,
            s.preemptions,
            s.context_switches
        );
        kprintln!(
            "[kernel] memory: {} / {} frames free, heap {} bytes, {} live capabilities",
            free,
            total,
            mm::heap::allocated(),
            self.caps.len()
        );
    }
}

/// Entry point for every trap from user mode (called by `arch::entry`).
pub fn user_trap(frame: &mut TrapFrame) {
    let next = {
        let mut guard = KERNEL.lock();
        let k = guard.as_mut().expect("kernel not initialised");
        let next = k.handle_trap(frame);
        if let Next::Shutdown(_) = next {
            k.print_stats();
        }
        next
    };
    if let Next::Shutdown(success) = next {
        if success {
            kprintln!("[kernel] system shut down cleanly");
        } else {
            kprintln!("[kernel] system shut down with an error");
        }
        arch::shutdown(success);
    }
}

/// Boot-time construction of the initial processes.
pub fn init(rng: ChaChaRng, modules: &[(&str, &[u8])]) {
    let mut k = Kernel::new(rng);
    let image = |name: &str| {
        modules
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, d)| *d)
            .unwrap_or_else(|| panic!("boot module '{name}' missing"))
    };

    let init = loader::spawn(&mut k, "init", image("init")).expect("failed to load init");
    let sandbox =
        loader::spawn(&mut k, "sandbox", image("sandbox")).expect("failed to load sandbox");

    let untyped = k
        .untypeds
        .insert(Untyped {
            remaining: limits::ROOT_UNTYPED_BYTES,
            refs: 0,
        })
        .expect("untyped");
    let cspace = k.threads.get(init.thread).expect("init").cspace;
    let initial = [
        (
            abi::slot::SELF_VSPACE,
            Object::VSpace(init.vspace),
            Rights::ALL,
        ),
        (
            abi::slot::SELF_THREAD,
            Object::Thread(init.thread),
            Rights::ALL,
        ),
        (abi::slot::UNTYPED, Object::Untyped(untyped), Rights::ALL),
        (
            abi::slot::CONSOLE,
            Object::Console,
            Rights::WRITE.union(Rights::GRANT),
        ),
        (
            abi::slot::SANDBOX_THREAD,
            Object::Thread(sandbox.thread),
            Rights::ALL,
        ),
        (
            abi::slot::SANDBOX_VSPACE,
            Object::VSpace(sandbox.vspace),
            Rights::ALL,
        ),
    ];
    for (slot, object, rights) in initial {
        k.caps
            .insert_root(
                cspace,
                slot,
                Capability {
                    object,
                    rights,
                    badge: 0,
                },
            )
            .expect("initial cap");
        k.retain(&object);
    }
    k.caps
        .check_invariants()
        .expect("capability database invariants");

    k.root = Some(init.thread);
    k.make_ready(init.thread);
    kprintln!(
        "[kernel] root task 'init' ready with {} initial capabilities; 'sandbox' created (inactive)",
        initial.len()
    );
    *KERNEL.lock() = Some(k);
}

/// Starts the scheduler and enters user mode. Never returns.
pub fn run(kernel_stack_top: u64) -> ! {
    let frame = {
        let mut guard = KERNEL.lock();
        let k = guard.as_mut().expect("kernel not initialised");
        let mut frame = TrapFrame::default();
        if let Next::Shutdown(_) = k.dispatch(&mut frame) {
            panic!("nothing to run");
        }
        frame
    };
    apic::start_timer(1_000_000);
    arch::entry::enter_user(&frame, kernel_stack_top)
}

/// Copies a NUL-free label for log prefixes.
pub(crate) fn prefix(name: &str) -> String {
    let mut s = String::from("[");
    s.push_str(name);
    s.push_str("] ");
    s
}
