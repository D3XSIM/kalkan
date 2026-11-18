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

mod audit;
mod ipc;
pub mod loader;
pub mod object;
mod syscall;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use kcore::abi;
use kcore::arena::Arena;
use kcore::chacha20::ChaChaRng;
use kcore::cspace::{CapDb, Capability};
use kcore::rights::Rights;

use self::object::*;
use crate::arch::entry::{SPURIOUS_VECTOR, SYSCALL_VECTOR, TIMER_VECTOR, TrapFrame};
use crate::arch::{self, apic};
use crate::log::Addr;
use crate::sync::SpinLock;
use crate::{kprintln, mm};

/// Hard limits that bound kernel memory consumption regardless of user behaviour.
pub mod limits {
    /// Room for every capability space to be full at once: a process that fills
    /// its own space cannot exhaust the capability table for everybody else.
    pub const MAX_CAPS: usize = MAX_CSPACES * kcore::abi::CSPACE_SLOTS;
    pub const MAX_CSPACES: usize = 64;
    pub const MAX_THREADS: usize = 64;
    /// Room for every endpoint the root budget can pay for: holders of budgets
    /// cannot exhaust the endpoint table for each other.
    pub const MAX_ENDPOINTS: usize = (ROOT_UNTYPED_BYTES / kcore::abi::cost::ENDPOINT) as usize;
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
    pub audits: u64,
}

/// Addresses of live kernel memory. A test kernel hands them to the self-test
/// suite (`kernel_layout`) so that its attacks hit the real kernel despite KASLR;
/// other kernels never reveal them.
#[derive(Clone, Copy, Debug, Default)]
pub struct Landmarks {
    /// Start of the kernel's code.
    pub text: u64,
    /// Start of the kernel's writable data.
    pub data: u64,
    /// The kernel image as seen through the direct map of physical memory.
    pub direct_map: u64,
    /// A word on the kernel stack.
    pub stack: u64,
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
    /// Self-test only: kernel addresses and a live heap object to aim at.
    #[cfg_attr(not(feature = "selftest"), allow(dead_code))]
    pub(crate) landmarks: Landmarks,
    #[cfg_attr(not(feature = "selftest"), allow(dead_code))]
    pub(crate) heap_canary: Option<Box<[u64; 4]>>,
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
            landmarks: Landmarks::default(),
            heap_canary: None,
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
            Object::Thread(_) | Object::Console | Object::Entropy => {}
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
                        if e.handlers == 0 {
                            self.destroy_endpoint(id);
                        } else {
                            self.orphan_endpoint(id);
                        }
                    }
                }
            }
            Object::Thread(_) | Object::Console | Object::Entropy => {}
        }
    }

    /// A thread stops reporting its faults to `ep`.
    fn drop_handler(&mut self, ep: EndpointId) {
        if let Some(e) = self.endpoints.get_mut(ep) {
            e.handlers -= 1;
            if e.handlers == 0 && e.refs == 0 {
                self.destroy_endpoint(ep);
            }
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
        self.refund(ep.charge);
        self.wake_waiters(id, ep.senders.into_iter().chain(ep.receivers).collect());
    }

    /// The last capability to an endpoint is gone while some threads still name it
    /// as their fault endpoint. Nobody can ever receive from it again, so every
    /// waiting thread is released now, and later reports to it are dropped
    /// ([`Kernel::report_death`]) instead of waiting forever.
    fn orphan_endpoint(&mut self, id: EndpointId) {
        let Some(e) = self.endpoints.get_mut(id) else {
            return;
        };
        let waiting: Vec<ThreadId> = e.senders.drain(..).chain(e.receivers.drain(..)).collect();
        self.wake_waiters(id, waiting);
    }

    /// Wakes the threads that were waiting on endpoint `id` with `EDEAD`; a dead
    /// thread that was waiting to deliver its final report is removed.
    fn wake_waiters(&mut self, id: EndpointId, waiting: Vec<ThreadId>) {
        for t in waiting {
            // Only threads that really are blocked on this endpoint are touched.
            let Some(th) = self.threads.get(t) else {
                continue;
            };
            if !matches!(th.state, ThreadState::BlockedSend(e) | ThreadState::BlockedRecv(e) if e == id)
            {
                continue;
            }
            if th.zombie {
                self.finish_thread(t);
            } else {
                self.complete(t, Err(abi::Error::Dead));
            }
        }
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

    /// Releases everything a terminating thread owns — its capability space, its
    /// address space, and the caller waiting for its reply — but keeps the thread
    /// record, which may still have to deliver a final report to its supervisor.
    ///
    /// Called the moment a thread dies, so its memory comes back at once even if
    /// nobody ever collects the report (no zombie can pin memory).
    pub(crate) fn release_resources(&mut self, t: ThreadId) {
        let Some(th) = self.threads.get_mut(t) else {
            return;
        };
        if th.zombie {
            return;
        }
        th.zombie = true;
        let (cspace, vspace, reply_to) = (th.cspace, th.vspace, th.reply_to.take());
        // A caller waiting for this thread's reply must not wait forever.
        if let Some(caller) = reply_to
            && self
                .threads
                .get(caller)
                .is_some_and(|c| c.state == ThreadState::BlockedReply)
        {
            self.complete(caller, Err(abi::Error::Dead));
        }
        if let Ok(removed) = self.caps.destroy_space(cspace) {
            for cap in removed {
                self.on_cap_removed(cap);
            }
        }
        self.release_vspace(vspace);
        self.run_queue.retain(|x| *x != t);
    }

    /// Terminates a thread and removes it.
    pub(crate) fn finish_thread(&mut self, t: ThreadId) {
        self.release_resources(t);
        let Some(th) = self.threads.remove(t) else {
            return;
        };
        // Unlink from any endpoint queue it may still be in.
        if let ThreadState::BlockedSend(ep) | ThreadState::BlockedRecv(ep) = th.state
            && let Some(e) = self.endpoints.get_mut(ep)
        {
            e.senders.retain(|x| *x != t);
            e.receivers.retain(|x| *x != t);
        }
        if let Some((ep, _)) = th.fault_ep {
            self.drop_handler(ep);
        }
        self.run_queue.retain(|x| *x != t);
    }

    /// Sends the final report of a dying thread to its supervisor, or removes the
    /// thread right away if nobody can receive it. Its resources are released
    /// first, whether or not the report is ever collected.
    pub(crate) fn report_death(&mut self, t: ThreadId, words: [u64; 4]) {
        self.release_resources(t);
        // Checked after the release: dropping the thread's own capabilities may
        // have orphaned its fault endpoint.
        let target = self
            .threads
            .get(t)
            .and_then(|th| th.fault_ep)
            .filter(|&(ep, _)| {
                Some(t) != self.root && self.endpoints.get(ep).is_some_and(|e| e.refs > 0)
            });
        match target {
            Some((ep, badge)) => {
                let msg = Outgoing {
                    badge,
                    words,
                    cap_slot: None,
                    call: false,
                    fault: true,
                };
                self.ipc_send(t, ep, msg);
            }
            None => self.finish_thread(t),
        }
    }

    fn name(&self, t: ThreadId) -> &str {
        self.threads.get(t).map_or("?", |th| th.name.as_str())
    }

    /// Handles a CPU exception raised by user code.
    fn fault(&mut self, t: ThreadId, vector: u64, error: u64, addr: u64) {
        self.stats.faults += 1;
        let Some(rip) = self.threads.get(t).map(|th| th.ctx.rip) else {
            return;
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
            "[fault] thread '{}' killed: {} (vector {}) at rip={} addr={} err={:#x}",
            self.name(t),
            what,
            vector,
            Addr(rip),
            Addr(addr),
            error
        );
        if Some(t) == self.root {
            kprintln!("[fault] the root task faulted");
        }
        self.report_death(t, [vector, error, addr, rip]);
    }

    // --------------------------------------------------------------- scheduling

    fn handle_trap(&mut self, frame: &mut TrapFrame) -> Next {
        let next = self.handle_trap_inner(frame);
        // With the `audit` feature the complete object graph is re-verified after
        // every single trap.
        #[cfg(feature = "audit")]
        if matches!(next, Next::Resume) {
            self.stats.audits += 1;
            if let Err(e) = self.audit(true) {
                panic!("kernel audit failed: {e}");
            }
        }
        next
    }

    fn handle_trap_inner(&mut self, frame: &mut TrapFrame) -> Next {
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

    /// Prints the final statistics and audits the object graph one last time.
    /// Returns `false` if the audit found an inconsistency.
    fn print_stats(&self) -> bool {
        let s = self.stats;
        let (free, total) = mm::frame::stats();
        kprintln!(
            "[kernel] stats: {} syscalls ({} denied), {} IPC messages, {} faults contained, \
             {} preemptions, {} context switches, {} kernel-mode debug traps",
            s.syscalls,
            s.denied,
            s.ipc_messages,
            s.faults,
            s.preemptions,
            s.context_switches,
            arch::entry::kernel_debug_traps()
        );
        kprintln!(
            "[kernel] memory: {} / {} frames free, heap {} bytes, {} live capabilities",
            free,
            total,
            mm::heap::allocated(),
            self.caps.len()
        );
        match self.audit(false) {
            Ok(c) => {
                kprintln!(
                    "[kernel] audit: object graph consistent ({} capabilities, {} threads, \
                     {} endpoints, {} frames, {} mappings, {} page tables, {} address spaces); \
                     {} audits passed, {} with a full page-table walk",
                    c.capabilities,
                    c.threads,
                    c.endpoints,
                    c.frames,
                    c.mappings,
                    c.page_tables,
                    c.vspaces,
                    s.audits + 1,
                    s.audits / audit::PAGE_WALK_INTERVAL + 1
                );
                true
            }
            Err(e) => {
                kprintln!("[kernel] AUDIT FAILED: {e}");
                false
            }
        }
    }
}

/// Entry point for every trap from user mode (called by `arch::entry`).
pub fn user_trap(frame: &mut TrapFrame) {
    let next = {
        let mut guard = KERNEL.lock();
        let k = guard.as_mut().expect("kernel not initialised");
        match k.handle_trap(frame) {
            Next::Shutdown(ok) => Next::Shutdown(k.print_stats() && ok),
            next => next,
        }
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
pub fn init(rng: ChaChaRng, modules: &[(&str, &[u8])], landmarks: Landmarks) {
    let mut k = Kernel::new(rng);
    if cfg!(feature = "selftest") {
        k.landmarks = landmarks;
        // A live heap object for the "read kernel heap memory" attack.
        k.heap_canary = Some(Box::new([0x6b61_6c6b_616e_6361; 4]));
    }
    let image = |name: &str| {
        modules
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, d)| *d)
            .unwrap_or_else(|| panic!("boot module '{name}' missing"))
    };

    let describe = |name: &str, p: &loader::Spawned| {
        kprintln!(
            "[loader] '{}': {} segments, {} relocations, base {}, entry {}, stack top {}",
            name,
            p.segments,
            p.relocations,
            Addr(p.base),
            Addr(p.entry),
            Addr(p.stack_top)
        );
    };
    let init = loader::spawn(&mut k, "init", image("init")).expect("failed to load init");
    describe("init", &init);
    let sandbox =
        loader::spawn(&mut k, "sandbox", image("sandbox")).expect("failed to load sandbox");
    describe("sandbox", &sandbox);
    // Test kernels only: probe processes, further instances of the (untrusted)
    // sandbox image, each with its own address space, capability space and ASLR
    // layout. The self-test suite starts one per attack.
    let probe_count = if cfg!(feature = "selftest") {
        abi::PROBE_COUNT
    } else {
        0
    };
    let probes: Vec<loader::Spawned> = (0..probe_count)
        .map(|i| {
            loader::spawn(&mut k, &alloc::format!("probe{i:02}"), image("sandbox"))
                .expect("failed to load a probe process")
        })
        .collect();

    let untyped = k
        .untypeds
        .insert(Untyped {
            total: limits::ROOT_UNTYPED_BYTES,
            remaining: limits::ROOT_UNTYPED_BYTES,
            refs: 0,
        })
        .expect("untyped");
    let cspace = k.threads.get(init.thread).expect("init").cspace;
    let console_rights = Rights::READ.union(Rights::WRITE).union(Rights::GRANT);
    let mut initial = alloc::vec![
        (
            abi::slot::SELF_VSPACE,
            Object::VSpace(init.vspace),
            Rights::ALL
        ),
        (
            abi::slot::SELF_THREAD,
            Object::Thread(init.thread),
            Rights::ALL
        ),
        (abi::slot::UNTYPED, Object::Untyped(untyped), Rights::ALL),
        (abi::slot::CONSOLE, Object::Console, console_rights),
        (
            abi::slot::SANDBOX_THREAD,
            Object::Thread(sandbox.thread),
            Rights::ALL
        ),
        (
            abi::slot::SANDBOX_VSPACE,
            Object::VSpace(sandbox.vspace),
            Rights::ALL
        ),
        (
            abi::slot::ENTROPY,
            Object::Entropy,
            Rights::READ.union(Rights::GRANT)
        ),
    ];
    for (i, p) in probes.iter().enumerate() {
        let i = i as u64;
        initial.push((
            abi::slot::PROBE_THREAD_FIRST + i,
            Object::Thread(p.thread),
            Rights::ALL,
        ));
        initial.push((
            abi::slot::PROBE_VSPACE_FIRST + i,
            Object::VSpace(p.vspace),
            Rights::ALL,
        ));
    }
    for &(slot, object, rights) in &initial {
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
    k.audit(false)
        .expect("initial kernel state is inconsistent");
    kprintln!(
        "[kernel] root task 'init' ready with {} initial capabilities; 'sandbox' and {} probe \
         processes created (inactive){}",
        initial.len(),
        probes.len(),
        if cfg!(feature = "selftest") {
            "; test kernel"
        } else {
            ""
        }
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
