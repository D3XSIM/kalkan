//! Kernel self-audit.
//!
//! The kernel keeps several derived quantities for speed: reference counts,
//! per-frame mapping counters, budget balances, scheduler and IPC queues, the
//! call/reply bookkeeping and the state of terminated threads. A bug in any path
//! that maintains them could turn into a use-after-free of physical memory, a
//! capability that outlives its object, or a thread that waits forever.
//!
//! [`Kernel::audit`] recomputes every one of these quantities **from first
//! principles** (by walking all capabilities, threads and page tables) and
//! compares the result with the stored state. With the `audit` feature — enabled
//! by `cargo xtask test` — it runs after *every* trap, so the adversarial test
//! suite and the system call fuzzer check the complete object graph thousands of
//! times; without the feature it still runs once at shutdown.
//!
//! Page tables are checked in both directions: every mapping a capability
//! records must be in the page tables (every audit), and every page present in
//! the page tables must be accounted for by a capability or by the program image
//! the kernel loaded — never writable and executable at once — while the number
//! of page tables must match the quota counter (every
//! [`PAGE_WALK_INTERVAL`]-th audit and at boot and shutdown, as walking every
//! table is slow).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::Kernel;
use super::object::*;
use crate::mm::paging::ADDR_MASK;
use crate::mm::paging::flags::{HUGE, NO_EXECUTE, USER, WRITABLE};

/// Every how many audits the user page tables are walked completely.
pub const PAGE_WALK_INTERVAL: u64 = 64;

type Audit = Result<(), String>;

fn ensure(cond: bool, msg: impl FnOnce() -> String) -> Audit {
    if cond { Ok(()) } else { Err(msg()) }
}

/// Totals found by an audit.
#[derive(Clone, Copy, Debug, Default)]
pub struct Census {
    pub capabilities: usize,
    pub threads: usize,
    pub endpoints: usize,
    pub frames: usize,
    pub vspaces: usize,
    pub untypeds: usize,
    pub mappings: usize,
    /// User page tables (counted when the page tables were walked).
    pub page_tables: usize,
}

impl Kernel {
    /// Verifies the consistency of the whole object graph.
    ///
    /// `scheduling` additionally checks the run queue and the current thread; it is
    /// skipped at shutdown, when no thread is going to run again.
    pub(super) fn audit(&self, scheduling: bool) -> Result<Census, String> {
        self.caps.check_invariants().map_err(String::from)?;

        let caps: Vec<Object> = self.caps.iter().map(|c| c.object).collect();
        let mut census = Census {
            capabilities: caps.len(),
            ..Census::default()
        };

        // --- every capability to a reference-counted object points to a live one
        for obj in &caps {
            let alive = match *obj {
                Object::Untyped(id) => self.untypeds.contains(id),
                Object::Frame { id, .. } => self.frames.contains(id),
                Object::VSpace(id) => self.vspaces.contains(id),
                Object::Endpoint(id) => self.endpoints.contains(id),
                // Thread capabilities are weak references by design.
                Object::Thread(_) | Object::Console | Object::Entropy => true,
            };
            ensure(alive, || {
                format!("capability to a destroyed object: {obj:?}")
            })?;
        }

        // --- frames: reference counts, W^X counters, mappings
        let mut mappings: Vec<(FrameId, Mapping)> = Vec::new();
        for (id, f) in self.frames.iter() {
            census.frames += 1;
            let mut refs = 0u32;
            let (mut writable, mut executable) = (0u32, 0u32);
            for obj in &caps {
                if let Object::Frame { id: fid, mapped } = *obj
                    && fid == id
                {
                    refs += 1;
                    if let Some(m) = mapped {
                        writable += u32::from(m.writable);
                        executable += u32::from(m.executable);
                        mappings.push((id, m));
                    }
                }
            }
            ensure(refs > 0, || {
                format!("frame {id:?} has no capability (leak)")
            })?;
            ensure(f.refs == refs, || {
                format!("frame {id:?}: refs {} but {refs} capabilities", f.refs)
            })?;
            ensure(
                f.writable_maps == writable && f.exec_maps == executable,
                || {
                    format!(
                        "frame {id:?}: map counters w{}/x{} but found w{writable}/x{executable}",
                        f.writable_maps, f.exec_maps
                    )
                },
            )?;
            ensure(!(writable > 0 && executable > 0), || {
                format!("frame {id:?} is writable and executable at the same time")
            })?;
        }
        census.mappings = mappings.len();
        for (i, (frame, m)) in mappings.iter().enumerate() {
            ensure(
                !mappings[..i]
                    .iter()
                    .any(|(_, o)| o.vspace == m.vspace && o.vaddr == m.vaddr),
                || format!("two capabilities claim the mapping at {:#x}", m.vaddr),
            )?;
            // The page tables must agree with the capability (while the address
            // space exists).
            if let Some(v) = self.vspaces.get(m.vspace) {
                let phys = self.frames.get(*frame).map(|f| f.phys);
                let t = v.space.translate(m.vaddr);
                ensure(
                    t.is_some_and(|t| {
                        Some(t.phys) == phys
                            && t.writable == m.writable
                            && t.executable == m.executable
                            && t.user
                    }),
                    || format!("page tables disagree with mapping {m:?}: {t:?}"),
                )?;
            }
        }

        // --- endpoints: reference counts and queues
        for (id, e) in self.endpoints.iter() {
            census.endpoints += 1;
            let cap_refs = caps.iter().filter(|o| **o == Object::Endpoint(id)).count();
            let handlers = self
                .threads
                .iter()
                .filter(|(_, t)| t.fault_ep.is_some_and(|(ep, _)| ep == id))
                .count();
            ensure(
                e.refs as usize == cap_refs
                    && e.handlers as usize == handlers
                    && cap_refs + handlers > 0,
                || {
                    format!(
                        "endpoint {id:?}: refs {}/handlers {} but {cap_refs} capabilities + \
                         {handlers} fault handlers",
                        e.refs, e.handlers
                    )
                },
            )?;
            ensure(
                cap_refs > 0 || (e.senders.is_empty() && e.receivers.is_empty()),
                || format!("endpoint {id:?} has no capabilities but threads waiting on it"),
            )?;
            ensure(e.senders.is_empty() || e.receivers.is_empty(), || {
                format!("endpoint {id:?} has senders and receivers waiting at once")
            })?;
            for (queue, want) in [
                (&e.senders, ThreadState::BlockedSend(id)),
                (&e.receivers, ThreadState::BlockedRecv(id)),
            ] {
                for (i, t) in queue.iter().enumerate() {
                    ensure(
                        self.threads.get(*t).is_some_and(|th| th.state == want),
                        || format!("endpoint {id:?} queues thread {t:?} which is not {want:?}"),
                    )?;
                    ensure(!queue.iter().take(i).any(|o| o == t), || {
                        format!("endpoint {id:?} queues thread {t:?} twice")
                    })?;
                }
            }
        }

        // --- address spaces
        for (id, v) in self.vspaces.iter() {
            census.vspaces += 1;
            let cap_refs = caps.iter().filter(|o| **o == Object::VSpace(id)).count();
            let thread_refs = self
                .threads
                .iter()
                .filter(|(_, t)| t.vspace == id && !t.zombie)
                .count();
            ensure(
                v.refs as usize == cap_refs + thread_refs && v.refs > 0,
                || {
                    format!(
                        "vspace {id:?}: refs {} but {cap_refs} capabilities + {thread_refs} threads",
                        v.refs
                    )
                },
            )?;
        }

        // --- page tables, the other way round (see the module documentation)
        if !scheduling || self.stats.audits.is_multiple_of(PAGE_WALK_INTERVAL) {
            for (id, v) in self.vspaces.iter() {
                let mut stray: Option<(u64, u64)> = None;
                let (found, counted) = v.space.census(&mut |vaddr, entry| {
                    let phys = entry & ADDR_MASK;
                    let writable = entry & WRITABLE != 0;
                    let executable = entry & NO_EXECUTE == 0;
                    let by_capability = mappings.iter().any(|(f, m)| {
                        m.vspace == id
                            && m.vaddr == vaddr
                            && m.writable == writable
                            && m.executable == executable
                            && self.frames.get(*f).is_some_and(|fr| fr.phys == phys)
                    });
                    let loaded = v.owned_frames.contains(&phys);
                    let sound = entry & USER != 0 && entry & HUGE == 0 && !(writable && executable);
                    if stray.is_none() && !(sound && (by_capability || loaded)) {
                        stray = Some((vaddr, entry));
                    }
                });
                if let Some((vaddr, entry)) = stray {
                    return Err(format!(
                        "vspace {id:?}: page {vaddr:#x} (entry {entry:#x}) is unaccounted for"
                    ));
                }
                ensure(found == counted, || {
                    format!("vspace {id:?}: {found} page tables exist, the quota counts {counted}")
                })?;
                census.page_tables += found as usize;
            }
        }

        // --- untyped budgets: nothing is created or lost
        for (id, u) in self.untypeds.iter() {
            census.untypeds += 1;
            let cap_refs = caps.iter().filter(|o| **o == Object::Untyped(id)).count();
            ensure(u.refs as usize == cap_refs && u.refs > 0, || {
                format!(
                    "untyped {id:?}: refs {} but {cap_refs} capabilities",
                    u.refs
                )
            })?;
            let charged = |c: Charge| c.filter(|(ut, _)| *ut == id).map_or(0, |(_, bytes)| bytes);
            let spent: u64 = self
                .frames
                .iter()
                .map(|(_, f)| charged(f.charge))
                .sum::<u64>()
                + self
                    .endpoints
                    .iter()
                    .map(|(_, e)| charged(e.charge))
                    .sum::<u64>();
            ensure(u.remaining + spent == u.total, || {
                format!(
                    "untyped {id:?}: {} remaining + {spent} spent != {} total",
                    u.remaining, u.total
                )
            })?;
        }

        // --- threads
        for (id, t) in self.threads.iter() {
            census.threads += 1;
            if t.zombie {
                // Terminated: everything is released, only the final report is left.
                ensure(
                    matches!(t.state, ThreadState::BlockedSend(_)) && t.outgoing.fault,
                    || format!("terminated thread {id:?} is {:?}, not reporting", t.state),
                )?;
                ensure(
                    !self.caps.space_exists(t.cspace) && t.reply_to.is_none(),
                    || format!("terminated thread {id:?} still holds capabilities or a caller"),
                )?;
            } else {
                ensure(self.caps.space_exists(t.cspace), || {
                    format!("thread {id:?} lost its CSpace")
                })?;
                ensure(self.vspaces.contains(t.vspace), || {
                    format!("thread {id:?} lost its VSpace")
                })?;
            }
            // Call/reply: a waiting caller is owed its reply by exactly one live
            // thread, and a thread that owes a reply owes it to a waiting caller.
            if t.state == ThreadState::BlockedReply {
                let owed_by = self
                    .threads
                    .iter()
                    .filter(|(_, s)| s.reply_to == Some(id))
                    .count();
                ensure(owed_by == 1, || {
                    format!("thread {id:?} waits for a reply owed by {owed_by} threads")
                })?;
            }
            if let Some(caller) = t.reply_to {
                ensure(
                    self.threads
                        .get(caller)
                        .is_none_or(|c| c.state == ThreadState::BlockedReply),
                    || format!("thread {id:?} owes a reply to {caller:?}, which is not waiting"),
                )?;
            }
            if let Some((ep, _)) = t.fault_ep {
                ensure(self.endpoints.contains(ep), || {
                    format!("thread {id:?} has a destroyed fault endpoint")
                })?;
            }
            let queued = |ep: EndpointId, senders: bool| {
                self.endpoints.get(ep).is_some_and(|e| {
                    let q = if senders { &e.senders } else { &e.receivers };
                    q.iter().filter(|x| **x == id).count() == 1
                })
            };
            let consistent = match t.state {
                ThreadState::BlockedSend(ep) => queued(ep, true),
                ThreadState::BlockedRecv(ep) => queued(ep, false),
                ThreadState::Inactive | ThreadState::Ready | ThreadState::BlockedReply => true,
            };
            ensure(consistent, || {
                format!(
                    "thread {id:?} is {:?} but not queued on that endpoint",
                    t.state
                )
            })?;
        }

        // --- scheduler
        if scheduling {
            let current = self.current;
            ensure(current.is_some_and(|c| self.is_ready(c)), || {
                format!("current thread {current:?} is not runnable")
            })?;
            for (i, t) in self.run_queue.iter().enumerate() {
                ensure(self.is_ready(*t) && Some(*t) != current, || {
                    format!("run queue holds {t:?}, which is not a waiting ready thread")
                })?;
                ensure(!self.run_queue.iter().take(i).any(|o| o == t), || {
                    format!("run queue holds {t:?} twice")
                })?;
            }
            for (id, t) in self.threads.iter() {
                if t.state == ThreadState::Ready && Some(id) != current {
                    ensure(self.run_queue.contains(&id), || {
                        format!("ready thread {id:?} is not in the run queue (lost wake-up)")
                    })?;
                }
            }
        }
        Ok(census)
    }
}
