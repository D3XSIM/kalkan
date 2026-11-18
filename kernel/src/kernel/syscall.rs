//! System call dispatch.
//!
//! Every argument is treated as hostile: slot indices are bounds checked (and
//! clamped against speculation), rights bits are validated, addresses are checked
//! against the user range, and every operation states exactly which right it
//! needs on which capability. A failing system call never changes kernel state.

use kcore::abi::{self, Error, sys};
use kcore::cspace::Capability;
use kcore::nospec;
use kcore::rights::Rights;

use super::object::*;
use super::{Kernel, prefix};
use crate::kprintln;
use crate::log;
use crate::mm::user::UserPerms;
use crate::mm::{self, PAGE_SIZE};

type SysResult = Result<(), Error>;

/// Maximum number of bytes accepted by `debug_write`.
const MAX_DEBUG_WRITE: u64 = 4096;

impl Kernel {
    /// Handles a system call from `t`. Returns `Some(success)` to shut down.
    pub(super) fn syscall(&mut self, t: ThreadId) -> Option<bool> {
        let th = self.threads.get(t)?;
        let c = th.ctx;
        let a = [c.rdi, c.rsi, c.rdx, c.r10, c.r8, c.r9];
        let cspace = th.cspace;

        // Spectre v1: the system call number is clamped before it is used.
        let Some(nr) = nospec::clamp(c.rax, sys::COUNT as usize) else {
            self.finish_syscall(t, Err(Error::NoSys));
            return None;
        };
        let nr = nr as u64;

        let result = match nr {
            sys::DEBUG_WRITE => self.sys_debug_write(t, cspace, a[0], a[1], a[2]),
            sys::CAP_MINT => self.sys_cap_mint(cspace, a[0], a[1], a[2], a[3]),
            sys::CAP_DELETE => self.sys_cap_delete(cspace, a[0]),
            sys::CAP_REVOKE => self.sys_cap_revoke(cspace, a[0]),
            sys::CAP_INFO => self.sys_cap_info(t, cspace, a[0]),
            sys::UNTYPED_RETYPE => self.sys_retype(cspace, a[0], a[1], a[2]),
            sys::VSPACE_MAP => self.sys_vspace_map(cspace, a[0], a[1], a[2], a[3]),
            sys::VSPACE_UNMAP => self.sys_vspace_unmap(cspace, a[0]),
            sys::THREAD_GRANT => self.sys_thread_grant(cspace, a[0], a[1], a[2], a[3], a[4]),
            sys::THREAD_START => self.sys_thread_start(cspace, a[0]),
            sys::THREAD_SET_FAULT_EP => self.sys_thread_set_fault_ep(cspace, a[0], a[1]),
            sys::THREAD_EXIT => {
                if Some(t) == self.root {
                    kprintln!("[kernel] root task exited with code {:#x}", a[0]);
                    return Some(a[0] == 0);
                }
                kprintln!(
                    "[kernel] thread '{}' exited with code {:#x}",
                    self.name(t),
                    a[0]
                );
                // A supervised thread reports its exit like a fault, so its
                // supervisor is never left waiting for it.
                match self.threads.get(t).and_then(|th| th.fault_ep) {
                    Some((ep, badge)) if self.endpoints.contains(ep) => {
                        let msg = Outgoing {
                            badge,
                            words: [abi::EXIT_VECTOR, a[0], 0, 0],
                            cap_slot: None,
                            call: false,
                            fault: true,
                        };
                        self.ipc_send(t, ep, msg);
                    }
                    _ => self.finish_thread(t),
                }
                return None;
            }
            sys::YIELD => {
                self.need_resched = true;
                Ok(())
            }
            sys::EP_SEND | sys::EP_CALL => {
                let call = nr == sys::EP_CALL;
                match self.endpoint_cap(cspace, a[0], Rights::WRITE) {
                    Ok((ep, badge)) => {
                        let cap_slot = (a[5] != abi::NO_CAP).then_some(a[5]);
                        let msg = Outgoing {
                            badge,
                            words: [a[1], a[2], a[3], a[4]],
                            cap_slot,
                            call,
                            fault: false,
                        };
                        self.ipc_send(t, ep, msg);
                        return None; // completion is handled by IPC
                    }
                    Err(e) => Err(e),
                }
            }
            sys::EP_RECV => match self.endpoint_cap(cspace, a[0], Rights::READ) {
                Ok((ep, _)) => {
                    let recv_slot = (a[1] != abi::NO_CAP).then_some(a[1]);
                    if let Some(slot) = recv_slot {
                        match self.caps.is_free(cspace, slot) {
                            Ok(true) => {}
                            Ok(false) => return self.fail(t, Error::SlotOccupied),
                            Err(e) => return self.fail(t, e.into()),
                        }
                    }
                    self.ipc_recv(t, ep, recv_slot);
                    return None;
                }
                Err(e) => Err(e),
            },
            sys::EP_REPLY => self.ipc_reply(t, [a[0], a[1], a[2], a[3]]),
            sys::RANDOM => {
                let v = self.rng.next_u64();
                if let Some(th) = self.threads.get_mut(t) {
                    th.ctx.rdi = v;
                }
                Ok(())
            }
            sys::KERNEL_STATS => self.sys_kernel_stats(t, cspace, a[0]),
            _ => Err(Error::NoSys),
        };
        self.finish_syscall(t, result);
        None
    }

    fn fail(&mut self, t: ThreadId, e: Error) -> Option<bool> {
        self.finish_syscall(t, Err(e));
        None
    }

    fn finish_syscall(&mut self, t: ThreadId, result: SysResult) {
        if let Err(e) = result
            && matches!(
                e,
                Error::PermissionDenied | Error::WxViolation | Error::BadAddress
            )
        {
            self.stats.denied += 1;
        }
        if let Some(th) = self.threads.get_mut(t)
            && th.state == ThreadState::Ready
        {
            th.ctx.rax = match result {
                Ok(()) => 0,
                Err(e) => e as u64,
            };
        }
    }

    // ------------------------------------------------------------- lookups

    fn endpoint_cap(
        &self,
        cs: CSpaceId,
        slot: u64,
        need: Rights,
    ) -> Result<(EndpointId, u64), Error> {
        let cap = self.caps.lookup(cs, slot, need)?;
        match cap.object {
            Object::Endpoint(ep) if self.endpoints.contains(ep) => Ok((ep, cap.badge)),
            Object::Endpoint(_) => Err(Error::Dead),
            _ => Err(Error::WrongType),
        }
    }

    fn thread_cap(&self, cs: CSpaceId, slot: u64, need: Rights) -> Result<ThreadId, Error> {
        match self.caps.lookup(cs, slot, need)?.object {
            Object::Thread(t) if self.threads.contains(t) => Ok(t),
            Object::Thread(_) => Err(Error::Dead),
            _ => Err(Error::WrongType),
        }
    }

    // ------------------------------------------------------------- handlers

    fn sys_debug_write(
        &mut self,
        t: ThreadId,
        cs: CSpaceId,
        slot: u64,
        ptr: u64,
        len: u64,
    ) -> SysResult {
        let cap = self.caps.lookup(cs, slot, Rights::WRITE)?;
        if cap.object != Object::Console {
            return Err(Error::WrongType);
        }
        if len > MAX_DEBUG_WRITE {
            return Err(Error::InvalidArgument);
        }
        let th = self.threads.get(t).ok_or(Error::Dead)?;
        let space = &self.vspaces.get(th.vspace).ok_or(Error::Dead)?.space;
        // A fixed buffer on the kernel stack: no heap allocation per call.
        let mut storage = [0u8; MAX_DEBUG_WRITE as usize];
        let buf = &mut storage[..len as usize];
        space
            .copy_from_user(ptr, buf)
            .map_err(|_| Error::BadAddress)?;
        log::write_untrusted(&prefix(&th.name), buf);
        Ok(())
    }

    fn sys_kernel_stats(&mut self, t: ThreadId, cs: CSpaceId, slot: u64) -> SysResult {
        let cap = self.caps.lookup(cs, slot, Rights::READ)?;
        if cap.object != Object::Console {
            return Err(Error::WrongType);
        }
        let (free, _) = mm::frame::stats();
        let values = [
            free as u64,
            mm::heap::allocated() as u64,
            self.caps.len() as u64,
            self.threads.len() as u64,
            self.frames.len() as u64,
            self.endpoints.len() as u64,
        ];
        let th = self.threads.get_mut(t).ok_or(Error::Dead)?;
        [
            th.ctx.rdi, th.ctx.rsi, th.ctx.rdx, th.ctx.r10, th.ctx.r8, th.ctx.r9,
        ] = values;
        Ok(())
    }

    fn sys_cap_mint(
        &mut self,
        cs: CSpaceId,
        src: u64,
        dst: u64,
        rights: u64,
        badge: u64,
    ) -> SysResult {
        let rights = Rights::from_bits(rights).ok_or(Error::InvalidArgument)?;
        self.caps.mint((cs, src), (cs, dst), rights, badge)?;
        let obj = self.caps.get(cs, dst)?.object;
        self.retain(&obj);
        Ok(())
    }

    fn sys_cap_delete(&mut self, cs: CSpaceId, slot: u64) -> SysResult {
        let cap = self.caps.delete(cs, slot)?;
        self.on_cap_removed(cap);
        Ok(())
    }

    fn sys_cap_revoke(&mut self, cs: CSpaceId, slot: u64) -> SysResult {
        let removed = self.caps.revoke(cs, slot)?;
        for cap in removed {
            self.on_cap_removed(cap);
        }
        Ok(())
    }

    fn sys_cap_info(&mut self, t: ThreadId, cs: CSpaceId, slot: u64) -> SysResult {
        let cap = self.caps.get(cs, slot)?;
        let (ty, rights, badge) = (cap.object.type_code(), cap.rights.bits(), cap.badge);
        let th = self.threads.get_mut(t).ok_or(Error::Dead)?;
        th.ctx.rdi = ty;
        th.ctx.rsi = rights;
        th.ctx.rdx = badge;
        Ok(())
    }

    fn sys_retype(
        &mut self,
        cs: CSpaceId,
        untyped_slot: u64,
        obj_type: u64,
        dst: u64,
    ) -> SysResult {
        let ut = match self.caps.lookup(cs, untyped_slot, Rights::WRITE)?.object {
            Object::Untyped(u) => u,
            _ => return Err(Error::WrongType),
        };
        if !self.caps.is_free(cs, dst)? {
            return Err(Error::SlotOccupied);
        }
        let cost = match obj_type {
            abi::obj::FRAME => abi::cost::FRAME,
            abi::obj::ENDPOINT => abi::cost::ENDPOINT,
            _ => return Err(Error::InvalidArgument),
        };
        let untyped = self.untypeds.get_mut(ut).ok_or(Error::Dead)?;
        if untyped.remaining < cost {
            return Err(Error::OutOfMemory);
        }
        untyped.remaining -= cost;
        let charge = Some((ut, cost));

        let created = match obj_type {
            abi::obj::FRAME => mm::frame::alloc_user()
                .ok_or(Error::OutOfMemory)
                .and_then(|phys| {
                    self.frames
                        .insert(Frame {
                            phys,
                            refs: 0,
                            charge,
                            writable_maps: 0,
                            exec_maps: 0,
                        })
                        .map_err(|_| {
                            mm::frame::free(phys);
                            Error::OutOfMemory
                        })
                })
                .map(|id| (Object::Frame { id, mapped: None }, Rights::ALL)),
            _ => self
                .endpoints
                .insert(Endpoint {
                    charge,
                    ..Endpoint::default()
                })
                .map_err(|_| Error::OutOfMemory)
                .map(|id| {
                    (
                        Object::Endpoint(id),
                        Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
                    )
                }),
        };
        let (object, rights) = match created {
            Ok(v) => v,
            Err(e) => {
                self.refund(charge);
                return Err(e);
            }
        };
        self.retain(&object);
        // Recorded as a child of the untyped capability: revoking the budget
        // destroys everything created from it.
        if let Err(e) = self.caps.insert_child(
            (cs, untyped_slot),
            (cs, dst),
            Capability {
                object,
                rights,
                badge: 0,
            },
        ) {
            self.release(object);
            return Err(e.into());
        }
        Ok(())
    }

    fn sys_vspace_map(
        &mut self,
        cs: CSpaceId,
        vs_slot: u64,
        frame_slot: u64,
        vaddr: u64,
        perms: u64,
    ) -> SysResult {
        let perms = Rights::from_bits(perms).ok_or(Error::InvalidArgument)?;
        if !perms.contains(Rights::READ) || perms.contains(Rights::GRANT) {
            return Err(Error::InvalidArgument);
        }
        let writable = perms.contains(Rights::WRITE);
        let executable = perms.contains(Rights::EXEC);
        let user_perms = UserPerms::new(writable, executable).ok_or(Error::WxViolation)?;
        if !vaddr.is_multiple_of(PAGE_SIZE) || !abi::is_user_range(vaddr, PAGE_SIZE) {
            return Err(Error::BadAddress);
        }
        let vs = match self.caps.lookup(cs, vs_slot, Rights::WRITE)?.object {
            Object::VSpace(v) => v,
            _ => return Err(Error::WrongType),
        };
        // The mapping may not exceed the rights of the frame capability.
        let (frame_id, mapped) = match self.caps.lookup(cs, frame_slot, perms)?.object {
            Object::Frame { id, mapped } => (id, mapped),
            _ => return Err(Error::WrongType),
        };
        if mapped.is_some() {
            return Err(Error::AlreadyMapped);
        }
        let frame = self.frames.get(frame_id).ok_or(Error::Dead)?;
        // W^X per frame: refuse to make a frame writable anywhere while it is
        // executable somewhere (or vice versa), even through aliases.
        if (writable && frame.exec_maps > 0) || (executable && frame.writable_maps > 0) {
            return Err(Error::WxViolation);
        }
        let phys = frame.phys;
        let v = self.vspaces.get_mut(vs).ok_or(Error::Dead)?;
        v.space.map(vaddr, phys, user_perms).map_err(|e| match e {
            mm::paging::MapError::OutOfMemory => Error::OutOfMemory,
            _ => Error::AlreadyMapped,
        })?;
        if let Some(f) = self.frames.get_mut(frame_id) {
            f.writable_maps += u32::from(writable);
            f.exec_maps += u32::from(executable);
        }
        if let Object::Frame { mapped, .. } = self.caps.object_mut(cs, frame_slot)? {
            *mapped = Some(Mapping {
                vspace: vs,
                vaddr,
                writable,
                executable,
            });
        }
        Ok(())
    }

    fn sys_vspace_unmap(&mut self, cs: CSpaceId, frame_slot: u64) -> SysResult {
        let obj = self.caps.object_mut(cs, frame_slot)?;
        let Object::Frame { id, mapped } = obj else {
            return Err(Error::WrongType);
        };
        let id = *id;
        let m = mapped.take().ok_or(Error::InvalidState)?;
        self.unmap_frame(id, m);
        Ok(())
    }

    fn sys_thread_grant(
        &mut self,
        cs: CSpaceId,
        thread_slot: u64,
        src: u64,
        dst: u64,
        rights: u64,
        badge: u64,
    ) -> SysResult {
        let target = self.thread_cap(cs, thread_slot, Rights::WRITE)?;
        let rights = Rights::from_bits(rights).ok_or(Error::InvalidArgument)?;
        let target_cs = self.threads.get(target).ok_or(Error::Dead)?.cspace;
        // Cross-CSpace mint: kcore enforces GRANT on the source capability.
        self.caps.mint((cs, src), (target_cs, dst), rights, badge)?;
        let obj = self.caps.get(target_cs, dst)?.object;
        self.retain(&obj);
        Ok(())
    }

    fn sys_thread_start(&mut self, cs: CSpaceId, thread_slot: u64) -> SysResult {
        let target = self.thread_cap(cs, thread_slot, Rights::WRITE)?;
        let th = self.threads.get(target).ok_or(Error::Dead)?;
        if th.state != ThreadState::Inactive {
            return Err(Error::InvalidState);
        }
        kprintln!("[kernel] starting thread '{}'", th.name);
        self.make_ready(target);
        Ok(())
    }

    fn sys_thread_set_fault_ep(
        &mut self,
        cs: CSpaceId,
        thread_slot: u64,
        ep_slot: u64,
    ) -> SysResult {
        let target = self.thread_cap(cs, thread_slot, Rights::WRITE)?;
        let (ep, badge) = self.endpoint_cap(cs, ep_slot, Rights::WRITE)?;
        // The thread holds a reference on its fault endpoint, so the endpoint (and
        // the id stored here) stays valid for as long as the thread needs it.
        self.retain(&Object::Endpoint(ep));
        let th = self.threads.get_mut(target).ok_or(Error::Dead)?;
        if let Some((old, _)) = th.fault_ep.replace((ep, badge)) {
            self.release(Object::Endpoint(old));
        }
        Ok(())
    }
}
