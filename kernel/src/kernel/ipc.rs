//! Synchronous IPC through endpoints.
//!
//! Messages are rendezvous-based: a sender blocks until a receiver arrives and vice
//! versa; nothing is buffered in the kernel, so IPC cannot be used to exhaust
//! kernel memory. Every message carries the *badge* of the capability the sender
//! used, which the sender cannot forge — servers identify clients by badge.
//!
//! A message may carry one capability. The transfer is a `mint` from the sender's
//! CSpace into the receiver's, so it is subject to the same rules as any other
//! derivation: it requires the GRANT right on the transferred capability and it is
//! recorded in the derivation tree (the sender can revoke it later).
//!
//! `call` gives the receiver a one-shot reply right that is consumed by `reply`.
//! A server that receives again without replying gives the right up: the waiting
//! caller is released with `EDEAD` instead of waiting forever.

use kcore::abi;

use super::Kernel;
use super::object::*;

impl Kernel {
    /// `sender` sends `msg` on `ep`. Either delivers immediately or blocks.
    pub(super) fn ipc_send(&mut self, sender: ThreadId, ep: EndpointId, msg: Outgoing) {
        let receiver = loop {
            let Some(e) = self.endpoints.get_mut(ep) else {
                if msg.fault {
                    // Nobody left to report to.
                    self.finish_thread(sender);
                } else {
                    self.complete(sender, Err(abi::Error::Dead));
                }
                return;
            };
            match e.receivers.pop_front() {
                Some(r)
                    if self
                        .threads
                        .get(r)
                        .is_some_and(|t| t.state == ThreadState::BlockedRecv(ep)) =>
                {
                    break Some(r);
                }
                Some(_) => continue, // stale entry
                None => break None,
            }
        };
        match receiver {
            Some(r) => self.deliver(sender, msg, r),
            None => {
                if let Some(t) = self.threads.get_mut(sender) {
                    t.state = ThreadState::BlockedSend(ep);
                    t.outgoing = msg;
                }
                if let Some(e) = self.endpoints.get_mut(ep) {
                    e.senders.push_back(sender);
                }
            }
        }
    }

    /// `receiver` waits for a message on `ep`.
    pub(super) fn ipc_recv(&mut self, receiver: ThreadId, ep: EndpointId, recv_slot: Option<u64>) {
        let abandoned = self.threads.get_mut(receiver).and_then(|t| {
            t.recv_slot = recv_slot;
            t.reply_to.take()
        });
        // Receiving again without replying abandons the pending call: release the
        // caller instead of leaving it blocked forever.
        if let Some(caller) = abandoned
            && self
                .threads
                .get(caller)
                .is_some_and(|c| c.state == ThreadState::BlockedReply)
        {
            self.complete(caller, Err(abi::Error::Dead));
        }
        let sender = loop {
            let Some(e) = self.endpoints.get_mut(ep) else {
                self.complete(receiver, Err(abi::Error::Dead));
                return;
            };
            match e.senders.pop_front() {
                Some(s)
                    if self
                        .threads
                        .get(s)
                        .is_some_and(|t| t.state == ThreadState::BlockedSend(ep)) =>
                {
                    break Some(s);
                }
                Some(_) => continue,
                None => break None,
            }
        };
        match sender {
            Some(s) => {
                let msg = self.threads.get(s).map(|t| t.outgoing).unwrap_or_default();
                self.deliver(s, msg, receiver);
            }
            None => {
                if let Some(t) = self.threads.get_mut(receiver) {
                    t.state = ThreadState::BlockedRecv(ep);
                }
                if let Some(e) = self.endpoints.get_mut(ep) {
                    e.receivers.push_back(receiver);
                }
            }
        }
    }

    /// Transfers `msg` from `sender` to `receiver` and updates both threads.
    fn deliver(&mut self, sender: ThreadId, msg: Outgoing, receiver: ThreadId) {
        self.stats.ipc_messages += 1;
        let mut info = if msg.fault { abi::msg::FAULT } else { 0 };

        if let Some(src_slot) = msg.cap_slot {
            let src_space = self.threads.get(sender).map(|t| t.cspace);
            let dst = self
                .threads
                .get(receiver)
                .and_then(|t| t.recv_slot.map(|s| (t.cspace, s)));
            let transferred = match (src_space, dst) {
                (Some(ss), Some((ds, dslot))) => {
                    let rights = self.caps.get(ss, src_slot).map(|c| c.rights);
                    match rights.and_then(|r| self.caps.mint((ss, src_slot), (ds, dslot), r, 0)) {
                        Ok(_) => {
                            if let Ok(cap) = self.caps.get(ds, dslot) {
                                let obj = cap.object;
                                self.retain(&obj);
                            }
                            true
                        }
                        Err(_) => false,
                    }
                }
                _ => false,
            };
            info |= if transferred {
                abi::msg::CAP_TRANSFERRED
            } else {
                abi::msg::CAP_REFUSED
            };
            if !transferred {
                self.stats.denied += 1;
            }
        }

        if let Some(r) = self.threads.get_mut(receiver) {
            r.ctx.rdi = msg.badge;
            r.ctx.rsi = msg.words[0];
            r.ctx.rdx = msg.words[1];
            r.ctx.r10 = msg.words[2];
            r.ctx.r8 = msg.words[3];
            r.ctx.r9 = info;
            r.reply_to = if msg.call { Some(sender) } else { None };
        }
        self.complete(receiver, Ok(()));

        if msg.fault {
            // The faulting thread never runs again; its report has been delivered.
            self.finish_thread(sender);
        } else if msg.call {
            if let Some(s) = self.threads.get_mut(sender) {
                s.state = ThreadState::BlockedReply;
            }
        } else {
            self.complete(sender, Ok(()));
        }
    }

    /// Replies to the caller recorded in `replier`'s one-shot reply slot.
    pub(super) fn ipc_reply(
        &mut self,
        replier: ThreadId,
        words: [u64; 4],
    ) -> Result<(), abi::Error> {
        let caller = self
            .threads
            .get_mut(replier)
            .and_then(|t| t.reply_to.take())
            .ok_or(abi::Error::InvalidState)?;
        let Some(c) = self.threads.get_mut(caller) else {
            return Err(abi::Error::Dead);
        };
        if c.state != ThreadState::BlockedReply {
            return Err(abi::Error::InvalidState);
        }
        c.ctx.rsi = words[0];
        c.ctx.rdx = words[1];
        c.ctx.r10 = words[2];
        c.ctx.r8 = words[3];
        c.ctx.rdi = 0;
        c.ctx.r9 = 0;
        self.stats.ipc_messages += 1;
        self.complete(caller, Ok(()));
        Ok(())
    }
}
