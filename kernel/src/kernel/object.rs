//! Kernel objects.
//!
//! Objects reference each other through generational [`Id`]s, never raw pointers.
//! An id of a destroyed object never resolves again, so stale references (in
//! capabilities, queues, fault handlers) degrade into a clean error instead of a
//! use-after-free.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use kcore::abi;
use kcore::arena::Id;
use kcore::cspace::{CapObject, SpaceId};

use crate::arch::entry::TrapFrame;
use crate::mm::user::AddressSpace;

pub type ThreadId = Id<Thread>;
pub type EndpointId = Id<Endpoint>;
pub type VSpaceId = Id<VSpace>;
pub type FrameId = Id<Frame>;
pub type UntypedId = Id<Untyped>;
pub type CSpaceId = SpaceId<Object>;

/// What a capability points to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    /// A memory budget from which new objects are created.
    Untyped(UntypedId),
    /// A physical frame. `mapped` records where *this capability* mapped it, so that
    /// deleting or revoking the capability also removes the mapping.
    Frame {
        id: FrameId,
        mapped: Option<Mapping>,
    },
    /// An address space.
    VSpace(VSpaceId),
    /// A thread.
    Thread(ThreadId),
    /// An IPC endpoint.
    Endpoint(EndpointId),
    /// The kernel debug console.
    Console,
}

impl CapObject for Object {
    fn derive(&self) -> Self {
        match *self {
            // A derived frame capability starts out unmapped.
            Self::Frame { id, .. } => Self::Frame { id, mapped: None },
            other => other,
        }
    }
}

impl Object {
    /// ABI type code (see `abi::obj`).
    #[must_use]
    pub const fn type_code(&self) -> u64 {
        match self {
            Self::Untyped(_) => abi::obj::UNTYPED,
            Self::Frame { .. } => abi::obj::FRAME,
            Self::VSpace(_) => abi::obj::VSPACE,
            Self::Thread(_) => abi::obj::THREAD,
            Self::Endpoint(_) => abi::obj::ENDPOINT,
            Self::Console => abi::obj::CONSOLE,
        }
    }
}

/// Where (and how) a frame capability mapped its frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub vspace: VSpaceId,
    pub vaddr: u64,
    pub writable: bool,
    pub executable: bool,
}

/// Who pays for an object, so the budget is refunded when it is destroyed.
pub type Charge = Option<(UntypedId, u64)>;

#[derive(Debug)]
pub struct Untyped {
    /// Size of the budget; `remaining` plus all outstanding charges always equals it.
    pub total: u64,
    pub remaining: u64,
    pub refs: u32,
}

#[derive(Debug)]
pub struct Frame {
    pub phys: u64,
    pub refs: u32,
    pub charge: Charge,
    /// Live writable / executable mappings of this frame, in any address space.
    /// W^X is enforced per *frame*: a frame is never writable through one
    /// mapping while executable through another (no W+X via aliasing).
    pub writable_maps: u32,
    pub exec_maps: u32,
}

#[derive(Debug, Default)]
pub struct Endpoint {
    pub senders: VecDeque<ThreadId>,
    pub receivers: VecDeque<ThreadId>,
    pub refs: u32,
    pub charge: Charge,
}

/// An address space plus the frames the kernel loaded into it (program image and
/// stack), which are freed together with it.
#[derive(Debug)]
pub struct VSpace {
    pub space: AddressSpace,
    pub owned_frames: Vec<u64>,
    /// Capabilities + threads referring to this address space.
    pub refs: u32,
}

impl Drop for VSpace {
    fn drop(&mut self) {
        for &phys in &self.owned_frames {
            crate::mm::frame::free(phys);
        }
        // `space` is dropped afterwards and frees the page tables.
    }
}

/// A message waiting to be delivered.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outgoing {
    pub badge: u64,
    pub words: [u64; 4],
    pub cap_slot: Option<u64>,
    pub call: bool,
    pub fault: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    /// Created but never started.
    Inactive,
    /// Runnable (or running).
    Ready,
    /// Waiting for a receiver on an endpoint.
    BlockedSend(EndpointId),
    /// Waiting for a sender on an endpoint.
    BlockedRecv(EndpointId),
    /// Waiting for the reply to a call.
    BlockedReply,
}

#[derive(Debug)]
pub struct Thread {
    pub name: String,
    pub ctx: TrapFrame,
    pub state: ThreadState,
    pub cspace: CSpaceId,
    pub vspace: VSpaceId,
    pub fault_ep: Option<(EndpointId, u64)>,
    /// One-shot reply capability: the caller this thread must reply to.
    pub reply_to: Option<ThreadId>,
    pub outgoing: Outgoing,
    pub recv_slot: Option<u64>,
}
