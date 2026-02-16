#![no_std]

// ============================================================================
// OpenClawDefender - Shared Common Crate
// ============================================================================
//
// This crate defines the exact telemetry payloads passed between the
// kernel-space eBPF program and the user-space daemon via an eBPF Ring Buffer.
//
// CRITICAL CONSTRAINTS:
// - #![no_std]: No standard library usage allowed (eBPF kernel compatibility)
// - #[repr(C)]: All structs/enums use C memory layout for deterministic
//   alignment across the eBPF VM and host architecture
// - Fixed-size only: No String, Vec, or any heap-allocated types
// - All text fields use fixed-size byte arrays
// ============================================================================

/// Maximum length for process command name (matches Linux TASK_COMM_LEN)
pub const TASK_COMM_LEN: usize = 16;

/// Maximum length for file path
pub const MAX_PATH_LEN: usize = 256;

/// Discriminant tag for FirewallEvent variants
pub const EVENT_PROCESS: u32 = 1;
pub const EVENT_NETWORK: u32 = 2;

// ============================================================================
// Process Telemetry (sys_enter_execve)
// ============================================================================

/// Telemetry payload for intercepted process execution attempts.
///
/// Captured at the `sys_enter_execve` tracepoint. All fields use fixed-size
/// representations to satisfy eBPF stack and memory constraints.
///
/// Memory layout (with #[repr(C)]):
///   offset  0: pid        (4 bytes)
///   offset  4: uid        (4 bytes)
///   offset  8: comm       (16 bytes)
///   offset 24: path       (256 bytes)
///   Total: 280 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    /// Process ID of the execution attempt
    pub pid: u32,
    /// User ID of the process owner
    pub uid: u32,
    /// Command name (task comm), null-padded fixed-size array
    pub comm: [u8; TASK_COMM_LEN],
    /// Binary path of the executed file, null-padded fixed-size array
    pub path: [u8; MAX_PATH_LEN],
}

// ============================================================================
// Network Telemetry (tcp_v4_connect)
// ============================================================================

/// Telemetry payload for intercepted IPv4 network connection attempts.
///
/// Captured at the `tcp_v4_connect` kprobe. IP addresses are stored as raw
/// u32 in network byte order. No std::net types are used.
///
/// Memory layout (with #[repr(C)]):
///   offset  0: pid        (4 bytes)
///   offset  4: src_ip     (4 bytes)
///   offset  8: dst_ip     (4 bytes)
///   offset 12: dst_port   (2 bytes)
///   offset 14: _pad       (2 bytes, compiler-inserted for alignment)
///   Total: 16 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    /// Process ID of the connecting process
    pub pid: u32,
    /// Source IPv4 address as raw u32 (network byte order)
    pub src_ip: u32,
    /// Destination IPv4 address as raw u32 (network byte order)
    pub dst_ip: u32,
    /// Destination port number (network byte order)
    pub dst_port: u16,
    /// Explicit padding for deterministic C layout alignment
    pub _pad: u16,
}

// ============================================================================
// Unified Event Envelope
// ============================================================================

/// Unified telemetry event pushed to the eBPF Ring Buffer.
///
/// Uses a tagged-union approach with explicit discriminant to ensure
/// deterministic parsing across kernel/user-space boundary.
///
/// We use a manual tag + union-like struct approach rather than a Rust enum
/// because Rust enum discriminants don't have guaranteed layout even with
/// #[repr(C)]. Instead, we use a flat struct with a tag field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FirewallEvent {
    /// Event type tag: EVENT_PROCESS (1) or EVENT_NETWORK (2)
    pub event_type: u32,
    /// Padding for 8-byte alignment of the payload union
    pub _pad: u32,
    /// Event payload (interpreted based on event_type)
    pub payload: EventPayload,
}

/// Union-like payload container. Both variants are #[repr(C)] and the
/// entire union is sized to the largest variant (ProcessEvent = 280 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub process: ProcessEvent,
    pub network: NetworkEvent,
}

// ============================================================================
// Blocklist Key Types
// ============================================================================

/// Key for the process blocklist HashMap.
/// Stores a hash of the binary path for O(1) lookup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlocklistKey {
    /// Hash or raw bytes identifying the blocked entity
    pub key: [u8; 32],
}

/// Value for the blocklist HashMap (simple presence marker).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlocklistValue {
    /// Non-zero means blocked
    pub blocked: u32,
}

// ============================================================================
// Safe construction helpers
// ============================================================================

impl ProcessEvent {
    /// Create a zeroed ProcessEvent (safe for eBPF stack allocation)
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; TASK_COMM_LEN],
            path: [0u8; MAX_PATH_LEN],
        }
    }
}

impl NetworkEvent {
    /// Create a zeroed NetworkEvent
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            src_ip: 0,
            dst_ip: 0,
            dst_port: 0,
            _pad: 0,
        }
    }
}

impl FirewallEvent {
    /// Create a zeroed FirewallEvent tagged as a process event
    #[inline(always)]
    pub const fn new_process(event: ProcessEvent) -> Self {
        Self {
            event_type: EVENT_PROCESS,
            _pad: 0,
            payload: EventPayload { process: event },
        }
    }

    /// Create a zeroed FirewallEvent tagged as a network event
    #[inline(always)]
    pub const fn new_network(event: NetworkEvent) -> Self {
        Self {
            event_type: EVENT_NETWORK,
            _pad: 0,
            payload: EventPayload { network: event },
        }
    }
}

// Safety: These types are plain-old-data with fixed layout, safe to share
// across threads and send between kernel/user space.
unsafe impl Sync for FirewallEvent {}
unsafe impl Send for FirewallEvent {}
unsafe impl Sync for EventPayload {}
unsafe impl Send for EventPayload {}
