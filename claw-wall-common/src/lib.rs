#![no_std]

// ============================================================================
// OpenClawDefender - Shared Common Crate (v2)
// ============================================================================
//
// CRITICAL CONSTRAINTS:
// - #![no_std]: No standard library usage allowed (eBPF kernel compatibility)
// - #[repr(C)]: All structs/enums use C memory layout for deterministic
//   alignment across the eBPF VM and host architecture
// - Fixed-size only: No String, Vec, or any heap-allocated types
// ============================================================================

/// Maximum length for process command name (matches Linux TASK_COMM_LEN)
pub const TASK_COMM_LEN: usize = 16;

/// Maximum length for file path
pub const MAX_PATH_LEN: usize = 256;

/// Maximum length for current working directory
pub const MAX_CWD_LEN: usize = 256;

/// Maximum length for DNS domain name
pub const MAX_DOMAIN_LEN: usize = 253;

/// Discriminant tags for FirewallEvent variants
pub const EVENT_PROCESS: u32 = 1;
pub const EVENT_NETWORK: u32 = 2;
pub const EVENT_DNS: u32 = 3;

/// Event tags for audit mode (WOULD_BLOCK = blocked in enforce mode, allowed in audit mode)
pub const EVENT_WOULD_BLOCK_PROCESS: u32 = 4;
pub const EVENT_WOULD_BLOCK_NETWORK: u32 = 5;

// ============================================================================
// FNV-1a 64-bit Hashing Algorithm (#![no_std] safe)
// ============================================================================

/// FNV-1a offset basis for 64-bit
pub const FNV1A_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
/// FNV-1a prime for 64-bit
pub const FNV1A_PRIME: u64 = 0x00000100000001B3;

/// Compute FNV-1a 64-bit hash over a fixed-size byte array.
///
/// This function is designed for both eBPF (kernel) and user-space usage.
/// It uses a bounded loop over the slice length, which the eBPF verifier
/// can prove will terminate.
///
/// For eBPF usage, callers must ensure `data` is a fixed-size array
/// (not a dynamically-sized slice) so the verifier sees a constant bound.
#[inline(always)]
pub const fn fnv1a_hash_fixed<const N: usize>(data: &[u8; N]) -> u64 {
    let mut hash: u64 = FNV1A_OFFSET_BASIS;
    let mut i = 0usize;
    while i < N {
        // Stop at null terminator for string-like data
        if data[i] == 0 {
            break;
        }
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(FNV1A_PRIME);
        i += 1;
    }
    hash
}

/// Compute FNV-1a hash over a byte slice (user-space only, not eBPF safe).
/// The eBPF verifier cannot verify dynamically-sized slices.
#[inline]
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = FNV1A_OFFSET_BASIS;
    for &byte in data {
        if byte == 0 {
            break;
        }
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

// ============================================================================
// Process Telemetry (sys_enter_execve)
// ============================================================================

/// Telemetry payload for intercepted process execution attempts.
///
/// Memory layout (with #[repr(C)]):
///   offset  0:   pid        (4 bytes)
///   offset  4:   uid        (4 bytes)
///   offset  8:   comm       (16 bytes)
///   offset  24:  path       (256 bytes)
///   offset  280: cwd        (256 bytes)
///   Total: 536 bytes
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
    /// Current working directory, null-padded fixed-size array
    pub cwd: [u8; MAX_CWD_LEN],
}

// ============================================================================
// Network Telemetry (tcp_v4_connect)
// ============================================================================

/// Telemetry payload for intercepted IPv4 network connection attempts.
///
/// Memory layout (with #[repr(C)]):
///   offset  0: pid        (4 bytes)
///   offset  4: src_ip     (4 bytes)
///   offset  8: dst_ip     (4 bytes)
///   offset 12: dst_port   (2 bytes)
///   offset 14: _pad       (2 bytes)
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
// DNS Telemetry (udp_sendmsg port 53)
// ============================================================================

/// Telemetry payload for intercepted DNS query attempts.
///
/// Memory layout (with #[repr(C)]):
///   offset  0:   pid        (4 bytes)
///   offset  4:   dst_ip     (4 bytes)
///   offset  8:   dst_port   (2 bytes)
///   offset  10:  _pad       (2 bytes)
///   offset  12:  domain_len (4 bytes)
///   offset  16:  domain     (253 bytes)
///   offset  269: _pad2      (3 bytes, alignment to 4)
///   Total: 272 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    /// Process ID making the DNS query
    pub pid: u32,
    /// Destination DNS server IP
    pub dst_ip: u32,
    /// Destination port (should be 53)
    pub dst_port: u16,
    /// Padding
    pub _pad: u16,
    /// Length of the domain name extracted
    pub domain_len: u32,
    /// Domain name from DNS query, null-padded
    pub domain: [u8; MAX_DOMAIN_LEN],
    /// Alignment padding
    pub _pad2: [u8; 3],
}

// ============================================================================
// Unified Event Envelope
// ============================================================================

/// Unified telemetry event pushed to the eBPF Ring Buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FirewallEvent {
    /// Event type tag: EVENT_PROCESS (1), EVENT_NETWORK (2), EVENT_DNS (3)
    pub event_type: u32,
    /// Padding for 8-byte alignment of the payload union
    pub _pad: u32,
    /// Event payload (interpreted based on event_type)
    pub payload: EventPayload,
}

/// Union-like payload container. Sized to the largest variant.
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub process: ProcessEvent,
    pub network: NetworkEvent,
    pub dns: DnsEvent,
}

// ============================================================================
// Blocklist Key Types (FNV-1a u64 hash - fixes collision vulnerability)
// ============================================================================

/// Key for the blocklist HashMap.
/// Uses a u64 FNV-1a hash instead of truncated 32-byte array to prevent
/// collisions between paths/IPs sharing the same prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlocklistKey {
    /// FNV-1a 64-bit hash of the blocked entity (path or IP string)
    pub hash: u64,
}

/// Value for the blocklist HashMap (simple presence marker).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlocklistValue {
    /// Non-zero means blocked
    pub blocked: u32,
    /// Padding for alignment
    pub _pad: u32,
}

// ============================================================================
// Global Configuration (eBPF Array Map)
// ============================================================================

/// Global configuration passed from user-space to kernel via eBPF Array map.
///
/// Memory layout (with #[repr(C)]):
///   offset 0: audit_mode (4 bytes)
///   Total: 4 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GlobalConfig {
    /// 0 = enforce mode (blocks are real), 1 = audit mode (log-only, no blocks)
    pub audit_mode: u32,
}

impl GlobalConfig {
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self { audit_mode: 0 }
    }
}

// ============================================================================
// Safe construction helpers
// ============================================================================

impl ProcessEvent {
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; TASK_COMM_LEN],
            path: [0u8; MAX_PATH_LEN],
            cwd: [0u8; MAX_CWD_LEN],
        }
    }
}

impl NetworkEvent {
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

impl DnsEvent {
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            dst_ip: 0,
            dst_port: 0,
            _pad: 0,
            domain_len: 0,
            domain: [0u8; MAX_DOMAIN_LEN],
            _pad2: [0u8; 3],
        }
    }
}

impl BlocklistKey {
    /// Create a BlocklistKey from a FNV-1a hash value
    #[inline(always)]
    pub const fn from_hash(hash: u64) -> Self {
        Self { hash }
    }
}

impl FirewallEvent {
    #[inline(always)]
    pub const fn new_process(event: ProcessEvent) -> Self {
        Self {
            event_type: EVENT_PROCESS,
            _pad: 0,
            payload: EventPayload { process: event },
        }
    }

    #[inline(always)]
    pub const fn new_network(event: NetworkEvent) -> Self {
        Self {
            event_type: EVENT_NETWORK,
            _pad: 0,
            payload: EventPayload { network: event },
        }
    }

    #[inline(always)]
    pub const fn new_dns(event: DnsEvent) -> Self {
        Self {
            event_type: EVENT_DNS,
            _pad: 0,
            payload: EventPayload { dns: event },
        }
    }
}

// Safety: These types are plain-old-data with fixed layout, safe to share
// across threads and send between kernel/user space.
unsafe impl Sync for FirewallEvent {}
unsafe impl Send for FirewallEvent {}
unsafe impl Sync for EventPayload {}
unsafe impl Send for EventPayload {}
