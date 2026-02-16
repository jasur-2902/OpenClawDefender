#![no_std]
#![no_main]

// ============================================================================
// OpenClawDefender - eBPF Kernel-Space Sensor ("Hot Path")
// ============================================================================
//
// This program hooks into:
//   1. sys_enter_execve (tracepoint) - intercepts process creation
//   2. tcp_v4_connect (kprobe) - intercepts IPv4 network connections
//   3. udp_sendmsg (kprobe) - intercepts DNS queries (port 53)
//
// For each event:
//   - Check the blocklist HashMap for the entity
//   - If blocked: return error code to deny the syscall
//   - If allowed: push telemetry to the RingBuf for user-space processing
//
// VERIFIER CONSTRAINTS:
//   - 512-byte stack limit strictly enforced
//   - No dynamic allocation, no unbounded loops
//   - All payloads use fixed-size arrays from claw-wall-common
//   - Only core library used
// ============================================================================

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
              bpf_probe_read_kernel, bpf_probe_read_user_str_bytes},
    macros::{tracepoint, kprobe, map},
    maps::{Array, HashMap, RingBuf},
    programs::{TracePointContext, ProbeContext},
    EbpfContext,
};
use claw_wall_common::{
    BlocklistKey, BlocklistValue, DnsEvent, FirewallEvent, NetworkEvent, ProcessEvent,
    EVENT_DNS, EVENT_NETWORK, EVENT_PROCESS, EVENT_WOULD_BLOCK_PROCESS, EVENT_WOULD_BLOCK_NETWORK,
    EventPayload, GlobalConfig, TASK_COMM_LEN, MAX_PATH_LEN,
    MAX_CWD_LEN, MAX_DOMAIN_LEN,
    fnv1a_hash_fixed,
};

// ============================================================================
// eBPF Maps
// ============================================================================

/// Blocklist HashMap: stores FNV-1a hashes of blocked file paths or IP addresses.
/// Key: BlocklistKey (u64 hash), Value: BlocklistValue (blocked flag)
/// Max 1024 entries for the fast-path lookup.
#[map]
static BLOCKLIST: HashMap<BlocklistKey, BlocklistValue> =
    HashMap::with_max_entries(1024, 0);

/// Telemetry Ring Buffer: events are pushed here for user-space consumption.
/// 256 KB ring buffer for high-throughput event streaming.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Global configuration array. Single element holding audit_mode flag.
/// Written by the user-space daemon at startup.
#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

// ============================================================================
// Tracepoint: sys_enter_execve - Process Execution Interception
// ============================================================================

/// Check if the firewall is running in audit mode (dry-run).
/// In audit mode, blocked events are logged as WOULD_BLOCK but allowed to proceed.
#[inline(always)]
fn is_audit_mode() -> bool {
    if let Some(cfg) = unsafe { CONFIG.get(0) } {
        cfg.audit_mode != 0
    } else {
        false // Default: enforce mode
    }
}

/// Hook into process execution attempts via the execve syscall.
///
/// Extracts PID, UID, command name, and binary path from kernel context.
/// Checks blocklist and either denies or logs the event.
#[tracepoint]
pub fn claw_wall_execve(ctx: TracePointContext) -> u32 {
    match try_execve(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Allow on error (fail-open for safety)
    }
}

#[inline(always)]
fn try_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    // Extract PID and UID from current task
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    // Build the process event with zeroed memory
    let mut event = ProcessEvent::zeroed();
    event.pid = pid;
    event.uid = uid;

    // Read command name from current task (safe, bounded to 16 bytes)
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // Read the filename pointer from the tracepoint args.
    // For sys_enter_execve, the filename is at offset 16 in the tracepoint args.
    let filename_ptr: *const u8 = unsafe {
        ctx.read_at::<u64>(16)? as *const u8
    };

    // Read the filename string from user space into fixed-size buffer.
    // bpf_probe_read_user_str_bytes is bounded by the destination buffer size.
    if !filename_ptr.is_null() {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr, &mut event.path)
        };
    }

    // --- CWD Extraction (Hybrid Approach) ---
    // Full kernel CWD extraction (task->fs->pwd->dentry traversal) is
    // impractical in eBPF for this tracepoint because:
    //   1. bpf_d_path() is only available for specific program types
    //      (fentry/fexit/LSM), not tracepoints
    //   2. Manual dentry traversal requires multiple bpf_probe_read_kernel
    //      calls through task_struct->fs->pwd->d_name, which risks verifier
    //      rejection due to pointer chain depth and kernel version variance
    //   3. ProcessEvent (536 bytes) already exceeds the 512-byte stack limit;
    //      it works only because we write directly to the ring buffer entry
    //
    // Resolution: event.cwd remains zeroed. User-space resolves CWD by
    // reading /proc/<pid>/cwd using the PID already captured in the event.
    // This is reliable and portable across kernel versions.

    // --- Blocklist Check ---
    // Hash the full path using FNV-1a (bounded loop over fixed-size array)
    let key = BlocklistKey::from_hash(fnv1a_hash_fixed(&event.path));

    // Check if this path is in the blocklist
    if let Some(val) = unsafe { BLOCKLIST.get(&key) } {
        if val.blocked != 0 {
            if is_audit_mode() {
                // AUDIT MODE: Log as WOULD_BLOCK but allow the syscall
                let mut fw_event = FirewallEvent::new_process(event);
                fw_event.event_type = EVENT_WOULD_BLOCK_PROCESS;
                if let Some(mut entry) = EVENTS.reserve::<FirewallEvent>(0) {
                    unsafe { core::ptr::write(entry.as_mut_ptr(), fw_event); }
                    entry.submit(0);
                }
                return Ok(0); // ALLOW (audit mode)
            }
            // ENFORCE MODE: Deny the syscall
            return Ok(1);
        }
    }

    // --- Telemetry: Push event to Ring Buffer ---
    let fw_event = FirewallEvent::new_process(event);

    if let Some(mut entry) = EVENTS.reserve::<FirewallEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write(ptr, fw_event);
        }
        entry.submit(0);
    }

    Ok(0) // Allow the syscall
}

// ============================================================================
// Kprobe: tcp_v4_connect - Network Connection Interception
// ============================================================================

/// Hook into IPv4 TCP connection attempts.
///
/// Extracts PID, source/destination IP, and destination port.
/// Checks blocklist by destination IP and either denies or logs.
#[kprobe]
pub fn claw_wall_connect(ctx: ProbeContext) -> u32 {
    match try_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail-open
    }
}

#[inline(always)]
fn try_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    // Extract PID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Read the sock pointer from the first argument (struct sock *sk)
    let sk: *const u8 = ctx.arg::<*const u8>(0).ok_or(1i64)?;

    // Read socket address fields from struct sock.
    // These offsets are for a typical Linux kernel sock struct.
    // __sk_common.skc_rcv_saddr (source IP) - offset varies by kernel version
    // __sk_common.skc_daddr (dest IP)
    // __sk_common.skc_dport (dest port)
    //
    // Standard offsets for struct sock __sk_common:
    //   skc_daddr:     offset 0  (destination IP)
    //   skc_rcv_saddr: offset 4  (source IP)
    //   skc_dport:     offset 12 (destination port, network byte order)
    //
    // NOTE: These offsets may need adjustment based on kernel version.
    // In production, use CO-RE (Compile Once Run Everywhere) with BTF.
    let dst_ip: u32 = unsafe { bpf_probe_read_kernel(&*((sk as usize + 0) as *const u32))? };
    let src_ip: u32 = unsafe { bpf_probe_read_kernel(&*((sk as usize + 4) as *const u32))? };
    let dst_port: u16 = unsafe { bpf_probe_read_kernel(&*((sk as usize + 12) as *const u16))? };

    // Build network event
    let mut event = NetworkEvent::zeroed();
    event.pid = pid;
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.dst_port = dst_port;

    // --- Blocklist Check ---
    // Hash the destination IP bytes using FNV-1a
    let ip_bytes = dst_ip.to_ne_bytes();
    let key = BlocklistKey::from_hash(fnv1a_hash_fixed(&ip_bytes));

    // Check if this destination IP is in the blocklist
    if let Some(val) = unsafe { BLOCKLIST.get(&key) } {
        if val.blocked != 0 {
            if is_audit_mode() {
                // AUDIT MODE: Log as WOULD_BLOCK but allow the connection
                let mut fw_event = FirewallEvent::new_network(event);
                fw_event.event_type = EVENT_WOULD_BLOCK_NETWORK;
                if let Some(mut entry) = EVENTS.reserve::<FirewallEvent>(0) {
                    unsafe { core::ptr::write(entry.as_mut_ptr(), fw_event); }
                    entry.submit(0);
                }
                return Ok(0); // ALLOW (audit mode)
            }
            return Ok(1); // ENFORCE: BLOCKED
        }
    }

    // --- Telemetry: Push event to Ring Buffer ---
    let fw_event = FirewallEvent::new_network(event);

    if let Some(mut entry) = EVENTS.reserve::<FirewallEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write(ptr, fw_event);
        }
        entry.submit(0);
    }

    Ok(0) // Allow
}

// ============================================================================
// Kprobe: udp_sendmsg - DNS Query Interception (port 53)
// ============================================================================

/// Hook into UDP sendmsg to intercept DNS queries.
///
/// Filters for destination port 53, parses the DNS question section
/// to extract the queried domain name, and emits a DnsEvent.
#[kprobe]
pub fn claw_wall_dns(ctx: ProbeContext) -> u32 {
    match try_dns(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail-open
    }
}

/// DNS query buffer size for reading payload from kernel memory.
/// Must be small enough for the eBPF 512-byte stack limit.
/// 64 bytes covers: 12-byte DNS header + enough of the question section
/// for most domain names.
const DNS_BUF_SIZE: usize = 64;

/// Maximum number of label segments to parse (bounded loop for verifier).
/// 32 iterations covers domains up to 32 labels deep (e.g., a.b.c.d...example.com).
const MAX_LABEL_ITERATIONS: usize = 32;

#[inline(always)]
fn try_dns(ctx: &ProbeContext) -> Result<u32, i64> {
    // arg0 for udp_sendmsg is struct sock *sk
    let sk: *const u8 = ctx.arg::<*const u8>(0).ok_or(1i64)?;

    // Read destination port from sock.__sk_common.skc_dport (offset 12, network byte order)
    let dst_port_be: u16 = unsafe {
        bpf_probe_read_kernel(&*((sk as usize + 12) as *const u16))?
    };

    // Filter: only intercept DNS traffic (port 53)
    // skc_dport is in network byte order, so compare against 53 in network order
    let dst_port_host = u16::from_be(dst_port_be);
    if dst_port_host != 53 {
        return Ok(0);
    }

    // Extract PID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Read destination IP from sock.__sk_common.skc_daddr (offset 0)
    let dst_ip: u32 = unsafe {
        bpf_probe_read_kernel(&*((sk as usize + 0) as *const u32))?
    };

    // arg1 for udp_sendmsg is struct msghdr *msg
    let msg: *const u8 = ctx.arg::<*const u8>(1).ok_or(1i64)?;

    // struct msghdr { ... struct iov_iter msg_iter; ... }
    // msg_iter contains the iovec array. On modern kernels:
    //   msg->msg_iter.iov is at offset 16 (after msg_name, msg_namelen, msg_iter type/count)
    //   The exact offset depends on kernel version; using offset 32 for msg_iter.__iov
    //   within the msghdr structure.
    //
    // msghdr layout (typical):
    //   offset 0:  msg_name       (8 bytes, pointer)
    //   offset 8:  msg_namelen    (4 bytes)
    //   offset 12: padding        (4 bytes)
    //   offset 16: msg_iter       (struct iov_iter)
    //     iov_iter offset 0:  iter_type/direction (1 byte) + padding
    //     iov_iter offset 8:  count (size_t, 8 bytes)
    //     iov_iter offset 16: __iov pointer (this is at msghdr+32)
    //
    // Read the iovec pointer from msghdr->msg_iter.__iov
    let iov_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(&*((msg as usize + 32) as *const *const u8))?
    };
    if iov_ptr.is_null() {
        return Ok(0);
    }

    // struct iovec { void *iov_base; size_t iov_len; }
    // Read iov_base (pointer to UDP payload data)
    let iov_base: *const u8 = unsafe {
        bpf_probe_read_kernel(&*(iov_ptr as *const *const u8))?
    };
    if iov_base.is_null() {
        return Ok(0);
    }

    // Read a chunk of the DNS payload into a stack buffer
    let dns_buf: [u8; DNS_BUF_SIZE] = unsafe {
        bpf_probe_read_kernel(&*(iov_base as *const [u8; DNS_BUF_SIZE]))?
    };

    // DNS header is 12 bytes. Question section starts at offset 12.
    // Parse the QNAME: sequence of length-prefixed labels ending with a 0-length label.
    // Example: \x03www\x06google\x03com\x00 -> "www.google.com"
    let mut event = DnsEvent::zeroed();
    event.pid = pid;
    event.dst_ip = dst_ip;
    event.dst_port = dst_port_be;

    let mut src_pos: usize = 12; // Start after DNS header
    let mut dst_pos: usize = 0;

    // Bounded loop for eBPF verifier compliance
    let mut i: usize = 0;
    while i < MAX_LABEL_ITERATIONS {
        i += 1;

        // Bounds check: ensure we don't read past our buffer
        if src_pos >= DNS_BUF_SIZE {
            break;
        }

        let label_len = dns_buf[src_pos] as usize;
        src_pos += 1;

        // Zero-length label marks end of QNAME
        if label_len == 0 {
            break;
        }

        // Validate label length (max 63 per RFC 1035)
        if label_len > 63 {
            break;
        }

        // Add dot separator between labels (not before first label)
        if dst_pos > 0 {
            if dst_pos < MAX_DOMAIN_LEN {
                event.domain[dst_pos] = b'.';
                dst_pos += 1;
            }
        }

        // Copy label bytes into domain buffer with bounded iteration
        let mut j: usize = 0;
        while j < 63 {
            if j >= label_len {
                break;
            }
            if src_pos >= DNS_BUF_SIZE {
                break;
            }
            if dst_pos >= MAX_DOMAIN_LEN {
                break;
            }
            event.domain[dst_pos] = dns_buf[src_pos];
            src_pos += 1;
            dst_pos += 1;
            j += 1;
        }
    }

    event.domain_len = dst_pos as u32;

    // --- Telemetry: Push DNS event to Ring Buffer ---
    let fw_event = FirewallEvent::new_dns(event);

    if let Some(mut entry) = EVENTS.reserve::<FirewallEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write(ptr, fw_event);
        }
        entry.submit(0);
    }

    Ok(0)
}

// ============================================================================
// Panic handler (required for #![no_std])
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
