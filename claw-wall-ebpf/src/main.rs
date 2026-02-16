#![no_std]
#![no_main]

// ============================================================================
// OpenClawDefender - eBPF Kernel-Space Sensor ("Hot Path")
// ============================================================================
//
// This program hooks into:
//   1. sys_enter_execve (tracepoint) - intercepts process creation
//   2. tcp_v4_connect (kprobe) - intercepts IPv4 network connections
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
    maps::{HashMap, RingBuf},
    programs::{TracePointContext, ProbeContext},
    EbpfContext,
};
use claw_wall_common::{
    BlocklistKey, BlocklistValue, FirewallEvent, NetworkEvent, ProcessEvent,
    EVENT_NETWORK, EVENT_PROCESS, EventPayload, TASK_COMM_LEN, MAX_PATH_LEN,
};

// ============================================================================
// eBPF Maps
// ============================================================================

/// Blocklist HashMap: stores hashes of blocked file paths or IP addresses.
/// Key: BlocklistKey (32 bytes), Value: BlocklistValue (4 bytes)
/// Max 1024 entries for the fast-path lookup.
#[map]
static BLOCKLIST: HashMap<BlocklistKey, BlocklistValue> =
    HashMap::with_max_entries(1024, 0);

/// Telemetry Ring Buffer: events are pushed here for user-space consumption.
/// 256 KB ring buffer for high-throughput event streaming.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ============================================================================
// Tracepoint: sys_enter_execve - Process Execution Interception
// ============================================================================

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

    // --- Blocklist Check ---
    // Build a simple blocklist key from the first 32 bytes of the path
    let mut key = BlocklistKey { key: [0u8; 32] };
    let copy_len = if event.path.len() < 32 { event.path.len() } else { 32 };
    let mut i = 0u32;
    // Bounded loop: verifier can prove termination (max 32 iterations)
    while i < copy_len as u32 {
        key.key[i as usize] = event.path[i as usize];
        i += 1;
    }

    // Check if this path is in the blocklist
    if let Some(val) = unsafe { BLOCKLIST.get(&key) } {
        if val.blocked != 0 {
            // BLOCKED: Return non-zero to signal denial
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
    // Build blocklist key from destination IP (stored in first 4 bytes)
    let mut key = BlocklistKey { key: [0u8; 32] };
    let ip_bytes = dst_ip.to_ne_bytes();
    key.key[0] = ip_bytes[0];
    key.key[1] = ip_bytes[1];
    key.key[2] = ip_bytes[2];
    key.key[3] = ip_bytes[3];

    // Check if this destination IP is in the blocklist
    if let Some(val) = unsafe { BLOCKLIST.get(&key) } {
        if val.blocked != 0 {
            return Ok(1); // BLOCKED
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
// Panic handler (required for #![no_std])
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
