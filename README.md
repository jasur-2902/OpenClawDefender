<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" alt="Rust"/>
  <img src="https://img.shields.io/badge/framework-Aya-blue?style=for-the-badge" alt="Aya"/>
  <img src="https://img.shields.io/badge/platform-Linux-green?style=for-the-badge&logo=linux" alt="Linux"/>
  <img src="https://img.shields.io/badge/kernel-eBPF-red?style=for-the-badge" alt="eBPF"/>
  <img src="https://img.shields.io/badge/license-MIT-purple?style=for-the-badge" alt="MIT"/>
</p>

# OpenClawDefender

**A high-performance, kernel-level execution firewall built in Rust using eBPF and the [Aya](https://aya-rs.dev/) framework.**

OpenClawDefender intercepts process executions and network connections at the Linux kernel level — before they reach user space — using eBPF probes. It evaluates each event against an in-kernel blocklist at wire speed, silently denying malicious activity while streaming real-time telemetry to a user-space daemon for logging and analysis.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [System Architecture Diagram](#system-architecture-diagram)
- [Data Flow](#data-flow)
- [Project Structure](#project-structure)
- [Crate Breakdown](#crate-breakdown)
  - [claw-wall-common](#claw-wall-common--shared-data-structures)
  - [claw-wall-ebpf](#claw-wall-ebpf--kernel-space-sensor)
  - [claw-wall-daemon](#claw-wall-daemon--user-space-daemon)
  - [xtask](#xtask--build-tooling)
- [Memory Layout & Alignment](#memory-layout--alignment)
- [eBPF Maps](#ebpf-maps)
- [Hook Points](#hook-points)
- [Decision Engine Flow](#decision-engine-flow)
- [Configuration](#configuration)
- [Deployment & Installation](#deployment--installation)
- [Systemd Integration](#systemd-integration)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [CLI Reference](#cli-reference)
- [License](#license)

---

## Architecture Overview

OpenClawDefender operates across two execution environments with a shared memory contract:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER SPACE                                   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   claw-wall-daemon                           │   │
│  │                                                              │   │
│  │  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐  │   │
│  │  │  clap    │  │  Aya Loader  │  │  Event Loop (tokio)   │  │   │
│  │  │  CLI     │  │  & Attacher  │  │  RingBuf consumer     │  │   │
│  │  └──────────┘  └──────┬───────┘  └───────────┬───────────┘  │   │
│  │                       │                       │              │   │
│  │              Load bytecode            Read events            │   │
│  │              Populate maps           Parse & log             │   │
│  └───────────────────────┼───────────────────────┼──────────────┘   │
│                          │                       │                   │
├──────────────────────────┼───────────────────────┼───────────────────┤
│                     KERNEL BOUNDARY                                  │
├──────────────────────────┼───────────────────────┼───────────────────┤
│                          │                       │                   │
│                    KERNEL SPACE                                      │
│                                                                     │
│  ┌───────────────────────┼───────────────────────┼──────────────┐   │
│  │                  claw-wall-ebpf                               │   │
│  │                       │                       ▲               │   │
│  │  ┌────────────────────▼────────────────────┐  │               │   │
│  │  │          eBPF Maps (shared memory)      │  │               │   │
│  │  │  ┌──────────────┐  ┌─────────────────┐  │  │               │   │
│  │  │  │  BLOCKLIST   │  │     EVENTS      │  │  │               │   │
│  │  │  │  (HashMap)   │  │   (RingBuf)     │──┼──┘               │   │
│  │  │  └──────┬───────┘  └────────▲────────┘  │                  │   │
│  │  └─────────┼───────────────────┼───────────┘                  │   │
│  │            │                   │                               │   │
│  │  ┌─────────▼───────────────────┼───────────────────────────┐  │   │
│  │  │              Hook Entry Points                          │  │   │
│  │  │                                                         │  │   │
│  │  │  ┌─────────────────────┐  ┌──────────────────────────┐  │  │   │
│  │  │  │  claw_wall_execve   │  │   claw_wall_connect      │  │  │   │
│  │  │  │  (tracepoint)       │  │   (kprobe)               │  │  │   │
│  │  │  │                     │  │                          │  │  │   │
│  │  │  │  sys_enter_execve   │  │   tcp_v4_connect         │  │  │   │
│  │  │  └─────────────────────┘  └──────────────────────────┘  │  │   │
│  │  └─────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Linux Kernel Syscall Table                                  │   │
│  │  execve()                         tcp_v4_connect()           │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## System Architecture Diagram

```
                    ┌──────────────────────────┐
                    │     System Admin / User   │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │     claw-wall CLI         │
                    │                          │
                    │  --configure   (API key)  │
                    │  --install-service        │
                    │  run           (daemon)   │
                    └────────────┬─────────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
        ┌────────▼──────┐ ┌─────▼──────┐ ┌──────▼───────┐
        │  Config TOML  │ │  systemd   │ │  Aya eBPF    │
        │  /etc/claw-   │ │  service   │ │  Loader      │
        │  wall/config  │ │  manager   │ │              │
        │  .toml        │ │            │ │  Load .o     │
        │  (chmod 600)  │ │  auto-     │ │  Attach      │
        │               │ │  restart   │ │  probes      │
        └───────────────┘ └────────────┘ └──────┬───────┘
                                                │
                          ┌─────────────────────┼──────────────┐
                          │   eBPF Virtual Machine (kernel)    │
                          │                                    │
                          │   ┌─────────┐    ┌─────────────┐   │
                          │   │BLOCKLIST│    │   EVENTS     │   │
                          │   │HashMap  │    │  RingBuf     │   │
                          │   │1024 max │    │  256 KB      │   │
                          │   └────┬────┘    └──────┬───────┘   │
                          │        │                │           │
                          │   ┌────▼────────────────▼───────┐   │
                          │   │      Decision Engine        │   │
                          │   │                             │   │
                          │   │  1. Extract event context   │   │
                          │   │  2. Lookup in BLOCKLIST     │   │
                          │   │  3a. MATCH → deny syscall   │   │
                          │   │  3b. NO MATCH → allow +     │   │
                          │   │      push to EVENTS         │   │
                          │   └─────────────────────────────┘   │
                          │                                    │
                          └────────────────────────────────────┘
```

---

## Data Flow

This diagram shows the exact path of a single intercepted event from syscall to log output:

```
 Process calls execve("/usr/bin/malware")
         │
         ▼
 ┌───────────────────────────────────────────┐
 │  Linux Kernel: sys_enter_execve           │
 │  Tracepoint fires → claw_wall_execve()    │
 └───────────────────┬───────────────────────┘
                     │
                     ▼
 ┌───────────────────────────────────────────┐
 │  Extract Context (eBPF helpers)           │
 │                                           │
 │  bpf_get_current_pid_tgid() → pid        │
 │  bpf_get_current_uid_gid()  → uid        │
 │  bpf_get_current_comm()     → comm[16]   │
 │  bpf_probe_read_user_str()  → path[256]  │
 └───────────────────┬───────────────────────┘
                     │
                     ▼
 ┌───────────────────────────────────────────┐
 │  Build BlocklistKey from path[0..32]      │
 │  Lookup in BLOCKLIST HashMap              │
 └──────┬────────────────────────┬───────────┘
        │                        │
   Found (blocked=1)        Not Found
        │                        │
        ▼                        ▼
 ┌──────────────┐    ┌───────────────────────┐
 │  DENY        │    │  ALLOW                │
 │  Return 1    │    │  Build FirewallEvent   │
 │  Syscall     │    │  Reserve RingBuf slot  │
 │  blocked     │    │  Write event           │
 │  silently    │    │  Submit to EVENTS      │
 └──────────────┘    │  Return 0              │
                     └───────────┬───────────┘
                                 │
                                 ▼
                  ┌──────────────────────────┐
                  │  User-Space Daemon       │
                  │  event_loop() reads      │
                  │  RingBuf via aya         │
                  │                          │
                  │  Parses FirewallEvent:   │
                  │  event_type=1 → Process  │
                  │  event_type=2 → Network  │
                  │                          │
                  │  Logs to stdout:         │
                  │  [PROCESS] pid=1234      │
                  │  uid=0 comm="malware"    │
                  │  path="/usr/bin/malware" │
                  └──────────────────────────┘
```

---

## Project Structure

```
OpenClawDefender/
├── .cargo/
│   └── config.toml                 # Cargo alias: `cargo xtask`
├── claw-wall-common/               # Shared #![no_std] data structures
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs                  # ProcessEvent, NetworkEvent, FirewallEvent
├── claw-wall-ebpf/                 # Kernel-space eBPF program
│   ├── Cargo.toml                  # Targets bpfel-unknown-none
│   ├── rust-toolchain.toml         # Requires nightly + rust-src
│   └── src/
│       └── main.rs                 # #![no_std] #![no_main] hooks + maps
├── claw-wall-daemon/               # User-space daemon & CLI
│   ├── Cargo.toml
│   └── src/
│       └── main.rs                 # Aya loader, event loop, clap CLI
├── xtask/                          # Build orchestration
│   ├── Cargo.toml
│   └── src/
│       └── main.rs                 # Cross-compilation commands
├── Cargo.toml                      # Workspace root
├── claw-wall.service               # systemd unit file
├── install.sh                      # POSIX installer script
├── .gitignore
└── README.md
```

---

## Crate Breakdown

### `claw-wall-common` — Shared Data Structures

The shared library that both the kernel eBPF program and user-space daemon link against. This is the **memory contract** between the two environments.

**Critical constraints enforced:**

| Constraint | Reason |
|---|---|
| `#![no_std]` | eBPF programs cannot use the Rust standard library |
| `#[repr(C)]` on every struct/union | Guarantees deterministic memory layout across architectures |
| Fixed-size byte arrays only | No `String`, `Vec`, or heap allocation in kernel space |
| Explicit padding fields | Prevents compiler-inserted padding from causing alignment drift |
| Manual tagged union | Rust enum discriminants have no guaranteed layout even with `#[repr(C)]` |

**Exported types:**

| Type | Purpose | Size |
|---|---|---|
| `ProcessEvent` | Exec telemetry (pid, uid, comm, path) | 280 bytes |
| `NetworkEvent` | Connection telemetry (pid, src/dst IP, port) | 16 bytes |
| `FirewallEvent` | Tagged union envelope for RingBuf | 288 bytes |
| `EventPayload` | C union of ProcessEvent / NetworkEvent | 280 bytes |
| `BlocklistKey` | HashMap key (32-byte identifier) | 32 bytes |
| `BlocklistValue` | HashMap value (blocked flag) | 4 bytes |

### `claw-wall-ebpf` — Kernel-Space Sensor

The "hot path" — code that runs inside the Linux kernel's eBPF virtual machine on every intercepted syscall.

**eBPF verifier constraints strictly enforced:**

| Constraint | Implementation |
|---|---|
| `#![no_std]` + `#![no_main]` | No standard library, no main function |
| 512-byte stack limit | All structs fit within budget; no recursive calls |
| No dynamic allocation | All data uses stack-allocated fixed-size arrays |
| No unbounded loops | Blocklist key copy uses bounded `while i < 32` |
| Core library only | Zero dependencies beyond `core` and `aya-ebpf` |
| Fail-open on error | Errors return 0 (allow) to prevent system lockout |

**Compilation target:** `bpfel-unknown-none` (eBPF little-endian, no OS)

### `claw-wall-daemon` — User-Space Daemon

The management plane: loads eBPF bytecode into the kernel, populates policy maps, and consumes telemetry events.

**Components:**

| Component | Technology | Purpose |
|---|---|---|
| CLI | `clap` (derive) | `configure`, `run`, `--install-service` |
| eBPF Loader | `aya` | Load `.o` bytecode, attach probes |
| Event Loop | `tokio` + `select!` | Async RingBuf consumer with graceful shutdown |
| Config | `serde` + `toml` | `/etc/claw-wall/config.toml` management |
| Logging | `env_logger` + `log` | Structured event output |

### `xtask` — Build Tooling

Orchestrates cross-compilation of two different target architectures in one workspace:

```
cargo xtask build
       │
       ├── 1. Build eBPF program
       │      cargo +nightly build
       │        --target=bpfel-unknown-none
       │        -Z build-std=core
       │      (claw-wall-ebpf/)
       │
       └── 2. Build user-space daemon
              cargo build
                --package claw-wall-daemon
              (target: x86_64-unknown-linux-gnu)
```

---

## Memory Layout & Alignment

The most critical engineering challenge in cross-boundary eBPF communication is **memory alignment**. If the kernel writes a struct with one layout and user space reads it with another, the data is corrupted.

### ProcessEvent Layout (280 bytes)

```
Offset  Size    Field           Type            Notes
──────  ──────  ──────────────  ──────────────  ─────────────────────────
0       4       pid             u32             Process ID
4       4       uid             u32             User ID
8       16      comm            [u8; 16]        Task name (TASK_COMM_LEN)
24      256     path            [u8; 256]       Binary path (null-padded)
──────  ──────
Total:  280 bytes                               No internal padding needed
```

### NetworkEvent Layout (16 bytes)

```
Offset  Size    Field           Type            Notes
──────  ──────  ──────────────  ──────────────  ─────────────────────────
0       4       pid             u32             Process ID
4       4       src_ip          u32             Source IPv4 (network order)
8       4       dst_ip          u32             Dest IPv4 (network order)
12      2       dst_port        u16             Dest port (network order)
14      2       _pad            u16             EXPLICIT padding to 4-byte
──────  ──────                                  alignment boundary
Total:  16 bytes
```

### FirewallEvent Layout (288 bytes)

```
Offset  Size    Field           Type            Notes
──────  ──────  ──────────────  ──────────────  ─────────────────────────
0       4       event_type      u32             Tag: 1=Process, 2=Network
4       4       _pad            u32             Align payload to 8 bytes
8       280     payload         EventPayload    C union (largest variant)
──────  ──────
Total:  288 bytes                               Pushed atomically to RingBuf
```

**Why `#[repr(C)]` is mandatory:**

```
                    Without #[repr(C)]              With #[repr(C)]
                    (Rust default layout)           (C-compatible layout)

                    ┌─────────────────┐             ┌─────────────────┐
                    │ Fields may be   │             │ Fields laid out  │
                    │ REORDERED by    │             │ IN DECLARATION   │
                    │ the compiler    │             │ ORDER            │
                    │                 │             │                 │
                    │ Padding is      │             │ Padding follows │
                    │ UNPREDICTABLE   │             │ C ABI rules     │
                    │                 │             │                 │
                    │ Layout DIFFERS  │             │ Layout MATCHES  │
                    │ between eBPF VM │             │ between eBPF VM │
                    │ and x86_64      │             │ and x86_64      │
                    └─────────────────┘             └─────────────────┘
                          ✗ BROKEN                       ✓ CORRECT
```

---

## eBPF Maps

Two eBPF maps provide the shared memory between kernel and user space:

```
┌─────────────────────────────────────────────────────────┐
│                    eBPF Maps                            │
│                                                         │
│  ┌──────────────────────────────┐                      │
│  │  BLOCKLIST (HashMap)         │                      │
│  │                              │                      │
│  │  Type: Hash Map              │                      │
│  │  Max entries: 1,024          │                      │
│  │  Key: BlocklistKey (32 B)    │                      │
│  │  Value: BlocklistValue (4 B) │                      │
│  │                              │                      │
│  │  Populated by: daemon        │◄── User space writes │
│  │  Read by: eBPF hooks         │──► Kernel reads      │
│  │                              │                      │
│  │  Lookup: O(1) per event      │                      │
│  └──────────────────────────────┘                      │
│                                                         │
│  ┌──────────────────────────────┐                      │
│  │  EVENTS (RingBuf)            │                      │
│  │                              │                      │
│  │  Type: Ring Buffer           │                      │
│  │  Size: 256 KB                │                      │
│  │  Payload: FirewallEvent      │                      │
│  │  (288 bytes per event)       │                      │
│  │                              │                      │
│  │  Written by: eBPF hooks      │──► Kernel writes     │
│  │  Read by: daemon             │◄── User space reads  │
│  │                              │                      │
│  │  ~900 events before wrap     │                      │
│  └──────────────────────────────┘                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Hook Points

### Tracepoint: `sys_enter_execve`

Intercepts every `execve()` syscall — the kernel function that replaces a process image with a new program.

```
                    Process calls execve()
                            │
                            ▼
         ┌──────────────────────────────────────┐
         │   sys_enter_execve tracepoint        │
         │                                      │
         │   Context extraction:                │
         │   ┌────────────────────────────────┐ │
         │   │ bpf_get_current_pid_tgid()     │ │
         │   │   → PID (upper 32 bits)        │ │
         │   │                                │ │
         │   │ bpf_get_current_uid_gid()      │ │
         │   │   → UID (lower 32 bits)        │ │
         │   │                                │ │
         │   │ bpf_get_current_comm()         │ │
         │   │   → comm[16] (task name)       │ │
         │   │                                │ │
         │   │ ctx.read_at::<u64>(16)         │ │
         │   │   → filename pointer           │ │
         │   │                                │ │
         │   │ bpf_probe_read_user_str_bytes()│ │
         │   │   → path[256] (binary path)    │ │
         │   └────────────────────────────────┘ │
         │                                      │
         │   Tracepoint args offset 16 =        │
         │   filename pointer in execve args    │
         └──────────────────────────────────────┘
```

### Kprobe: `tcp_v4_connect`

Intercepts every outbound IPv4 TCP connection attempt.

```
                    Process calls connect()
                            │
                            ▼
         ┌──────────────────────────────────────┐
         │   tcp_v4_connect kprobe              │
         │                                      │
         │   Argument: struct sock *sk          │
         │                                      │
         │   Context extraction:                │
         │   ┌────────────────────────────────┐ │
         │   │ bpf_get_current_pid_tgid()     │ │
         │   │   → PID                        │ │
         │   │                                │ │
         │   │ sk + offset 0                  │ │
         │   │   → dst_ip  (skc_daddr)        │ │
         │   │                                │ │
         │   │ sk + offset 4                  │ │
         │   │   → src_ip  (skc_rcv_saddr)    │ │
         │   │                                │ │
         │   │ sk + offset 12                 │ │
         │   │   → dst_port (skc_dport)       │ │
         │   └────────────────────────────────┘ │
         │                                      │
         │   Note: Offsets are kernel-version   │
         │   dependent. Production should use   │
         │   CO-RE with BTF for portability.    │
         └──────────────────────────────────────┘
```

---

## Decision Engine Flow

```
                         Event Intercepted
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Extract context    │
                    │  (PID, path/IP)     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Build BlocklistKey │
                    │  from first 32      │
                    │  bytes of path/IP   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  BLOCKLIST.get(&key)│
                    │  HashMap O(1)       │
                    └──────┬───────┬──────┘
                           │       │
                     Found │       │ Not Found
                           │       │
                    ┌──────▼──┐ ┌──▼──────────────────┐
                    │ blocked │ │                      │
                    │ != 0 ?  │ │  Build FirewallEvent │
                    └──┬───┬──┘ │  Reserve RingBuf     │
                       │   │    │  Write + Submit      │
                  Yes  │   │No  │                      │
                       │   │    └──────────┬───────────┘
                 ┌─────▼─┐ │              │
                 │DENY   │ └──────┐       │
                 │Return │        │       │
                 │  1    │        ▼       ▼
                 └───────┘    ┌──────────────┐
                              │ ALLOW        │
                              │ Return 0     │
                              └──────────────┘
```

---

## Configuration

Configuration is stored at `/etc/claw-wall/config.toml` with `chmod 600` (root-only read/write):

```toml
[api]
key = "sk-your-api-key-here"

[blocklist]
paths = [
    "/usr/bin/malware",
    "/tmp/suspicious-binary",
    "/home/user/.backdoor"
]
ips = [
    "192.168.1.100",
    "10.0.0.50",
    "203.0.113.42"
]
```

**Config path hierarchy:**

```
/etc/claw-wall/              (chmod 700, root only)
├── config.toml              (chmod 600, API key + blocklist)
└── claw-wall-ebpf.o         (compiled eBPF bytecode)
```

---

## Deployment & Installation

### Installation Flow

```
                    sudo ./install.sh
                           │
              ┌────────────▼────────────┐
              │  1. Verify root (id -u) │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  2. Detect architecture │
              │  uname -m              │
              │  x86_64 │ aarch64      │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  3. Check systemd       │
              │  command -v systemctl   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  4. Check BPF support   │
              │  /proc/config.gz or     │
              │  /boot/config-$(uname)  │
              │  → CONFIG_BPF=y         │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  5. Create config dir   │
              │  /etc/claw-wall/        │
              │  chmod 700              │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  6. Install binary      │
              │  → /usr/local/bin/      │
              │     claw-wall           │
              │  chmod 755              │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  7. Install service     │
              │  → /etc/systemd/system/ │
              │     claw-wall.service   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  8. systemctl           │
              │  daemon-reload          │
              │  enable claw-wall       │
              │  start claw-wall        │
              └────────────┬────────────┘
                           │
                           ▼
                    Installation complete!
                    Next: claw-wall --configure
```

---

## Systemd Integration

The daemon runs as a background system service managed by systemd:

```ini
[Unit]
Description=OpenClawDefender eBPF Execution Firewall
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/claw-wall run
Restart=on-failure
RestartSec=5
User=root

# eBPF requires elevated kernel capabilities
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON

# Security hardening
ProtectSystem=strict
ReadWritePaths=/etc/claw-wall
PrivateTmp=true

[Install]
WantedBy=multi-user.target    # Start on boot
```

**Service lifecycle:**

```
                    System Boot
                        │
                        ▼
              multi-user.target reached
                        │
                        ▼
              claw-wall.service starts
                        │
                ┌───────▼───────┐
                │  Load eBPF    │
                │  Attach hooks │
                │  Read events  │
                └───────┬───────┘
                        │
           ┌────────────┼────────────┐
           │            │            │
      On failure    SIGTERM     Running OK
           │            │            │
           ▼            ▼            │
      Restart       Graceful        │
      after 5s      shutdown        │
           │                        │
           └────────────────────────┘
```

---

## Security Model

```
┌──────────────────────────────────────────────────────────┐
│                   Security Layers                        │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Layer 1: File Permissions                      │    │
│  │  /etc/claw-wall/config.toml → chmod 600 (root)  │    │
│  │  /etc/claw-wall/            → chmod 700 (root)  │    │
│  │  API key accessible only by root process        │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Layer 2: Linux Capabilities                    │    │
│  │  CAP_BPF       → Load eBPF programs             │    │
│  │  CAP_SYS_ADMIN → Access kernel memory maps      │    │
│  │  CAP_NET_ADMIN → Network probe attachment        │    │
│  │  CAP_PERFMON   → Performance monitoring access   │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Layer 3: systemd Hardening                     │    │
│  │  ProtectSystem=strict (read-only filesystem)    │    │
│  │  PrivateTmp=true (isolated /tmp)                │    │
│  │  ReadWritePaths=/etc/claw-wall (only exception) │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Layer 4: eBPF Verifier                         │    │
│  │  Kernel validates all eBPF bytecode before load │    │
│  │  No unbounded loops, no OOB access, no crashes  │    │
│  │  512-byte stack limit enforced by hardware      │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Layer 5: Fail-Open Design                      │    │
│  │  eBPF hooks return ALLOW on any internal error  │    │
│  │  System never locks out due to firewall bugs    │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Minimum Version | Purpose |
|---|---|---|
| Linux kernel | 5.15+ | eBPF ring buffer support |
| Rust toolchain | nightly | `build-std=core` for eBPF target |
| `rust-src` component | — | Required for `-Z build-std` |
| [bpf-linker](https://github.com/aya-rs/bpf-linker) | latest | Links eBPF object files |
| systemd | 240+ | Service management |
| Root access | — | eBPF loading + /etc writes |

### Install Prerequisites

```bash
# Install Rust nightly with rust-src
rustup toolchain install nightly --component rust-src

# Install bpf-linker
cargo install bpf-linker

# Install kernel headers (Debian/Ubuntu)
sudo apt install linux-headers-$(uname -r)

# Install kernel headers (Fedora/RHEL)
sudo dnf install kernel-devel-$(uname -r)
```

---

## Build Instructions

```bash
# Clone the repository
git clone https://github.com/jasur-2902/OpenClawDefender.git
cd OpenClawDefender

# Build everything (eBPF + daemon)
cargo xtask build

# Build in release mode
cargo xtask build --release

# Build only the eBPF program
cargo xtask build-ebpf

# Build only the eBPF program in release mode
cargo xtask build-ebpf --release
```

### Full deployment:

```bash
# Build release binaries
cargo xtask build --release

# Install system-wide
sudo ./install.sh

# Configure API key and blocklist
sudo claw-wall --configure

# Check status
sudo systemctl status claw-wall

# View real-time logs
sudo journalctl -u claw-wall -f
```

---

## CLI Reference

```
claw-wall — OpenClawDefender eBPF firewall daemon

USAGE:
    claw-wall [OPTIONS] [COMMAND]

COMMANDS:
    configure    Interactive API key configuration
    run          Start the daemon (default if no command given)

OPTIONS:
    --configure        Configure the daemon (interactive API key prompt)
    --install-service  Generate and install systemd unit file
    -h, --help         Print help
```

### Examples

```bash
# Start the daemon (foreground)
sudo claw-wall run

# Or equivalently (run is the default)
sudo claw-wall

# Configure API key interactively
sudo claw-wall --configure
# > Enter your Anthropic/OpenAI API Key: sk-...

# Install as systemd service
sudo claw-wall --install-service
# Then: sudo systemctl daemon-reload && sudo systemctl enable --now claw-wall
```

### Log Output Format

```
[2025-01-15T10:23:45Z INFO  claw_wall] Attached tracepoint: syscalls/sys_enter_execve
[2025-01-15T10:23:45Z INFO  claw_wall] Attached kprobe: tcp_v4_connect
[2025-01-15T10:23:45Z INFO  claw_wall] Blocklisted path: /usr/bin/malware
[2025-01-15T10:23:45Z INFO  claw_wall] Daemon started — listening for eBPF events
[2025-01-15T10:23:46Z INFO  claw_wall] [PROCESS] pid=1234 uid=1000 comm="bash" path="/usr/bin/ls"
[2025-01-15T10:23:47Z INFO  claw_wall] [NETWORK] pid=5678 0.0.0.0:0 -> 93.184.216.34:443
```

---

## License

MIT

---

<p align="center">
  Built with Rust, eBPF, and the <a href="https://aya-rs.dev/">Aya framework</a>.
</p>
