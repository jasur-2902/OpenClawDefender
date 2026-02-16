<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" alt="Rust"/>
  <img src="https://img.shields.io/badge/framework-Aya-blue?style=for-the-badge" alt="Aya"/>
  <img src="https://img.shields.io/badge/platform-Linux-green?style=for-the-badge&logo=linux" alt="Linux"/>
  <img src="https://img.shields.io/badge/kernel-eBPF-red?style=for-the-badge" alt="eBPF"/>
  <img src="https://img.shields.io/badge/AI-LLM%20Cold%20Path-purple?style=for-the-badge" alt="AI"/>
  <img src="https://img.shields.io/badge/license-MIT-purple?style=for-the-badge" alt="MIT"/>
</p>

# OpenClawDefender

**A high-performance, kernel-level execution firewall built in Rust using eBPF and the [Aya](https://aya-rs.dev/) framework, with AI-powered threat analysis.**

OpenClawDefender intercepts process executions, network connections, and DNS queries at the Linux kernel level — before they reach user space — using eBPF probes. It evaluates each event against an in-kernel blocklist using FNV-1a hashing at wire speed, silently denying malicious activity while streaming real-time telemetry to a user-space daemon. Suspicious events are routed to an LLM-based "AI Cold Path" for behavioral analysis, and blocked entities are dynamically injected back into the kernel blocklist.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Key Features](#key-features)
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
- [FNV-1a Hashing](#fnv-1a-hashing)
- [AI Cold Path Analysis](#ai-cold-path-analysis)
- [Terminal UI (TUI)](#terminal-ui-tui)
- [Configuration](#configuration)
- [Testing on macOS](#testing-on-macos)
- [Deployment & Installation](#deployment--installation)
- [Systemd Integration](#systemd-integration)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [CLI Reference](#cli-reference)
- [License](#license)

---

## Key Features

| Feature | Description |
|---------|-------------|
| **FNV-1a Collision-Resistant Hashing** | All blocklist lookups use 64-bit FNV-1a hashes instead of truncated byte arrays, eliminating prefix collisions |
| **Process Execution Interception** | Tracepoint on `sys_enter_execve` captures every process spawn with PID, UID, command name, and binary path |
| **Network Connection Interception** | Kprobe on `tcp_v4_connect` intercepts IPv4 TCP connections with source/destination IP and port |
| **DNS Query Interception** | Kprobe on `udp_sendmsg` captures DNS queries (port 53) and extracts queried domain names |
| **CWD-Aware Path Resolution** | Relative execution paths (e.g., `./malware`) are resolved to absolute paths using `/proc/<pid>/cwd` |
| **AI Cold Path Analysis** | Suspicious events are asynchronously evaluated by an LLM (Anthropic Claude / OpenAI) for behavioral threat analysis |
| **Dynamic Blocklist Updates** | AI-blocked entities are immediately hashed and inserted into the kernel eBPF blocklist map |
| **Domain Policy Engine** | DNS queries are cross-referenced against a configurable domain blocklist with subdomain matching |
| **Real-Time TUI Dashboard** | Split-pane terminal UI shows live syscall interceptions and AI verdict history |
| **macOS Testing Support** | Docker, Lima VM, and Vagrant backends for testing on macOS |

---

## Architecture Overview

OpenClawDefender operates across two execution environments with a shared memory contract, plus an async AI analysis pipeline:

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
│  │              Load bytecode            Route events           │   │
│  │              Populate maps           ┌────────┴────────┐    │   │
│  │                                      │                 │    │   │
│  │                               ┌──────▼──────┐  ┌──────▼──┐ │   │
│  │                               │  Known-Safe  │  │  AI     │ │   │
│  │                               │  Filter      │  │  Cold   │ │   │
│  │                               │  (fast path) │  │  Path   │ │   │
│  │                               └──────────────┘  └────┬────┘ │   │
│  │                                                       │      │   │
│  │                               ┌───────────────────────▼────┐ │   │
│  │                               │  TUI Dashboard (ratatui)  │ │   │
│  │                               │  ┌─────────┐ ┌──────────┐ │ │   │
│  │                               │  │ Syscalls │ │AI Verdicts│ │ │   │
│  │                               │  │  (live)  │ │ (history) │ │ │   │
│  │                               │  └─────────┘ └──────────┘ │ │   │
│  │                               └────────────────────────────┘ │   │
│  └───────────────────────┼──────────────────────────────────────┘   │
│                          │                                          │
├──────────────────────────┼──────────────────────────────────────────┤
│                     KERNEL BOUNDARY                                 │
├──────────────────────────┼──────────────────────────────────────────┤
│                          │                                          │
│                    KERNEL SPACE                                     │
│                                                                     │
│  ┌───────────────────────┼──────────────────────────────────────┐   │
│  │                  claw-wall-ebpf                               │   │
│  │                       │                       ▲               │   │
│  │  ┌────────────────────▼────────────────────┐  │               │   │
│  │  │          eBPF Maps (shared memory)      │  │               │   │
│  │  │  ┌──────────────┐  ┌─────────────────┐  │  │               │   │
│  │  │  │  BLOCKLIST   │  │     EVENTS      │  │  │               │   │
│  │  │  │  (HashMap)   │  │   (RingBuf)     │──┼──┘               │   │
│  │  │  │  u64 FNV-1a  │  └────────▲────────┘  │                  │   │
│  │  │  └──────┬───────┘           │            │                  │   │
│  │  └─────────┼───────────────────┼────────────┘                  │   │
│  │            │                   │                               │   │
│  │  ┌─────────▼───────────────────┼───────────────────────────┐  │   │
│  │  │              Hook Entry Points                          │  │   │
│  │  │                                                         │  │   │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │   │
│  │  │  │ claw_wall_   │  │ claw_wall_   │  │ claw_wall_   │  │  │   │
│  │  │  │ execve       │  │ connect      │  │ dns          │  │  │   │
│  │  │  │ (tracepoint) │  │ (kprobe)     │  │ (kprobe)     │  │  │   │
│  │  │  │              │  │              │  │              │  │  │   │
│  │  │  │ sys_enter_   │  │ tcp_v4_      │  │ udp_sendmsg  │  │  │   │
│  │  │  │ execve       │  │ connect      │  │ (port 53)    │  │  │   │
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │   │
│  │  └─────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

```
 Process calls execve("./malware")
         │
         ▼
 ┌───────────────────────────────────────────┐
 │  Linux Kernel: sys_enter_execve           │
 │  Tracepoint fires → claw_wall_execve()   │
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
 │  FNV-1a Hash path → BlocklistKey (u64)   │
 │  Lookup in BLOCKLIST HashMap             │
 └──────┬────────────────────────┬──────────┘
        │                        │
   Found (blocked=1)        Not Found
        │                        │
        ▼                        ▼
 ┌──────────────┐    ┌───────────────────────┐
 │  DENY        │    │  ALLOW                │
 │  Return 1    │    │  Push FirewallEvent   │
 │  Syscall     │    │  to EVENTS RingBuf    │
 │  blocked     │    │  Return 0             │
 └──────────────┘    └───────────┬───────────┘
                                 │
                                 ▼
                  ┌──────────────────────────┐
                  │  User-Space Daemon       │
                  │  Telemetry Router        │
                  │                          │
                  │  1. Resolve relative     │
                  │     path via /proc/cwd   │
                  │                          │
                  │  2. Known-safe filter:   │
                  │     /usr/bin/* → ALLOW   │
                  │     PID 1     → ALLOW   │
                  │                          │
                  │  3. Unknown → AI Cold    │
                  │     Path (async LLM)     │
                  │                          │
                  │  4. AI BLOCK → hash &    │
                  │     insert into eBPF     │
                  │     BLOCKLIST map        │
                  │                          │
                  │  5. Push to TUI state    │
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
│       └── lib.rs                  # ProcessEvent, NetworkEvent, DnsEvent,
│                                   # FirewallEvent, BlocklistKey, FNV-1a
├── claw-wall-ebpf/                 # Kernel-space eBPF program
│   ├── Cargo.toml                  # Targets bpfel-unknown-none
│   ├── rust-toolchain.toml         # Requires nightly + rust-src
│   └── src/
│       └── main.rs                 # #![no_std] hooks: execve, connect, dns
├── claw-wall-daemon/               # User-space daemon & CLI
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # Aya loader, event loop, telemetry router
│       ├── ai_analyzer.rs          # Async LLM client (Anthropic/OpenAI)
│       └── tui.rs                  # Terminal UI (ratatui + crossterm)
├── xtask/                          # Build orchestration
│   ├── Cargo.toml
│   └── src/
│       └── main.rs                 # Cross-compilation commands
├── scripts/
│   ├── test-mac.sh                 # Auto-detecting macOS test launcher
│   ├── test-docker.sh              # Docker-based testing
│   ├── test-lima.sh                # Lima VM testing
│   ├── test-vm.sh                  # Vagrant VM testing
│   └── docker-entrypoint.sh        # Docker container entrypoint
├── tests/
│   └── integration_test.sh         # Integration test suite
├── Cargo.toml                      # Workspace root
├── Dockerfile.test                 # Multi-stage test Dockerfile
├── lima.yaml                       # Lima VM configuration
├── Vagrantfile                     # Vagrant VM configuration
├── claw-wall.service               # systemd unit file
├── install.sh                      # POSIX installer script
├── .dockerignore
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
| `ProcessEvent` | Exec telemetry (pid, uid, comm, path, cwd) | 536 bytes |
| `NetworkEvent` | Connection telemetry (pid, src/dst IP, port) | 16 bytes |
| `DnsEvent` | DNS query telemetry (pid, domain, dst IP) | 272 bytes |
| `FirewallEvent` | Tagged union envelope for RingBuf | 544 bytes |
| `EventPayload` | C union of ProcessEvent / NetworkEvent / DnsEvent | 536 bytes |
| `BlocklistKey` | HashMap key (FNV-1a u64 hash) | 8 bytes |
| `BlocklistValue` | HashMap value (blocked flag) | 8 bytes |

**Exported functions:**

| Function | Purpose | eBPF Safe |
|---|---|---|
| `fnv1a_hash_fixed::<N>(&[u8; N]) -> u64` | Hash fixed-size arrays (bounded loop) | Yes |
| `fnv1a_hash(&[u8]) -> u64` | Hash dynamic slices | No (user-space only) |

### `claw-wall-ebpf` — Kernel-Space Sensor

The "hot path" — code that runs inside the Linux kernel's eBPF virtual machine on every intercepted syscall.

**Three hook points:**

| Hook | Type | Intercepts |
|---|---|---|
| `claw_wall_execve` | Tracepoint (`sys_enter_execve`) | Process execution |
| `claw_wall_connect` | Kprobe (`tcp_v4_connect`) | IPv4 TCP connections |
| `claw_wall_dns` | Kprobe (`udp_sendmsg`) | DNS queries (port 53) |

**eBPF verifier constraints strictly enforced:**

| Constraint | Implementation |
|---|---|
| `#![no_std]` + `#![no_main]` | No standard library, no main function |
| 512-byte stack limit | All structs fit within budget; no recursive calls |
| No dynamic allocation | All data uses stack-allocated fixed-size arrays |
| No unbounded loops | All loops use compile-time constant bounds |
| Core library only | Zero dependencies beyond `core` and `aya-ebpf` |
| Fail-open on error | Errors return 0 (allow) to prevent system lockout |

**Compilation target:** `bpfel-unknown-none` (eBPF little-endian, no OS)

### `claw-wall-daemon` — User-Space Daemon

The management plane: loads eBPF bytecode into the kernel, populates policy maps, consumes telemetry events, routes suspicious activity to AI analysis, and provides a real-time terminal UI.

**Components:**

| Component | Technology | Purpose |
|---|---|---|
| CLI | `clap` (derive) | `configure`, `run`, `--install-service` |
| eBPF Loader | `aya` | Load `.o` bytecode, attach probes |
| Event Loop | `tokio` + `select!` | Async RingBuf consumer with graceful shutdown |
| Telemetry Router | Custom | Filter known-safe events, route suspicious to AI |
| AI Cold Path | `reqwest` + LLM | Async threat analysis (Anthropic/OpenAI) |
| Path Resolver | `std::path` | Resolve relative paths via CWD + `/proc/<pid>/cwd` |
| Domain Policy | Config-driven | Cross-reference DNS queries against domain blocklist |
| TUI Dashboard | `ratatui` + `crossterm` | Split-pane real-time terminal interface |
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

### ProcessEvent Layout (536 bytes)

```
Offset  Size    Field           Type            Notes
──────  ──────  ──────────────  ──────────────  ─────────────────────────
0       4       pid             u32             Process ID
4       4       uid             u32             User ID
8       16      comm            [u8; 16]        Task name (TASK_COMM_LEN)
24      256     path            [u8; 256]       Binary path (null-padded)
280     256     cwd             [u8; 256]       Current working directory
──────  ──────
Total:  536 bytes                               No internal padding needed
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

### DnsEvent Layout (272 bytes)

```
Offset  Size    Field           Type            Notes
──────  ──────  ──────────────  ──────────────  ─────────────────────────
0       4       pid             u32             Process ID
4       4       dst_ip          u32             DNS server IP
8       2       dst_port        u16             Port (should be 53)
10      2       _pad            u16             Padding
12      4       domain_len      u32             Extracted domain length
16      253     domain          [u8; 253]       Domain name (null-padded)
269     3       _pad2           [u8; 3]         Alignment padding
──────  ──────
Total:  272 bytes
```

### BlocklistKey Layout (8 bytes)

```
Offset  Size    Field           Type            Notes
──────  ──────  ──────────────  ──────────────  ─────────────────────────
0       8       hash            u64             FNV-1a 64-bit hash
──────  ──────
Total:  8 bytes                                 Collision-resistant lookup
```

---

## eBPF Maps

```
┌─────────────────────────────────────────────────────────┐
│                    eBPF Maps                            │
│                                                         │
│  ┌──────────────────────────────┐                      │
│  │  BLOCKLIST (HashMap)         │                      │
│  │                              │                      │
│  │  Type: Hash Map              │                      │
│  │  Max entries: 1,024          │                      │
│  │  Key: BlocklistKey (8 B)     │                      │
│  │       u64 FNV-1a hash        │                      │
│  │  Value: BlocklistValue (8 B) │                      │
│  │                              │                      │
│  │  Written by:                 │                      │
│  │    - Daemon (config init)    │◄── User space writes │
│  │    - AI verdicts (dynamic)   │                      │
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
│  │  (544 bytes per event)       │                      │
│  │                              │                      │
│  │  Written by: eBPF hooks      │──► Kernel writes     │
│  │  Read by: daemon             │◄── User space reads  │
│  │                              │                      │
│  │  ~480 events before wrap     │                      │
│  └──────────────────────────────┘                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Hook Points

### Tracepoint: `sys_enter_execve`

Intercepts every `execve()` syscall. Extracts PID, UID, command name, binary path. Hashes the path with FNV-1a and checks the blocklist.

### Kprobe: `tcp_v4_connect`

Intercepts outbound IPv4 TCP connections. Extracts PID, source/destination IP, port. Hashes the destination IP with FNV-1a and checks the blocklist.

### Kprobe: `udp_sendmsg` (DNS)

Intercepts UDP sendmsg calls. Filters for port 53 (DNS). Parses the DNS question section to extract the queried domain name using bounded label iteration (max 32 labels, max 63 bytes per label). Emits a `DnsEvent` to the ring buffer.

---

## FNV-1a Hashing

The previous implementation truncated file paths and IPs to 32 bytes for `BlocklistKey`, causing **collision vulnerability** — paths sharing the same first 32 bytes would be indistinguishable. For example, `/usr/local/bin/legitimate-tool` and `/usr/local/bin/legitimate-malware` would map to the same key.

**Fix:** All blocklist lookups now use FNV-1a (Fowler-Noll-Vo) 64-bit hashing:

```
FNV-1a Algorithm:
  hash = 0xcbf29ce484222325 (offset basis)
  for each byte:
    hash ^= byte
    hash *= 0x00000100000001B3 (prime)
  return hash
```

The same algorithm is implemented in both:
- **Kernel (eBPF):** `fnv1a_hash_fixed::<N>()` — `const fn` with compile-time bounded loop
- **User-space (daemon):** `fnv1a_hash()` — iterates over dynamic slices

Both produce identical u64 hashes, ensuring kernel/user-space consistency.

---

## AI Cold Path Analysis

Events that pass the known-safe filter are sent to an LLM for behavioral threat analysis:

```
Event Router
    │
    ├── Known-safe? (PID 1, /usr/bin/*, loopback IP)
    │   └── Yes → Log only, skip AI
    │
    └── Unknown/Suspicious
        └── tokio::spawn async AI call
            │
            ├── Anthropic (sk-ant-* key)
            │   POST https://api.anthropic.com/v1/messages
            │
            └── OpenAI (sk-* key)
                POST https://api.openai.com/v1/chat/completions
            │
            ├── 5-second timeout
            ├── Fail-open: any error → ALLOW
            │
            ├── ALLOW → Log verdict, push to TUI
            └── BLOCK → Hash entity, insert into eBPF BLOCKLIST map
                        Future attempts blocked at kernel level
```

**System prompt:**
> "You are an AI security analyzer. Evaluate this system process/network connection initiated by an autonomous agent. Does this match known prompt-injection or data exfiltration behaviors? Respond strictly with 'ALLOW' or 'BLOCK'."

---

## Terminal UI (TUI)

A real-time split-pane dashboard built with `ratatui` and `crossterm`:

```
┌─────────── Intercepted Syscalls ────────────┬──── AI Cold Path Analysis ────┐
│ Time     Type     PID      Details           │ [3s ago] [BLOCK] /tmp/shell   │
│ 2s ago   PROCESS  1234     comm="curl" ...   │   Suspicious execution        │
│ 5s ago   NETWORK  5678     10.0.0.1 -> ...   │                               │
│ 8s ago   DNS      9012     query "evil.com"  │ [15s ago] [ALLOW] /usr/bin/ls │
│ ...                                          │   Normal system operation     │
│                                              │                               │
│ Green = allowed, Red = blocked               │ Green = ALLOW, Red = BLOCK    │
└──────────────────────────────────────────────┴───────────────────────────────┘
  q/Ctrl+C = quit    ↑/↓ = scroll
```

- **Left pane (60%):** Real-time scrolling table of intercepted syscalls (Process/Network/DNS)
- **Right pane (40%):** AI verdict history with ALLOW/BLOCK status
- **State:** `Arc<RwLock<AppState>>` with last 100 events and last 10 AI verdicts
- **Rendering:** ~10 FPS via tokio task, non-blocking reads from shared state
- **Terminal cleanup:** Graceful raw-mode teardown on Ctrl+C

---

## Configuration

Configuration is stored at `/etc/claw-wall/config.toml` with `chmod 600` (root-only read/write):

```toml
[api]
key = "sk-your-api-key-here"  # Anthropic (sk-ant-*) or OpenAI (sk-*)

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
domains = [
    "malware.com",
    "evil.example.org",
    "c2-server.net"
]
```

**Config path hierarchy:**

```
/etc/claw-wall/              (chmod 700, root only)
├── config.toml              (chmod 600, API key + blocklist)
└── claw-wall-ebpf.o         (compiled eBPF bytecode)
```

---

## Testing on macOS

Since eBPF requires a Linux kernel, testing on macOS requires a Linux environment. The project supports three backends, with an auto-detecting launcher:

```bash
# Auto-detect best available backend and run tests
./scripts/test-mac.sh

# List available backends
./scripts/test-mac.sh --list

# Force a specific backend
./scripts/test-mac.sh --docker
./scripts/test-mac.sh --lima
./scripts/test-mac.sh --vagrant

# Run full eBPF tests (not just build validation)
./scripts/test-mac.sh --full
```

| Backend | Install | Best For |
|---------|---------|----------|
| Docker Desktop | `brew install --cask docker` | Fast iteration, build validation |
| Lima VM | `brew install lima` | Full eBPF kernel testing |
| Vagrant | `brew install --cask virtualbox vagrant` | Reproducible VM environments |

---

## Deployment & Installation

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

## Systemd Integration

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
WantedBy=multi-user.target
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
│  │  AI analysis defaults to ALLOW on timeout/error │    │
│  │  System never locks out due to firewall bugs    │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Layer 6: FNV-1a Collision Resistance           │    │
│  │  64-bit hash space (2^64 possible keys)         │    │
│  │  Eliminates prefix-based collision attacks      │    │
│  │  Identical algorithm in kernel and user space   │    │
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

### Testing on macOS:

```bash
# Quick build validation via Docker
./scripts/test-mac.sh

# Full eBPF testing via Lima VM
./scripts/test-mac.sh --lima --full
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
# Start the daemon with TUI (foreground)
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
[INFO  claw_wall] Attached tracepoint: syscalls/sys_enter_execve
[INFO  claw_wall] Attached kprobe: tcp_v4_connect
[INFO  claw_wall] Attached kprobe: udp_sendmsg (DNS)
[INFO  claw_wall] Blocklisted path: /usr/bin/malware
[INFO  claw_wall] Blocklisted domain: malware.com
[INFO  claw_wall] Daemon started — listening for eBPF events
[INFO  claw_wall] [PROCESS] pid=1234 uid=1000 comm="bash" path="/usr/bin/ls"
[INFO  claw_wall] [NETWORK] pid=5678 10.0.0.1:0 -> 93.184.216.34:443
[INFO  claw_wall] [DNS] pid=9012 query "example.com" via 8.8.8.8
[INFO  claw_wall] AI verdict: BLOCK
[INFO  claw_wall] AI blocked path inserted into BLOCKLIST: /tmp/suspicious
```

---

## License

MIT

---

<p align="center">
  Built with Rust, eBPF, and the <a href="https://aya-rs.dev/">Aya framework</a>.
</p>
