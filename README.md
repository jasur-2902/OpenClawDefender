# OpenClawDefender

Rust-based eBPF execution firewall using the [Aya](https://aya-rs.dev/) framework.

## Architecture

This project is organized as a Cargo workspace with four crates:

| Crate | Role |
|---|---|
| `claw-wall-common` | Shared `#![no_std]` structs used by both kernel and user-space code |
| `claw-wall-ebpf` | Kernel-side eBPF probes (compiled to BPF bytecode) |
| `claw-wall-daemon` | User-space loader, policy engine, and CLI |
| `xtask` | Build tooling and developer workflows |

## Prerequisites

- Linux kernel 5.15+
- Rust nightly toolchain
- [bpf-linker](https://github.com/aya-rs/bpf-linker)

## Build

```sh
cargo xtask build          # debug build
cargo xtask build --release # release build
```

## Install

```sh
sudo ./install.sh
```

## Configure

```sh
sudo claw-wall --configure
```

## How It Works

OpenClawDefender attaches eBPF probes to two kernel entry points:

- **sys_enter_execve** -- intercepts process execution attempts
- **tcp_v4_connect** -- intercepts outbound IPv4 connections

Each probe checks the event against a **BPF HashMap** blocklist loaded from user-space policy. Blocked events are denied at the kernel level before they can proceed. All decisions (allow/deny) are streamed to the daemon via a **RingBuf** for real-time telemetry and logging.

## License

MIT
