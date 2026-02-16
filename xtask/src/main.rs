use std::process::Command;
use std::path::PathBuf;
use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "xtask")]
enum Xtask {
    /// Build the eBPF program
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build the entire project (eBPF + user-space)
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cmd = Xtask::parse();
    match cmd {
        Xtask::BuildEbpf { release } => build_ebpf(release),
        Xtask::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
    }
}

fn workspace_root() -> PathBuf {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .expect("failed to run cargo locate-project");
    let path = String::from_utf8(output.stdout).expect("invalid utf8");
    PathBuf::from(path.trim()).parent().unwrap().to_path_buf()
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root();
    let ebpf_dir = root.join("claw-wall-ebpf");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env("CARGO_CFG_BPF_TARGET_ARCH", "x86_64")
        .args([
            "+nightly",
            "build",
            "--target=bpfel-unknown-none",
            "-Z", "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build eBPF program")?;
    if !status.success() {
        bail!("eBPF build failed");
    }

    println!("eBPF program built successfully");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--package", "claw-wall-daemon"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build user-space daemon")?;
    if !status.success() {
        bail!("user-space build failed");
    }

    println!("User-space daemon built successfully");
    Ok(())
}
