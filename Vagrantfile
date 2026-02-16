# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# OpenClawDefender - Vagrant VM for Linux eBPF Testing on macOS
#
# Usage:
#   vagrant up        # Boot and provision the VM
#   vagrant ssh       # SSH into the VM
#   vagrant destroy   # Tear down the VM

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"   # Ubuntu 22.04 LTS (kernel 5.15+)
  config.vm.hostname = "claw-wall-dev"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "OpenClawDefender-Dev"
    vb.memory = 4096
    vb.cpus = 2
  end

  # Sync the project directory into the VM
  config.vm.synced_folder ".", "/home/vagrant/OpenClawDefender", type: "rsync",
    rsync__exclude: [".git/", "target/"]

  # Provision: install Rust nightly, bpf-linker, kernel headers, BPF tools
  config.vm.provision "shell", privileged: true, inline: <<-SHELL
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    echo "=== Installing system packages ==="
    apt-get update -qq
    apt-get install -y -qq \
      build-essential \
      pkg-config \
      libssl-dev \
      linux-headers-$(uname -r) \
      linux-tools-$(uname -r) \
      linux-tools-common \
      bpftool \
      clang \
      llvm \
      libelf-dev \
      curl \
      git

    echo "=== Verifying BPF support ==="
    if [ -f /boot/config-$(uname -r) ]; then
      grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) && echo "BPF support: OK" || echo "WARNING: CONFIG_BPF not found"
      grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r) && echo "BPF_SYSCALL: OK" || echo "WARNING: CONFIG_BPF_SYSCALL not found"
    fi
  SHELL

  # Provision as vagrant user: install Rust toolchain
  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    set -euo pipefail

    echo "=== Installing Rust toolchain ==="
    if ! command -v rustup >/dev/null 2>&1; then
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
    fi
    source "$HOME/.cargo/env"

    echo "=== Installing nightly + rust-src ==="
    rustup toolchain install nightly --component rust-src
    rustup default nightly

    echo "=== Installing bpf-linker ==="
    cargo install bpf-linker

    echo "=== Verifying toolchain ==="
    rustc --version
    cargo --version
    rustup component list --installed | grep rust-src && echo "rust-src: OK"
    command -v bpf-linker && echo "bpf-linker: OK"

    echo "=== Provisioning complete ==="
  SHELL
end
