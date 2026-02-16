class Clawai < Formula
  desc "A firewall for AI agents - intercept, inspect, and control MCP tool calls"
  homepage "https://github.com/clawai/clawai"
  version "0.1.0"
  license all_of: ["Apache-2.0", "MIT"]

  on_macos do
    url "https://github.com/clawai/clawai/releases/download/v#{version}/clawai-macos-universal.tar.gz"
    sha256 "PLACEHOLDER"
  end

  def install
    bin.install "clawai"
  end

  def post_install
    system bin/"clawai", "init"
  end

  def caveats
    <<~EOS
      ClawAI has been installed!

      To protect an MCP server:
        clawai wrap <server-name>

      Configuration: ~/.config/clawai/
      Audit logs:    ~/.local/share/clawai/
    EOS
  end

  test do
    assert_match "clawai", shell_output("#{bin}/clawai --version")
  end
end
