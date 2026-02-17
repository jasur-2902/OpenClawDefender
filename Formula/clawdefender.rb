class Clawdefender < Formula
  desc "A firewall for AI agents - intercept, inspect, and control MCP tool calls"
  homepage "https://github.com/clawdefender/clawdefender"
  version "0.1.0"
  license all_of: ["Apache-2.0", "MIT"]

  on_macos do
    url "https://github.com/clawdefender/clawdefender/releases/download/v#{version}/clawdefender-macos-universal.tar.gz"
    sha256 "PLACEHOLDER"
  end

  def install
    bin.install "clawdefender"
    bin.install "clawdefender-daemon"
  end

  def post_install
    system bin/"clawdefender", "init"
  end

  def caveats
    <<~EOS
      ClawDefender has been installed!

      To protect an MCP server:
        clawdefender wrap <server-name>

      To start the background daemon:
        clawdefender daemon start

      Configuration: ~/.config/clawdefender/
      Audit logs:    ~/.local/share/clawdefender/
    EOS
  end

  test do
    assert_match "clawdefender", shell_output("#{bin}/clawdefender --version")
    assert_match(/ok|warn|error/i, shell_output("#{bin}/clawdefender doctor 2>&1", 0))
  end
end
