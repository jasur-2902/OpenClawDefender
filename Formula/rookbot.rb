class Rookbot < Formula
  desc "A firewall for AI agents — intercept, inspect, and control MCP tool calls"
  homepage "https://github.com/rookbot-io/rookbot"
  version "0.5.0-beta"
  license all_of: ["Apache-2.0", "MIT"]

  on_macos do
    url "https://github.com/rookbot-io/rookbot/releases/download/v#{version}/rookbot-macos-universal.tar.gz"
    sha256 "a7e063c2f3676ef0c33b4bc6885cf08fe6b971933677f71c601dd23c93ad5d2f"
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/rookbot-io/rookbot/releases/download/v#{version}/rookbot-linux-aarch64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/rookbot-io/rookbot/releases/download/v#{version}/rookbot-linux-x86_64.tar.gz"
      sha256 "a91b772cd805464ee1c68210dfed25149abc30ab70061dc48ca5c2f554db577d"
    end
  end

  def install
    bin.install "rookbot"
    bin.install "rookbot-daemon"
  end

  def post_install
    system bin/"rookbot", "init"
  end

  def caveats
    <<~EOS
      Rookbot has been installed!

      To protect an MCP server:
        rookbot wrap <server-name>

      To start the background daemon:
        rookbot daemon start

      Configuration: ~/.config/rookbot/
      Audit logs:    ~/.local/share/rookbot/
    EOS
  end

  test do
    assert_match "rookbot", shell_output("#{bin}/rookbot --version")
    assert_match(/ok|warn|error/i, shell_output("#{bin}/rookbot doctor 2>&1", 0))
  end
end
