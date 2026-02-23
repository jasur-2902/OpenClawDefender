cask "clawdefender" do
  version "0.5.0-beta"
  sha256 :no_check  # Will be set in release workflow

  url "https://github.com/clawdefender/clawdefender/releases/download/v#{version}/ClawDefender-#{version}-universal.dmg"
  name "ClawDefender"
  desc "AI Agent Security Firewall - GUI Application"
  homepage "https://github.com/clawdefender/clawdefender"

  app "ClawDefender.app"
  binary "ClawDefender.app/Contents/MacOS/clawdefender"

  zap trash: [
    "~/.clawdefender",
    "~/.local/share/clawdefender",
    "~/Library/Application Support/com.clawdefender.app",
    "~/Library/Preferences/com.clawdefender.app.plist",
  ]
end
