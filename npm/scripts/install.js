#!/usr/bin/env node
"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");

const REPO = "rookbot-io/rookbot";
const VERSION = require("../package.json").version;
const BIN_DIR = path.join(__dirname, "..", "bin");

const PLATFORM_MAP = {
  darwin: { tarball: "rookbot-macos-universal.tar.gz" },
  linux: {
    x64: "rookbot-linux-x86_64.tar.gz",
    arm64: "rookbot-linux-aarch64.tar.gz",
  },
};

function getTarball() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "darwin") {
    return PLATFORM_MAP.darwin.tarball;
  }

  if (platform === "linux") {
    const tarball = PLATFORM_MAP.linux[arch];
    if (!tarball) {
      throw new Error(
        `Unsupported Linux architecture: ${arch}. Supported: x64, arm64`
      );
    }
    return tarball;
  }

  throw new Error(
    `Unsupported platform: ${platform}. Rookbot supports macOS and Linux.`
  );
}

function download(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    client
      .get(url, { headers: { "User-Agent": "rookbot-npm-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return download(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`Download failed: HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

async function install() {
  const tarball = getTarball();
  const tag = VERSION.includes("-") ? `v${VERSION}` : `v${VERSION}`;
  const url = `https://github.com/${REPO}/releases/download/${tag}/${tarball}`;

  console.log(`Rookbot: Downloading ${tarball} for ${process.platform}/${process.arch}...`);

  const data = await download(url);

  // Write tarball to temp file
  const tmpDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "rookbot-"));
  const tarPath = path.join(tmpDir, tarball);
  fs.writeFileSync(tarPath, data);

  // Ensure bin directory exists
  fs.mkdirSync(BIN_DIR, { recursive: true });

  // Extract
  console.log("Rookbot: Extracting binaries...");
  execSync(`tar xzf "${tarPath}" -C "${BIN_DIR}"`, { stdio: "inherit" });

  // Set executable permissions
  const rookbot = path.join(BIN_DIR, "rookbot");
  const daemon = path.join(BIN_DIR, "rookbot-daemon");

  if (fs.existsSync(rookbot)) {
    fs.chmodSync(rookbot, 0o755);
  }
  if (fs.existsSync(daemon)) {
    fs.chmodSync(daemon, 0o755);
  }

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log("Rookbot: Installation complete!");
  console.log("  Run 'rookbot --help' to get started.");
}

install().catch((err) => {
  console.error(`Rookbot installation failed: ${err.message}`);
  console.error("");
  console.error("You can install manually:");
  console.error("  curl -fsSL https://raw.githubusercontent.com/rookbot-io/rookbot/main/scripts/install.sh | bash");
  process.exit(1);
});
