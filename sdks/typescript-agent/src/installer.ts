import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';

export type ConsentMode = 'auto' | 'prompt' | 'skip';

export interface InstallerOptions {
  consent?: ConsentMode;
  version?: string;
  installDir?: string;
}

function defaultInstallDir(): string {
  const platform = os.platform();
  if (platform === 'win32') {
    const appData = process.env['APPDATA'] ?? path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(appData, 'clawdefender', 'bin');
  }
  return path.join(os.homedir(), '.local', 'bin');
}

function findClawDefender(): string | null {
  const names = os.platform() === 'win32'
    ? ['clawdefender.exe']
    : ['clawdefender'];

  for (const name of names) {
    try {
      const result = execFileSync('which', [name], {
        encoding: 'utf-8',
        timeout: 3000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();
      if (result) return result;
    } catch {
      // not found via which
    }
  }

  // Check common install locations
  const candidates = [
    path.join(defaultInstallDir(), 'clawdefender'),
    '/usr/local/bin/clawdefender',
    '/usr/bin/clawdefender',
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }

  return null;
}

function getVersion(binary: string): string | null {
  try {
    const output = execFileSync(binary, ['--version'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    const match = output.match(/(\d+\.\d+\.\d+)/);
    return match ? match[1]! : null;
  } catch {
    return null;
  }
}

export interface DetectionResult {
  found: boolean;
  path: string | null;
  version: string | null;
  daemonRunning: boolean;
}

export async function detectClawDefender(): Promise<DetectionResult> {
  const binaryPath = findClawDefender();
  if (!binaryPath) {
    return { found: false, path: null, version: null, daemonRunning: false };
  }

  const version = getVersion(binaryPath);

  let daemonRunning = false;
  try {
    const res = await fetch('http://127.0.0.1:3202/api/v1/health', {
      signal: AbortSignal.timeout(2000),
    });
    daemonRunning = res.ok;
  } catch {
    daemonRunning = false;
  }

  return {
    found: true,
    path: binaryPath,
    version,
    daemonRunning,
  };
}

export async function ensureInstalled(
  options?: InstallerOptions,
): Promise<DetectionResult> {
  const consent = options?.consent ?? 'auto';
  const detection = await detectClawDefender();

  if (detection.found) {
    return detection;
  }

  if (consent === 'skip') {
    return detection;
  }

  if (consent === 'prompt') {
    console.log(
      'ClawDefender is not installed. Install it from https://github.com/clawdefender/clawdefender',
    );
    return detection;
  }

  // consent === 'auto': attempt download
  const installDir = options?.installDir ?? defaultInstallDir();
  const version = options?.version ?? 'latest';

  console.log(`ClawDefender not found. Attempting auto-install to ${installDir}...`);

  try {
    fs.mkdirSync(installDir, { recursive: true });
  } catch {
    console.error(`Failed to create install directory: ${installDir}`);
    return detection;
  }

  const platform = os.platform();
  const arch = os.arch();
  const platformMap: Record<string, string> = {
    linux: 'linux',
    darwin: 'macos',
    win32: 'windows',
  };
  const archMap: Record<string, string> = {
    x64: 'x86_64',
    arm64: 'aarch64',
  };

  const pStr = platformMap[platform];
  const aStr = archMap[arch];
  if (!pStr || !aStr) {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    return detection;
  }

  const ext = platform === 'win32' ? '.zip' : '.tar.gz';
  const url = `https://github.com/clawdefender/clawdefender/releases/${version === 'latest' ? 'latest/download' : `download/v${version}`}/clawdefender-${pStr}-${aStr}${ext}`;

  console.log(`Downloading from ${url}...`);

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(60000) });
    if (!res.ok) {
      console.error(`Download failed: HTTP ${res.status}`);
      return detection;
    }

    const tmpFile = path.join(os.tmpdir(), `clawdefender-download${ext}`);
    const buffer = Buffer.from(await res.arrayBuffer());
    fs.writeFileSync(tmpFile, buffer);

    if (ext === '.tar.gz') {
      execFileSync('tar', ['xzf', tmpFile, '-C', installDir], {
        timeout: 30000,
      });
    } else {
      execFileSync('unzip', ['-o', tmpFile, '-d', installDir], {
        timeout: 30000,
      });
    }

    try {
      fs.unlinkSync(tmpFile);
    } catch {
      // ignore cleanup failures
    }

    const binaryName = platform === 'win32' ? 'clawdefender.exe' : 'clawdefender';
    const binaryPath = path.join(installDir, binaryName);
    if (platform !== 'win32') {
      fs.chmodSync(binaryPath, 0o755);
    }

    console.log(`ClawDefender installed to ${binaryPath}`);
    return {
      found: true,
      path: binaryPath,
      version: getVersion(binaryPath),
      daemonRunning: false,
    };
  } catch (err) {
    console.error(`Auto-install failed: ${err}`);
    return detection;
  }
}
