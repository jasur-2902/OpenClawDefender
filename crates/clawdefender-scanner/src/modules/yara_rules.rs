/// Embedded YARA rules for RookBot signature detection.
///
/// Rules are organized by threat category. Each rule includes metadata
/// with description and severity to map detections to Finding severity levels.
/// EICAR antivirus test file detection.
pub const RULE_EICAR_TEST: &str = r##"
rule EICAR_Test {
    meta:
        description = "EICAR antivirus test file"
        severity = "info"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"##;

/// macOS-specific malware detection rules.
pub const RULES_MACOS_MALWARE: &str = r##"
rule Atomic_Stealer_AMOS {
    meta:
        description = "Atomic Stealer (AMOS) macOS credential theft malware"
        severity = "critical"
        reference = "https://www.sentinelone.com/blog/atomic-stealer-threat-actor-spawns-new-variant/"
    strings:
        $osascript_password = "osascript" ascii
        $dialog_password = "display dialog" ascii
        $keychain = "security find-generic-password" ascii
        $crypto_wallet = "Exodus" ascii
        $steal_cookies = "Cookies/Cookies.binarycookies" ascii
        $apple_script_admin = "with administrator privileges" ascii
        $login_keychain = "login.keychain" ascii
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe or
        (3 of ($osascript_password, $dialog_password, $keychain, $apple_script_admin, $login_keychain) and
         1 of ($crypto_wallet, $steal_cookies))
}

rule AdLoad_Adware {
    meta:
        description = "AdLoad adware/bundleware for macOS"
        severity = "high"
        reference = "https://www.sentinelone.com/blog/adload-malware-will-that-be-a-ppc-intel-or-apple-silicon/"
    strings:
        $bundleid1 = "com.machelper" ascii
        $bundleid2 = "com.AdLoader" ascii
        $bundleid3 = "com.SearchDaemon" ascii
        $persistence_la = "Library/LaunchAgents" ascii
        $persistence_ld = "Library/LaunchDaemons" ascii
        $sysctl_hw = "sysctl hw.model" ascii
        $curl_download = "curl -o" ascii
        $hidden_dir = "/var/root/." ascii
    condition:
        2 of them
}

rule Silver_Sparrow {
    meta:
        description = "Silver Sparrow macOS malware"
        severity = "critical"
        reference = "https://redcanary.com/blog/silver-sparrow/"
    strings:
        $marker = "._insu" ascii
        $lib_update = "~/Library/Application Support/agent_updater" ascii
        $plist_label = "init_agent" ascii
        $s3_bucket = ".s3.amazonaws.com" ascii
        $version_check = "api.github.com" ascii
        $js_exec = "verx" ascii
        $macho_arm = {cf fa ed fe}
    condition:
        ($marker and 1 of ($lib_update, $plist_label, $s3_bucket)) or
        (3 of them)
}

rule XCSSET_Malware {
    meta:
        description = "XCSSET malicious Xcode project infection"
        severity = "critical"
        reference = "https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware.html"
    strings:
        $xcworkspace = ".xcworkspace" ascii
        $build_phase = "PBXShellScriptBuildPhase" ascii
        $payload_url = "adobestats.com" ascii
        $replicator = "xcassets" ascii
        $module_safari = "safari_remote" ascii
        $module_notes = "notes_remote" ascii
        $eval_payload = "eval(decodeURIComponent" ascii
    condition:
        ($xcworkspace and $build_phase and 1 of ($payload_url, $eval_payload)) or
        (3 of ($module_safari, $module_notes, $replicator, $payload_url))
}

rule Bundlore_Adware {
    meta:
        description = "Bundlore macOS adware family"
        severity = "medium"
        reference = "https://www.sentinelone.com/blog/bundlore-macos-malware/"
    strings:
        $installer_pkg = "Bundlore" ascii nocase
        $search_baron = "searchbaron" ascii nocase
        $search_marquis = "searchmarquis" ascii nocase
        $safe_finder = "safefinder" ascii nocase
        $weknow = "weknow.ac" ascii
        $chumsearch = "chumsearch" ascii
        $browser_ext = "Contents/MacOS/applet" ascii
    condition:
        2 of them
}

rule MacOS_Suspicious_MachO {
    meta:
        description = "Suspicious unsigned Mach-O with unusual capabilities"
        severity = "medium"
    strings:
        $entitlement_camera = "com.apple.security.device.camera" ascii
        $entitlement_mic = "com.apple.security.device.microphone" ascii
        $entitlement_location = "com.apple.security.personal-information.location" ascii
        $entitlement_contacts = "com.apple.security.personal-information.addressbook" ascii
        $entitlement_keychain = "com.apple.security.keychain-access-groups" ascii
    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or
         uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and
        (2 of ($entitlement_camera, $entitlement_mic, $entitlement_location,
               $entitlement_contacts, $entitlement_keychain))
}

rule MacOS_Persistence_LaunchAgent {
    meta:
        description = "Suspicious LaunchAgent plist for persistence"
        severity = "medium"
    strings:
        $plist_header = "<?xml" ascii
        $plist_key_label = "<key>Label</key>" ascii
        $plist_key_program = "<key>ProgramArguments</key>" ascii
        $run_at_load = "<key>RunAtLoad</key>" ascii
        $keep_alive = "<key>KeepAlive</key>" ascii
        $hidden_path = "/." ascii
        $tmp_exec = "/tmp/" ascii
        $var_exec = "/var/tmp/" ascii
    condition:
        $plist_header and $plist_key_label and $plist_key_program and
        ($run_at_load or $keep_alive) and
        1 of ($hidden_path, $tmp_exec, $var_exec)
}

rule MacOS_Backdoor_Generic {
    meta:
        description = "Generic macOS backdoor indicators"
        severity = "high"
    strings:
        $screen_capture = "CGWindowListCreateImage" ascii
        $keylogger = "CGEventTapCreate" ascii
        $webcam = "AVCaptureSession" ascii
        $exfil_curl = "curl -X POST" ascii
        $exfil_http = "NSURLSession" ascii
    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or
         uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and
        2 of ($screen_capture, $keylogger, $webcam) and
        1 of ($exfil_curl, $exfil_http)
}
"##;

/// Suspicious shell script detection rules.
pub const RULES_SUSPICIOUS_SCRIPTS: &str = r##"
rule Suspicious_Shell_Base64_Exec {
    meta:
        description = "Shell script with base64-encoded payload execution"
        severity = "high"
    strings:
        $shebang_bash = "#!/bin/bash" ascii
        $shebang_sh = "#!/bin/sh" ascii
        $shebang_zsh = "#!/bin/zsh" ascii
        $base64_decode1 = "base64 -d" ascii
        $base64_decode2 = "base64 --decode" ascii
        $base64_decode3 = "openssl base64 -d" ascii
        $pipe_exec1 = "| bash" ascii
        $pipe_exec2 = "| sh" ascii
        $pipe_exec3 = "| /bin/bash" ascii
        $pipe_exec4 = "| /bin/sh" ascii
        $eval_exec = "eval " ascii
    condition:
        1 of ($shebang_bash, $shebang_sh, $shebang_zsh) and
        1 of ($base64_decode1, $base64_decode2, $base64_decode3) and
        1 of ($pipe_exec1, $pipe_exec2, $pipe_exec3, $pipe_exec4, $eval_exec)
}

rule Suspicious_Curl_Pipe_Bash {
    meta:
        description = "Curl piped to shell execution (download-and-execute)"
        severity = "high"
    strings:
        $curl_bash1 = "curl" ascii
        $curl_bash2 = "wget" ascii
        $pipe_sh1 = "| bash" ascii
        $pipe_sh2 = "| sh" ascii
        $pipe_sh3 = "| /bin/bash" ascii
        $pipe_sh4 = "| /bin/sh" ascii
        $pipe_sh5 = "| sudo bash" ascii
        $pipe_sh6 = "| sudo sh" ascii
    condition:
        1 of ($curl_bash1, $curl_bash2) and
        1 of ($pipe_sh1, $pipe_sh2, $pipe_sh3, $pipe_sh4, $pipe_sh5, $pipe_sh6)
}

rule Suspicious_Script_Obfuscation {
    meta:
        description = "Script with heavy obfuscation patterns"
        severity = "medium"
    strings:
        $eval_base64 = /eval\s*\(\s*(atob|Buffer\.from|base64)/ ascii
        $char_code = "String.fromCharCode" ascii
        $hex_decode = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/ ascii
        $python_exec = "exec(compile(" ascii
        $perl_eval = /eval\s+pack\s*\(/ ascii
        $rev_string = "rev | " ascii
        $xxd_decode = "xxd -r" ascii
    condition:
        2 of them
}

rule Suspicious_Shell_Cleanup {
    meta:
        description = "Shell script with anti-forensics cleanup commands"
        severity = "high"
    strings:
        $rm_logs = "rm -rf /var/log" ascii
        $rm_history = "history -c" ascii
        $rm_bash_history = "rm ~/.bash_history" ascii
        $rm_zsh_history = "rm ~/.zsh_history" ascii
        $unset_histfile = "unset HISTFILE" ascii
        $shred_cmd = "shred -u" ascii
        $touch_timestamps = "touch -t" ascii
    condition:
        2 of them
}
"##;

/// Reverse shell detection rules.
pub const RULES_REVERSE_SHELLS: &str = r##"
rule Reverse_Shell_Bash {
    meta:
        description = "Bash reverse shell one-liner"
        severity = "critical"
    strings:
        $bash_i = "bash -i >& /dev/tcp/" ascii
        $bash_i2 = "bash -i >&/dev/tcp/" ascii
        $bash_196 = "/bin/bash -l > /dev/tcp/" ascii
        $bash_udp = "bash -i >& /dev/udp/" ascii
    condition:
        any of them
}

rule Reverse_Shell_Netcat {
    meta:
        description = "Netcat reverse shell"
        severity = "critical"
    strings:
        $nc_e = /nc\s+-e\s+\/bin\/(ba)?sh/ ascii
        $ncat_e = /ncat\s+-e\s+\/bin\/(ba)?sh/ ascii
        $nc_c = /nc\s+-c\s+\/bin\/(ba)?sh/ ascii
        $netcat_e = /netcat\s+-e\s+\/bin\/(ba)?sh/ ascii
    condition:
        any of them
}

rule Reverse_Shell_Python {
    meta:
        description = "Python reverse shell"
        severity = "critical"
    strings:
        $pty_spawn = "pty.spawn" ascii
        $socket_connect = "socket.socket" ascii
        $subprocess_call = "subprocess.call" ascii
        $os_dup2 = "os.dup2" ascii
        $python_revshell = "import socket,subprocess,os" ascii
    condition:
        ($pty_spawn and $socket_connect) or
        ($os_dup2 and $socket_connect and $subprocess_call) or
        $python_revshell
}

rule Reverse_Shell_Perl {
    meta:
        description = "Perl reverse shell"
        severity = "critical"
    strings:
        $perl_socket = "use Socket" ascii
        $perl_exec = "exec(\"/bin/sh" ascii
        $perl_revshell = /perl\s+-e\s+'use\s+Socket/ ascii
    condition:
        ($perl_socket and $perl_exec) or
        $perl_revshell
}

rule Reverse_Shell_Ruby {
    meta:
        description = "Ruby reverse shell"
        severity = "critical"
    strings:
        $ruby_tcp = "TCPSocket.new" ascii
        $ruby_open = "TCPSocket.open" ascii
        $ruby_exec = "exec sprintf(\"/bin/sh" ascii
    condition:
        1 of ($ruby_tcp, $ruby_open) and $ruby_exec
}
"##;

/// Encoded payload and cryptominer detection rules.
pub const RULES_ENCODED_AND_MINERS: &str = r##"
rule Encoded_Payload_Long_Base64 {
    meta:
        description = "Long base64-encoded payload likely containing executable code"
        severity = "medium"
    strings:
        $long_b64 = /[A-Za-z0-9+\/]{500,}={0,2}/ ascii
        $decode_exec1 = "base64 -d" ascii
        $decode_exec2 = "base64 --decode" ascii
        $decode_exec3 = "atob(" ascii
        $decode_exec4 = "b64decode" ascii
    condition:
        $long_b64 and 1 of ($decode_exec1, $decode_exec2, $decode_exec3, $decode_exec4)
}

rule Cryptominer_Stratum {
    meta:
        description = "Cryptocurrency mining software using stratum protocol"
        severity = "high"
    strings:
        $stratum1 = "stratum+tcp://" ascii nocase
        $stratum2 = "stratum+ssl://" ascii nocase
        $stratum3 = "stratum2+tcp://" ascii nocase
        $mining_method1 = "mining.subscribe" ascii
        $mining_method2 = "mining.authorize" ascii
        $mining_method3 = "mining.submit" ascii
    condition:
        1 of ($stratum1, $stratum2, $stratum3) or
        2 of ($mining_method1, $mining_method2, $mining_method3)
}

rule Cryptominer_XMRig {
    meta:
        description = "XMRig Monero cryptocurrency miner"
        severity = "high"
    strings:
        $xmrig1 = "xmrig" ascii nocase
        $xmrig2 = "XMRig" ascii
        $monero_addr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        $algo_cn = "cryptonight" ascii nocase
        $algo_rx = "randomx" ascii nocase
        $pool_config = "\"pool\"" ascii
        $donate_level = "donate-level" ascii
    condition:
        1 of ($xmrig1, $xmrig2) or
        ($monero_addr and 1 of ($algo_cn, $algo_rx, $pool_config, $donate_level))
}

rule Cryptominer_Generic {
    meta:
        description = "Generic cryptocurrency mining indicators"
        severity = "medium"
    strings:
        $hashrate = "hashrate" ascii nocase
        $worker_id = "worker_id" ascii
        $nonce = "\"nonce\"" ascii
        $difficulty = "\"difficulty\"" ascii
        $block_header = "block_header" ascii
        $pool_url = /pool\.(minergate|nanopool|f2pool|supportxmr|hashvault)/ ascii nocase
    condition:
        $pool_url or (3 of ($hashrate, $worker_id, $nonce, $difficulty, $block_header))
}
"##;

/// Generic threat pattern rules.
pub const RULES_GENERIC_THREATS: &str = r##"
rule Suspicious_Keylogger_macOS {
    meta:
        description = "macOS keylogger using Carbon or Cocoa event taps"
        severity = "high"
    strings:
        $event_tap = "CGEventTapCreate" ascii
        $event_mask = "kCGEventKeyDown" ascii
        $event_mask2 = "CGEventMaskBit" ascii
        $run_loop = "CFRunLoop" ascii
        $log_keys = /key(log|stroke|press)/i ascii
    condition:
        ($event_tap and 1 of ($event_mask, $event_mask2) and $run_loop) or
        ($event_tap and $log_keys)
}

rule Suspicious_Credential_Access {
    meta:
        description = "Attempts to access macOS Keychain or saved credentials"
        severity = "high"
    strings:
        $security_cmd = "security find" ascii
        $keychain_dump = "security dump-keychain" ascii
        $keychain_unlock = "security unlock-keychain" ascii
        $safari_passwords = "Safari/Passwords" ascii
        $chrome_login = "Chrome/Default/Login Data" ascii
        $firefox_logins = "logins.json" ascii
        $cookie_steal = "Cookies.binarycookies" ascii
    condition:
        2 of them
}

rule Suspicious_Data_Staging {
    meta:
        description = "Data collection and staging for exfiltration"
        severity = "medium"
    strings:
        $tar_create = "tar -czf" ascii
        $tar_create2 = "tar czf" ascii
        $zip_create = "zip -r" ascii
        $ditto_cmd = "ditto -c" ascii
        $find_docs = /find\s+.*\.(doc|pdf|xls|key|ppt|csv)/ ascii
        $tmp_staging = "/tmp/" ascii
        $var_staging = "/var/tmp/" ascii
        $curl_upload = "curl -F" ascii
        $curl_post = "curl -X POST" ascii
    condition:
        1 of ($tar_create, $tar_create2, $zip_create, $ditto_cmd) and
        1 of ($find_docs, $tmp_staging, $var_staging) and
        1 of ($curl_upload, $curl_post)
}

rule Webshell_Generic {
    meta:
        description = "Generic web shell indicators"
        severity = "critical"
    strings:
        $php_eval = "eval($_" ascii
        $php_system = "system($_" ascii
        $php_exec = "exec($_" ascii
        $php_passthru = "passthru($_" ascii
        $php_shell = "shell_exec($_" ascii
        $php_base64_eval = /eval\s*\(\s*base64_decode\s*\(/ ascii
        $jsp_runtime = "Runtime.getRuntime().exec" ascii
        $asp_eval = "eval(Request" ascii
    condition:
        any of them
}

rule Suspicious_Env_Harvesting {
    meta:
        description = "Harvesting environment variables and system info"
        severity = "low"
    strings:
        $env_dump = "printenv" ascii
        $env_all = "env | " ascii
        $sw_vers = "sw_vers" ascii
        $system_profiler = "system_profiler" ascii
        $ifconfig = "ifconfig" ascii
        $whoami = "whoami" ascii
        $uname = "uname -a" ascii
    condition:
        4 of them
}
"##;

/// Returns all YARA rule sources concatenated for compilation.
pub fn all_rules() -> String {
    [
        RULE_EICAR_TEST,
        RULES_MACOS_MALWARE,
        RULES_SUSPICIOUS_SCRIPTS,
        RULES_REVERSE_SHELLS,
        RULES_ENCODED_AND_MINERS,
        RULES_GENERIC_THREATS,
    ]
    .join("\n")
}

/// Memory-specific YARA rules for process memory scanning.
///
/// These rules target fileless malware indicators found in process artifacts:
/// command lines, environment variables, open file descriptors, and loaded
/// libraries. They are compiled separately from file-scanning rules to avoid
/// false positives from Mach-O header checks.
pub fn memory_scan_rules() -> String {
    r#"
rule Memory_Credential_Stealing {
    meta:
        description = "Credential stealing patterns in process memory"
        severity = "critical"
    strings:
        $chrome_cookies = "Cookies/Cookies" ascii
        $chrome_login = "Login Data" ascii
        $keychain_dump = "security dump-keychain" ascii
        $keychain_find = "security find-generic-password" ascii
        $safari_cookies = "Cookies.binarycookies" ascii
    condition:
        2 of them
}

rule Memory_C2_Communication {
    meta:
        description = "C2 communication patterns in process memory"
        severity = "high"
    strings:
        $beacon = "beacon" ascii nocase
        $c2_post = "POST /api/checkin" ascii
        $c2_agent = "user-agent: Mozilla" ascii
        $cobalt = "sleeptime" ascii
        $sliver = "implant" ascii
    condition:
        2 of them
}

rule Memory_Crypto_Wallet_Theft {
    meta:
        description = "Cryptocurrency wallet theft patterns in process memory"
        severity = "critical"
    strings:
        $electrum = "electrum/wallets" ascii nocase
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $ledger = "Ledger Live" ascii
        $exodus = "exodus/exodus.wallet" ascii
        $bitcoin = "wallet.dat" ascii
    condition:
        2 of them
}

rule Memory_AMOS_Stealer {
    meta:
        description = "Atomic macOS Stealer (AMOS) memory patterns"
        severity = "critical"
    strings:
        $amos1 = "osascript -e" ascii
        $amos2 = "AppleScript" ascii
        $amos3 = "display dialog" ascii
        $amos4 = "default answer" ascii
        $steal = "/Users/" ascii
    condition:
        3 of ($amos*) and $steal
}

rule Memory_Dylib_Injection {
    meta:
        description = "Dynamic library injection indicators in process memory"
        severity = "high"
    strings:
        $dyld_insert = "DYLD_INSERT_LIBRARIES" ascii
        $dyld_force = "DYLD_FORCE_FLAT_NAMESPACE" ascii
        $inject_lib = "inject.dylib" ascii
        $interpose = "__interpose" ascii
        $dylib_hijack = "DYLD_LIBRARY_PATH" ascii
    condition:
        2 of them
}

rule Memory_Shell_Spawner {
    meta:
        description = "Process spawning reverse shell or interactive shell"
        severity = "critical"
    strings:
        $bash_tcp = "/dev/tcp/" ascii
        $bash_udp = "/dev/udp/" ascii
        $nc_shell = "nc -e /bin/" ascii
        $python_pty = "pty.spawn" ascii
        $perl_socket = "use Socket" ascii
        $ruby_tcp = "TCPSocket" ascii
    condition:
        any of them
}

rule Memory_Persistence_Install {
    meta:
        description = "Process installing persistence mechanisms"
        severity = "high"
    strings:
        $launch_agent = "Library/LaunchAgents" ascii
        $launch_daemon = "Library/LaunchDaemons" ascii
        $cron_write = "crontab -" ascii
        $login_item = "LSSharedFileList" ascii
        $plist_write = "RunAtLoad" ascii
    condition:
        2 of them
}
"#
    .to_string()
}
