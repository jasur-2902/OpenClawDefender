# Claude Desktop Manual Test Procedures

## Prerequisites

- macOS with Claude Desktop installed
- ClawDefender built and in PATH: `cargo build --release`
- An MCP server configured in Claude Desktop (e.g. filesystem server)

## Test 1: Wrap command writes absolute path

**Steps:**
1. Run `clawdefender wrap <server-name> --client claude`
2. Open `~/Library/Application Support/Claude/claude_desktop_config.json`
3. Inspect the `"command"` field for the wrapped server

**Expected:**
- The `"command"` field contains an absolute path (e.g. `/Users/<you>/.cargo/bin/clawdefender`
  or `/opt/homebrew/bin/clawdefender`)
- NOT bare `"clawdefender"`

**Verify:**
```bash
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | python3 -c "
import json, sys
config = json.load(sys.stdin)
for name, srv in config.get('mcpServers', {}).items():
    cmd = srv.get('command', '')
    if 'clawdefender' in cmd:
        assert cmd.startswith('/'), f'FAIL: {name} has relative path: {cmd}'
        print(f'PASS: {name} -> {cmd}')
"
```

## Test 2: No stdout pollution

**Steps:**
1. Wrap a server with `clawdefender wrap <server-name>`
2. Restart Claude Desktop
3. Use the MCP server through Claude Desktop (trigger a tool call)

**Expected:**
- Claude Desktop connects successfully
- MCP tools work normally
- No "server disconnected" or parsing errors in Claude Desktop

**Debug method:**
```bash
# Run the proxy manually with logging enabled to verify stderr-only output
RUST_LOG=debug clawdefender proxy -- npx -y @modelcontextprotocol/server-filesystem ~/Projects 2>/tmp/proxy-stderr.log
# In another terminal, send a test message to stdin:
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | RUST_LOG=debug clawdefender proxy -- echo 2>/tmp/proxy-stderr.log > /tmp/proxy-stdout.log
# Verify stdout contains only JSON-RPC:
cat /tmp/proxy-stdout.log  # Should be empty or valid JSON only
cat /tmp/proxy-stderr.log  # Should contain tracing output
```

## Test 3: Double-wrap prevention

**Steps:**
1. Run `clawdefender wrap <server-name>` (first time)
2. Run `clawdefender wrap <server-name>` (second time)

**Expected:**
- Second wrap prints: `"<server>" is already wrapped by ClawDefender in Claude Desktop.`
- Config file is NOT modified the second time
- No duplicate nesting of proxy commands

## Test 4: Unwrap restores original config

**Steps:**
1. Note the original config for a server
2. Run `clawdefender wrap <server-name>`
3. Run `clawdefender unwrap <server-name>`
4. Compare the config to the original

**Expected:**
- `command` and `args` are restored to their original values
- `_clawdefender_original` key is removed
- Other fields (e.g. `env`) are preserved unchanged
- A `.json.bak` backup file exists

## Test 5: Wrap non-existent server

**Steps:**
1. Run `clawdefender wrap nonexistent-server`

**Expected:**
- Error message lists all available servers:
  ```
  Server "nonexistent-server" not found in Claude Desktop.

  Available servers:
    - filesystem-server
    - ...
  ```

## Test 6: Unwrap non-wrapped server

**Steps:**
1. Run `clawdefender unwrap <server-name>` on a server that was never wrapped

**Expected:**
- Prints: `This server is not wrapped by ClawDefender.`
- Config is NOT modified

## Test 7: Config backup creation

**Steps:**
1. Run `clawdefender wrap <server-name>`
2. Check for backup file

**Expected:**
- File `~/Library/Application Support/Claude/claude_desktop_config.json.bak` exists
- Backup contains the pre-wrap config

## Test 8: Proxy handles initialize immediately

**Steps:**
1. Start the proxy manually:
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' | \
     clawdefender proxy -- npx -y @modelcontextprotocol/server-filesystem ~/Projects
   ```

**Expected:**
- Proxy starts and forwards the initialize request to the server
- Server responds with capabilities
- No timeout or hang

## Test 9: Proxy handles notifications

**Steps:**
1. Send a notification (no `id` field) through the proxy:
   ```bash
   echo '{"jsonrpc":"2.0","method":"notifications/initialized"}' | \
     clawdefender proxy -- <server-command>
   ```

**Expected:**
- Notification is forwarded without error
- No error response generated (notifications have no `id`)

## Test 10: Proxy handles numeric and string IDs

**Steps:**
1. Send requests with different ID types:
   ```bash
   echo '{"jsonrpc":"2.0","id":42,"method":"tools/list"}'
   echo '{"jsonrpc":"2.0","id":"abc-123","method":"tools/list"}'
   ```

**Expected:**
- Both ID types are forwarded correctly
- Responses maintain the original ID type

## Test 11: Large response handling

**Steps:**
1. Use an MCP server that returns large responses (e.g. read a large file)
2. Verify the response is forwarded correctly

**Expected:**
- Responses up to 10 MB are forwarded
- Responses over 10 MB are rejected with a warning (not a crash)

## Test 12: Multiple proxy instances

**Steps:**
1. Wrap two different MCP servers
2. Restart Claude Desktop
3. Use both servers

**Expected:**
- Both proxy instances run independently
- One proxy crashing does not affect the other
- Each proxy has its own stdin/stdout streams

## Test 13: Proxy transparency (raw byte forwarding)

**Steps:**
1. Create a JSON-RPC message with specific key ordering:
   ```json
   {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test","arguments":{"z":1,"a":2}}}
   ```
2. Send through the proxy and capture what reaches the server

**Expected:**
- The forwarded message preserves the original key ordering (`"z"` before `"a"`)
- No whitespace or formatting changes
- Byte-for-byte identical to the input

## Test 14: Config preserves other fields

**Steps:**
1. Add custom fields to a server config (e.g. `"env"`, `"disabled"`)
2. Run `clawdefender wrap <server-name>`
3. Run `clawdefender unwrap <server-name>`

**Expected:**
- Custom fields are preserved through the wrap/unwrap cycle
- Only `command`, `args`, and `_clawdefender_original` are modified
