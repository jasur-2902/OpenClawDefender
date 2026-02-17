# Guard REST API Guide

The ClawDefender daemon exposes a REST API at `http://127.0.0.1:3202` for managing agent guards programmatically. All endpoints (except the OpenAPI spec) require Bearer token authentication.

## Authentication

Every request must include a Bearer token in the `Authorization` header:

```
Authorization: Bearer <token>
```

The token is generated when the daemon starts and is stored at `~/.local/share/clawdefender/api-token`. The Python and TypeScript packages read this file automatically.

## Endpoints

### Create a guard

```
POST /api/v1/guards
```

Register a new guard for an agent.

**Request body:**

```json
{
  "agent_name": "my-bot",
  "pid": 12345,
  "permissions": {
    "file_read": ["~/workspace/**"],
    "file_write": ["~/workspace/output/**"],
    "file_delete": [],
    "shell_policy": "deny",
    "network_allowlist": ["api.anthropic.com"],
    "tools": ["read_file", "write_file"]
  },
  "mode": "enforce"
}
```

**Response (201 Created):**

```json
{
  "guard_id": "guard_a1b2c3d4e5f6",
  "rules_generated": 5,
  "status": "active"
}
```

**curl example:**

```bash
TOKEN=$(cat ~/.local/share/clawdefender/api-token)
curl -s -X POST http://127.0.0.1:3202/api/v1/guards \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "my-bot",
    "pid": '$$',
    "permissions": {
      "file_read": ["~/workspace/**"],
      "shell_policy": "deny",
      "network_allowlist": ["api.anthropic.com"],
      "tools": ["read_file"]
    },
    "mode": "enforce"
  }'
```

### List guards

```
GET /api/v1/guards
```

List all active guards.

**Response (200 OK):**

```json
{
  "guards": [
    {
      "guard_id": "guard_a1b2c3d4e5f6",
      "agent_name": "my-bot",
      "pid": 12345,
      "mode": "enforce",
      "status": "active",
      "created_at": "2025-01-15T10:30:00Z",
      "checks_total": 42
    }
  ]
}
```

**curl example:**

```bash
curl -s http://127.0.0.1:3202/api/v1/guards \
  -H "Authorization: Bearer $TOKEN"
```

### Get guard details

```
GET /api/v1/guards/:guard_id
```

**Response (200 OK):**

```json
{
  "guard_id": "guard_a1b2c3d4e5f6",
  "agent_name": "my-bot",
  "pid": 12345,
  "mode": "enforce",
  "status": "active",
  "created_at": "2025-01-15T10:30:00Z",
  "checks_total": 42,
  "checks_allowed": 38,
  "checks_blocked": 4
}
```

### Delete a guard

```
DELETE /api/v1/guards/:guard_id
```

Deregister a guard when the agent shuts down.

**Response (200 OK):**

```json
{
  "deleted": true
}
```

### Check an action

```
POST /api/v1/guards/:guard_id/check
```

Check whether an action is allowed by the guard's policy.

**Request body:**

```json
{
  "action": "file_read",
  "target": "/home/user/workspace/data.txt"
}
```

**Response (200 OK):**

```json
{
  "allowed": true,
  "reason": "Path '/home/user/workspace/data.txt' matches allowed patterns for 'file_read'",
  "rule": "guard_file_read_pattern"
}
```

**curl example:**

```bash
GUARD_ID="guard_a1b2c3d4e5f6"
curl -s -X POST "http://127.0.0.1:3202/api/v1/guards/$GUARD_ID/check" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "file_read", "target": "/home/user/workspace/data.txt"}'
```

### Get guard statistics

```
GET /api/v1/guards/:guard_id/stats
```

**Response (200 OK):**

```json
{
  "guard_id": "guard_a1b2c3d4e5f6",
  "checks_total": 42,
  "checks_allowed": 38,
  "checks_blocked": 4,
  "blocked_operations": [
    {
      "action": "file_read",
      "target": "/etc/passwd",
      "reason": "Path '/etc/passwd' does not match any allowed pattern for 'file_read'",
      "rule": "guard_file_read_pattern",
      "timestamp": "2025-01-15T10:35:00Z"
    }
  ],
  "policy_rules": [
    "guard_block_sensitive_paths",
    "guard_file_read_pattern",
    "guard_shell_policy",
    "guard_network_allowlist",
    "guard_tool_allowlist"
  ]
}
```

### Get permission suggestions

```
GET /api/v1/guards/:guard_id/suggest
```

For guards in monitor mode, returns suggested permissions based on observed operations.

**Response (200 OK):**

```json
{
  "suggestions": [
    {
      "action": "file_read",
      "suggested_pattern": "/home/user/extra-data/report.txt",
      "reason": "Operation 'file_read' on '/home/user/extra-data/report.txt' was blocked by rule 'guard_file_read_pattern'"
    }
  ]
}
```

### Register a webhook

```
POST /api/v1/guards/:guard_id/webhooks
```

Register a webhook to receive notifications when operations are blocked.

**Request body:**

```json
{
  "url": "http://127.0.0.1:8080/guard-events",
  "events": ["blocked", "anomaly"]
}
```

**Response (200 OK):**

```json
{
  "registered": true
}
```

**Webhook payload (POST to your URL):**

```json
{
  "guard_id": "guard_a1b2c3d4e5f6",
  "event": "blocked",
  "data": {
    "action": "shell",
    "target": "rm -rf /",
    "reason": "Shell execution is denied by policy",
    "rule": "guard_shell_policy",
    "timestamp": "2025-01-15T10:40:00Z"
  }
}
```

### Get webhooks

```
GET /api/v1/guards/:guard_id/webhooks
```

**Response (200 OK):**

```json
{
  "webhooks": [
    {
      "url": "http://127.0.0.1:8080/guard-events",
      "events": ["blocked", "anomaly"]
    }
  ]
}
```

### OpenAPI spec

```
GET /api/v1/openapi.yaml
```

Returns the OpenAPI 3.0 specification for the API. No authentication required.

### Health check

```
GET /api/v1/health
```

Returns daemon health status. No authentication required.

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "0.3.0",
  "guards_active": 2
}
```

## Error responses

All errors return JSON with an `error` field:

```json
{
  "error": "Guard not found"
}
```

Common status codes:
- `400` - Bad request (malformed JSON, missing fields)
- `401` - Unauthorized (missing or invalid token)
- `404` - Guard not found
- `500` - Internal server error

## Example integrations

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
)

func main() {
    token, _ := os.ReadFile(os.ExpandEnv("$HOME/.local/share/clawdefender/api-token"))

    body, _ := json.Marshal(map[string]interface{}{
        "agent_name": "go-bot",
        "pid":        os.Getpid(),
        "permissions": map[string]interface{}{
            "file_read":         []string{"~/workspace/**"},
            "shell_policy":      "deny",
            "network_allowlist": []string{"api.anthropic.com"},
            "tools":             []string{"read_file"},
        },
        "mode": "enforce",
    })

    req, _ := http.NewRequest("POST", "http://127.0.0.1:3202/api/v1/guards", bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Guard created: %v\n", result["guard_id"])
}
```

### Java

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;

public class GuardExample {
    public static void main(String[] args) throws Exception {
        String token = Files.readString(
            Path.of(System.getProperty("user.home"),
                     ".local/share/clawdefender/api-token")).strip();

        String body = """
            {
              "agent_name": "java-bot",
              "pid": %d,
              "permissions": {
                "file_read": ["~/workspace/**"],
                "shell_policy": "deny",
                "network_allowlist": ["api.anthropic.com"],
                "tools": ["read_file"]
              },
              "mode": "enforce"
            }
            """.formatted(ProcessHandle.current().pid());

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("http://127.0.0.1:3202/api/v1/guards"))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
            .send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println("Response: " + response.body());
    }
}
```

### Ruby

```ruby
require 'net/http'
require 'json'
require 'uri'

token = File.read(File.expand_path('~/.local/share/clawdefender/api-token')).strip

uri = URI('http://127.0.0.1:3202/api/v1/guards')
req = Net::HTTP::Post.new(uri)
req['Authorization'] = "Bearer #{token}"
req['Content-Type'] = 'application/json'
req.body = {
  agent_name: 'ruby-bot',
  pid: Process.pid,
  permissions: {
    file_read: ['~/workspace/**'],
    shell_policy: 'deny',
    network_allowlist: ['api.anthropic.com'],
    tools: ['read_file']
  },
  mode: 'enforce'
}.to_json

res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
puts "Guard created: #{JSON.parse(res.body)['guard_id']}"
```
