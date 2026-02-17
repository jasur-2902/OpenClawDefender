use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};

use crate::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use crate::modules::{ScanContext, ScanModule};

const FUZZ_SEED: u64 = 42;
const RANDOM_COMBOS_PER_TOOL: usize = 20;
const RAPID_FIRE_COUNT: usize = 100;
const CONCURRENT_CALLS: usize = 10;
const LARGE_PAYLOAD_SIZE: usize = 5 * 1024 * 1024; // 5MB

/// Variants for generating fuzzed strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringFuzzVariant {
    Empty,
    VeryLong,
    NullBytes,
    UnicodeEdgeCases,
    WhitespaceOnly,
    AnsiEscapes,
    NewlinesCarriageReturns,
}

/// Classification of a crash or hang discovered during fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashClass {
    ReproducibleCrash,
    NonDeterministicCrash,
    Hang,
    CrashUnderLoad,
    MemoryExhaustion,
    PoorErrorHandling,
}

impl CrashClass {
    pub fn severity(&self) -> Severity {
        match self {
            CrashClass::ReproducibleCrash => Severity::High,
            CrashClass::NonDeterministicCrash => Severity::Medium,
            CrashClass::Hang => Severity::Medium,
            CrashClass::CrashUnderLoad => Severity::Medium,
            CrashClass::MemoryExhaustion => Severity::Medium,
            CrashClass::PoorErrorHandling => Severity::High,
        }
    }

    pub fn cvss(&self) -> f64 {
        match self {
            CrashClass::ReproducibleCrash => 7.5,
            CrashClass::NonDeterministicCrash => 5.5,
            CrashClass::Hang => 5.3,
            CrashClass::CrashUnderLoad => 5.5,
            CrashClass::MemoryExhaustion => 5.0,
            CrashClass::PoorErrorHandling => 6.5,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            CrashClass::ReproducibleCrash => "Reproducible crash on specific input",
            CrashClass::NonDeterministicCrash => "Non-deterministic crash",
            CrashClass::Hang => "Server hang (no response)",
            CrashClass::CrashUnderLoad => "Crash under concurrent load",
            CrashClass::MemoryExhaustion => "Memory exhaustion (accepts huge input)",
            CrashClass::PoorErrorHandling => "Poor error handling on malformed input",
        }
    }
}

pub struct FuzzingModule;

impl FuzzingModule {
    pub fn new() -> Self {
        Self
    }
}

/// Generate a fuzzed string for the given variant.
pub fn generate_fuzzed_string(variant: StringFuzzVariant) -> String {
    match variant {
        StringFuzzVariant::Empty => String::new(),
        StringFuzzVariant::VeryLong => "A".repeat(1_000_000),
        StringFuzzVariant::NullBytes => "hello\x00world\x00\x00end".to_string(),
        StringFuzzVariant::UnicodeEdgeCases => {
            // Zero-width joiners, RTL override, various edge cases
            "\u{200D}\u{202E}\u{FEFF}\u{200B}\u{2066}\u{2069}test\u{0000}\u{FFFD}".to_string()
        }
        StringFuzzVariant::WhitespaceOnly => "   \t\t\n\n  \r\n  ".to_string(),
        StringFuzzVariant::AnsiEscapes => "\x1b[31mRED\x1b[0m\x1b[1;32mGREEN\x1b[0m".to_string(),
        StringFuzzVariant::NewlinesCarriageReturns => {
            "line1\nline2\rline3\r\nline4\n\n\nline5".to_string()
        }
    }
}

/// Generate a fuzzed JSON value for the given JSON schema type name.
pub fn generate_fuzzed_value_for_type(type_name: &str, rng: &mut StdRng) -> Value {
    match type_name {
        "string" => {
            let variants = [
                StringFuzzVariant::Empty,
                StringFuzzVariant::VeryLong,
                StringFuzzVariant::NullBytes,
                StringFuzzVariant::UnicodeEdgeCases,
                StringFuzzVariant::WhitespaceOnly,
                StringFuzzVariant::AnsiEscapes,
                StringFuzzVariant::NewlinesCarriageReturns,
            ];
            let idx = rng.gen_range(0..variants.len());
            Value::String(generate_fuzzed_string(variants[idx]))
        }
        "number" | "integer" => {
            let choices: Vec<Value> = vec![
                json!(0),
                json!(-1),
                json!(i64::MAX),
                json!(i64::MIN),
                Value::Null, // stand-in for NaN
                json!(1.7976931348623157e308_f64),
                json!(-1.7976931348623157e308_f64),
            ];
            let idx = rng.gen_range(0..choices.len());
            choices[idx].clone()
        }
        "boolean" => {
            let choices: Vec<Value> = vec![
                json!(0),
                json!(1),
                json!("true"),
                json!("false"),
                Value::Null,
            ];
            let idx = rng.gen_range(0..choices.len());
            choices[idx].clone()
        }
        "array" => {
            let variant = rng.gen_range(0..4);
            match variant {
                0 => json!([]),
                1 => {
                    // 10000 elements
                    Value::Array((0..10000).map(|i| json!(i)).collect())
                }
                2 => {
                    // Nested 100 deep
                    let mut val = json!("leaf");
                    for _ in 0..100 {
                        val = json!([val]);
                    }
                    val
                }
                _ => {
                    // Mixed types
                    json!([1, "two", true, null, 4.5, [], {"a": "b"}])
                }
            }
        }
        "object" => {
            let variant = rng.gen_range(0..4);
            match variant {
                0 => json!({}),
                1 => {
                    // 1000 keys
                    let mut map = serde_json::Map::new();
                    for i in 0..1000 {
                        map.insert(format!("key_{i}"), json!(i));
                    }
                    Value::Object(map)
                }
                2 => {
                    // Deeply nested
                    let mut val = json!("leaf");
                    for i in 0..100 {
                        let mut map = serde_json::Map::new();
                        map.insert(format!("level_{i}"), val);
                        val = Value::Object(map);
                    }
                    val
                }
                _ => {
                    // Very long keys
                    let mut map = serde_json::Map::new();
                    let long_key = "k".repeat(10000);
                    map.insert(long_key, json!("value"));
                    Value::Object(map)
                }
            }
        }
        _ => Value::Null,
    }
}

/// Generate random fuzzed arguments from a JSON schema, using a seeded RNG.
pub fn generate_random_args(schema: &Value, rng: &mut StdRng) -> Value {
    let properties = match schema.get("properties").and_then(|p| p.as_object()) {
        Some(props) => props,
        None => return json!({}),
    };

    let mut args = serde_json::Map::new();
    for (key, prop_schema) in properties {
        let type_name = prop_schema
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("string");
        args.insert(key.clone(), generate_fuzzed_value_for_type(type_name, rng));
    }
    Value::Object(args)
}

/// Returns a list of malformed JSON-RPC messages and their descriptions.
pub fn malformed_jsonrpc_messages() -> Vec<(String, &'static str)> {
    let mut messages = Vec::new();

    // Invalid JSON
    messages.push(("{not json}\n".to_string(), "Invalid JSON (not json)"));
    messages.push((
        "{\"jsonrpc\":\"2.0\",\n".to_string(),
        "Truncated JSON",
    ));

    // Valid JSON, invalid JSON-RPC
    messages.push((
        serde_json::to_string(&json!({"id": 9999, "method": "ping"})).unwrap() + "\n",
        "Missing jsonrpc field",
    ));
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": 9999})).unwrap() + "\n",
        "Missing method field",
    ));
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "1.0", "id": 9999, "method": "ping"})).unwrap()
            + "\n",
        "Wrong JSON-RPC version (1.0)",
    ));

    // Unexpected methods
    let long_method = "x".repeat(10240);
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": 9998, "method": long_method}))
            .unwrap()
            + "\n",
        "Very long method name (10KB)",
    ));
    messages.push((
        serde_json::to_string(
            &json!({"jsonrpc": "2.0", "id": 9997, "method": "foo\x00bar\n\rbaz"}),
        )
        .unwrap()
            + "\n",
        "Method with special characters",
    ));

    // Corrupted id fields
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": null, "method": "ping"})).unwrap()
            + "\n",
        "Null id",
    ));
    messages.push((
        serde_json::to_string(
            &json!({"jsonrpc": "2.0", "id": u64::MAX, "method": "ping"}),
        )
        .unwrap()
            + "\n",
        "Very large id (u64::MAX)",
    ));
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": -1, "method": "ping"})).unwrap()
            + "\n",
        "Negative id",
    ));
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": 1.5, "method": "ping"})).unwrap()
            + "\n",
        "Float id",
    ));
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": true, "method": "ping"})).unwrap()
            + "\n",
        "Boolean id",
    ));
    messages.push((
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": [1, 2], "method": "ping"}))
            .unwrap()
            + "\n",
        "Array id",
    ));
    messages.push((
        serde_json::to_string(
            &json!({"jsonrpc": "2.0", "id": {"nested": true}, "method": "ping"}),
        )
        .unwrap()
            + "\n",
        "Object id",
    ));

    messages
}

fn make_finding(
    id: &str,
    title: &str,
    crash_class: &CrashClass,
    description: &str,
    input_repr: &str,
    stderr: Option<String>,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        severity: crash_class.severity(),
        cvss: crash_class.cvss(),
        category: ModuleCategory::Fuzzing,
        description: description.to_string(),
        reproduction: Some(Reproduction {
            method: format!("Send the following fuzzed input: {}", truncate_for_display(input_repr, 500)),
            tool: None,
            arguments: None,
        }),
        evidence: Evidence {
            stderr_output: stderr,
            ..Evidence::empty()
        },
        remediation: "Validate and sanitize all inputs. Implement proper error handling for \
            malformed messages. Set resource limits to prevent memory exhaustion."
            .to_string(),
    }
}

fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... [truncated, total {} bytes]", &s[..max_len], s.len())
    }
}

async fn capture_stderr(ctx: &ScanContext) -> Option<String> {
    let stderr = ctx.server_stderr.lock().await;
    if stderr.is_empty() {
        None
    } else {
        Some(stderr.clone())
    }
}

#[async_trait]
impl ScanModule for FuzzingModule {
    fn name(&self) -> &str {
        "fuzzing"
    }

    fn description(&self) -> &str {
        "Fuzzes MCP protocol messages with malformed inputs"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Fuzzing
    }

    async fn run(&self, ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut finding_counter = 0u32;
        let mut next_id = || -> String {
            finding_counter += 1;
            format!("FUZZ-{finding_counter:03}")
        };

        // =============================================
        // 1. JSON-RPC protocol fuzzing
        // =============================================
        let messages = malformed_jsonrpc_messages();
        for (raw, desc) in &messages {
            if !ctx.client.is_running() {
                let stderr = capture_stderr(ctx).await;
                findings.push(make_finding(
                    &next_id(),
                    &format!("Server crashed before protocol fuzz: {desc}"),
                    &CrashClass::ReproducibleCrash,
                    "Server was not running when attempting to send malformed JSON-RPC message.",
                    raw,
                    stderr,
                ));
                break;
            }

            let send_result = ctx.client.send_raw_bytes(raw.as_bytes()).await;
            if send_result.is_err() {
                continue;
            }

            // Give server a moment to process
            tokio::time::sleep(Duration::from_millis(50)).await;

            if !ctx.client.is_running() {
                let stderr = capture_stderr(ctx).await;
                findings.push(make_finding(
                    &next_id(),
                    &format!("Server crashed on malformed JSON-RPC: {desc}"),
                    &CrashClass::PoorErrorHandling,
                    &format!(
                        "Server process terminated after receiving malformed message: {desc}. \
                         The server should handle protocol errors gracefully."
                    ),
                    raw,
                    stderr,
                ));
                // Server crashed, cannot continue protocol fuzzing
                break;
            }
        }

        // Rapid-fire: 100 valid requests
        if ctx.client.is_running() {
            for i in 0..RAPID_FIRE_COUNT {
                let msg = serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": 50000 + i,
                    "method": "ping"
                }))
                .unwrap()
                    + "\n";
                let _ = ctx.client.send_raw_bytes(msg.as_bytes()).await;
            }

            tokio::time::sleep(Duration::from_millis(500)).await;

            if !ctx.client.is_running() {
                let stderr = capture_stderr(ctx).await;
                findings.push(make_finding(
                    &next_id(),
                    "Server crashed under rapid-fire messages",
                    &CrashClass::CrashUnderLoad,
                    &format!(
                        "Server crashed after receiving {RAPID_FIRE_COUNT} rapid-fire JSON-RPC \
                         messages. The server should handle high message rates gracefully."
                    ),
                    &format!("{RAPID_FIRE_COUNT} rapid-fire ping messages"),
                    stderr,
                ));
            }
        }

        // =============================================
        // 2. Tool argument fuzzing
        // =============================================
        if ctx.client.is_running() && !ctx.tool_list.is_empty() {
            let mut rng = StdRng::seed_from_u64(FUZZ_SEED);
            let tools: Vec<_> = ctx.tool_list.clone();

            for tool in &tools {
                if !ctx.client.is_running() {
                    break;
                }

                // Generate RANDOM_COMBOS_PER_TOOL random fuzzed argument sets per tool
                for combo_idx in 0..RANDOM_COMBOS_PER_TOOL {
                    if !ctx.client.is_running() {
                        break;
                    }

                    let fuzzed_args = generate_random_args(&tool.input_schema, &mut rng);
                    let timeout_dur = Duration::from_secs(10);

                    let result = tokio::time::timeout(
                        timeout_dur,
                        ctx.client
                            .call_tool_raw(&tool.name, fuzzed_args.clone()),
                    )
                    .await;

                    match result {
                        Ok(Ok(_)) => {
                            // Tool handled it, no issue
                        }
                        Ok(Err(_)) => {
                            // Error returned, check if server is still running
                            if !ctx.client.is_running() {
                                let stderr = capture_stderr(ctx).await;
                                let input_repr =
                                    serde_json::to_string(&fuzzed_args).unwrap_or_default();
                                findings.push(make_finding(
                                    &next_id(),
                                    &format!(
                                        "Server crashed on fuzzed tool call: {} (combo {combo_idx})",
                                        tool.name
                                    ),
                                    &CrashClass::ReproducibleCrash,
                                    &format!(
                                        "Server crashed when tool '{}' received fuzzed arguments. \
                                         Tools should validate inputs and return errors, not crash.",
                                        tool.name
                                    ),
                                    &input_repr,
                                    stderr,
                                ));
                                break;
                            }
                        }
                        Err(_) => {
                            // Timeout - possible hang
                            if !ctx.client.is_running() {
                                let stderr = capture_stderr(ctx).await;
                                let input_repr =
                                    serde_json::to_string(&fuzzed_args).unwrap_or_default();
                                findings.push(make_finding(
                                    &next_id(),
                                    &format!(
                                        "Server hung on fuzzed tool call: {} (combo {combo_idx})",
                                        tool.name
                                    ),
                                    &CrashClass::Hang,
                                    &format!(
                                        "Server did not respond within {timeout_dur:?} when tool \
                                         '{}' received fuzzed arguments.",
                                        tool.name
                                    ),
                                    &input_repr,
                                    stderr,
                                ));
                            }
                            // Don't break; continue trying other combos
                        }
                    }
                }
            }
        }

        // =============================================
        // 3. Stress testing
        // =============================================
        if ctx.client.is_running() && !ctx.tool_list.is_empty() {
            // 3a. Concurrent tool calls
            let first_tool = ctx.tool_list[0].name.clone();

            // We cannot share &mut ScanContext across tasks, so we send rapid sequential calls
            // via raw bytes to simulate concurrency pressure.
            for i in 0..CONCURRENT_CALLS {
                let msg = serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": 60000 + i,
                    "method": "tools/call",
                    "params": {
                        "name": first_tool,
                        "arguments": {}
                    }
                }))
                .unwrap()
                    + "\n";
                let _ = ctx.client.send_raw_bytes(msg.as_bytes()).await;
            }

            // Wait for responses
            tokio::time::sleep(Duration::from_secs(5)).await;

            if !ctx.client.is_running() {
                let stderr = capture_stderr(ctx).await;
                findings.push(make_finding(
                    &next_id(),
                    "Server crashed under concurrent tool calls",
                    &CrashClass::CrashUnderLoad,
                    &format!(
                        "Server crashed after {CONCURRENT_CALLS} concurrent tool calls to '{}'. \
                         The server should handle concurrent requests gracefully.",
                        first_tool
                    ),
                    &format!("{CONCURRENT_CALLS} concurrent calls to {first_tool}"),
                    stderr,
                ));
            }

            // 3b. Memory probe: 5MB argument
            if ctx.client.is_running() {
                let large_arg = "X".repeat(LARGE_PAYLOAD_SIZE);
                let result = tokio::time::timeout(
                    Duration::from_secs(15),
                    ctx.client.call_tool_raw(
                        &first_tool,
                        json!({"data": large_arg}),
                    ),
                )
                .await;

                match result {
                    Ok(Ok(resp)) => {
                        // Server accepted it - that could be a memory exhaustion issue
                        // Only flag if the server actually processed it without error
                        if resp.get("result").is_some() {
                            findings.push(make_finding(
                                &next_id(),
                                "Server accepts very large payload without rejection",
                                &CrashClass::MemoryExhaustion,
                                &format!(
                                    "Server accepted a {}MB payload for tool '{}' without \
                                     rejecting it. Servers should enforce payload size limits.",
                                    LARGE_PAYLOAD_SIZE / (1024 * 1024),
                                    first_tool
                                ),
                                &format!("{}MB string argument", LARGE_PAYLOAD_SIZE / (1024 * 1024)),
                                None,
                            ));
                        }
                    }
                    Ok(Err(_)) => {
                        if !ctx.client.is_running() {
                            let stderr = capture_stderr(ctx).await;
                            findings.push(make_finding(
                                &next_id(),
                                "Server crashed on large payload",
                                &CrashClass::ReproducibleCrash,
                                &format!(
                                    "Server crashed when receiving a {}MB argument for tool '{}'.",
                                    LARGE_PAYLOAD_SIZE / (1024 * 1024),
                                    first_tool
                                ),
                                &format!("{}MB string argument", LARGE_PAYLOAD_SIZE / (1024 * 1024)),
                                stderr,
                            ));
                        }
                    }
                    Err(_) => {
                        // Timeout on large payload, not necessarily a finding
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_jsonrpc_messages_count() {
        let messages = malformed_jsonrpc_messages();
        // 2 invalid JSON + 3 invalid JSON-RPC + 2 unexpected methods + 7 corrupted ids = 14
        assert_eq!(messages.len(), 14);
        for (raw, desc) in &messages {
            assert!(!raw.is_empty(), "Message should not be empty for: {desc}");
            assert!(!desc.is_empty(), "Description should not be empty");
        }
    }

    #[test]
    fn test_generate_fuzzed_string_empty() {
        let s = generate_fuzzed_string(StringFuzzVariant::Empty);
        assert!(s.is_empty());
    }

    #[test]
    fn test_generate_fuzzed_string_very_long() {
        let s = generate_fuzzed_string(StringFuzzVariant::VeryLong);
        assert_eq!(s.len(), 1_000_000);
    }

    #[test]
    fn test_generate_fuzzed_string_null_bytes() {
        let s = generate_fuzzed_string(StringFuzzVariant::NullBytes);
        assert!(s.contains('\x00'));
    }

    #[test]
    fn test_generate_fuzzed_string_unicode() {
        let s = generate_fuzzed_string(StringFuzzVariant::UnicodeEdgeCases);
        assert!(s.contains('\u{200D}'));
        assert!(s.contains('\u{202E}'));
        // Ensure it's valid UTF-8 (it is, since it's a Rust String)
        assert!(s.len() > 0);
    }

    #[test]
    fn test_generate_fuzzed_string_whitespace() {
        let s = generate_fuzzed_string(StringFuzzVariant::WhitespaceOnly);
        assert!(s.trim().is_empty());
    }

    #[test]
    fn test_generate_fuzzed_string_ansi() {
        let s = generate_fuzzed_string(StringFuzzVariant::AnsiEscapes);
        assert!(s.contains('\x1b'));
    }

    #[test]
    fn test_generate_fuzzed_string_newlines() {
        let s = generate_fuzzed_string(StringFuzzVariant::NewlinesCarriageReturns);
        assert!(s.contains('\n'));
        assert!(s.contains('\r'));
    }

    #[test]
    fn test_generate_fuzzed_value_for_string() {
        let mut rng = StdRng::seed_from_u64(42);
        let val = generate_fuzzed_value_for_type("string", &mut rng);
        assert!(val.is_string() || val.is_null());
    }

    #[test]
    fn test_generate_fuzzed_value_for_number() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..20 {
            let val = generate_fuzzed_value_for_type("number", &mut rng);
            assert!(val.is_number() || val.is_null());
        }
    }

    #[test]
    fn test_generate_fuzzed_value_for_boolean() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..20 {
            let val = generate_fuzzed_value_for_type("boolean", &mut rng);
            // Could be 0, 1, "true", "false", or null
            assert!(
                val.is_number() || val.is_string() || val.is_null(),
                "Unexpected boolean fuzz value: {val}"
            );
        }
    }

    #[test]
    fn test_generate_fuzzed_value_for_array() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..10 {
            let val = generate_fuzzed_value_for_type("array", &mut rng);
            assert!(val.is_array());
        }
    }

    #[test]
    fn test_generate_fuzzed_value_for_object() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..10 {
            let val = generate_fuzzed_value_for_type("object", &mut rng);
            assert!(val.is_object());
        }
    }

    #[test]
    fn test_generate_random_args_with_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"}
            }
        });
        let mut rng = StdRng::seed_from_u64(42);
        let args = generate_random_args(&schema, &mut rng);
        let obj = args.as_object().unwrap();
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("count"));
        assert!(obj.contains_key("enabled"));
    }

    #[test]
    fn test_seeded_rng_reproducibility() {
        let mut rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(42);

        let schema = json!({
            "type": "object",
            "properties": {
                "x": {"type": "string"},
                "y": {"type": "number"}
            }
        });

        let args1 = generate_random_args(&schema, &mut rng1);
        let args2 = generate_random_args(&schema, &mut rng2);
        assert_eq!(args1, args2);
    }

    #[test]
    fn test_deeply_nested_json_generation() {
        let mut rng = StdRng::seed_from_u64(99);
        // Force the object variant that generates deeply nested structures
        // We test that it doesn't stack overflow and produces valid JSON
        for _ in 0..50 {
            let val = generate_fuzzed_value_for_type("object", &mut rng);
            // Just ensure it serializes without error
            let serialized = serde_json::to_string(&val).unwrap();
            assert!(!serialized.is_empty());
        }
    }

    #[test]
    fn test_crash_classification_severity() {
        assert_eq!(CrashClass::ReproducibleCrash.severity(), Severity::High);
        assert_eq!(CrashClass::NonDeterministicCrash.severity(), Severity::Medium);
        assert_eq!(CrashClass::Hang.severity(), Severity::Medium);
        assert_eq!(CrashClass::CrashUnderLoad.severity(), Severity::Medium);
        assert_eq!(CrashClass::MemoryExhaustion.severity(), Severity::Medium);
        assert_eq!(CrashClass::PoorErrorHandling.severity(), Severity::High);
    }

    #[test]
    fn test_crash_classification_cvss() {
        assert!((CrashClass::ReproducibleCrash.cvss() - 7.5).abs() < f64::EPSILON);
        assert!((CrashClass::CrashUnderLoad.cvss() - 5.5).abs() < f64::EPSILON);
        assert!((CrashClass::Hang.cvss() - 5.3).abs() < f64::EPSILON);
        assert!((CrashClass::MemoryExhaustion.cvss() - 5.0).abs() < f64::EPSILON);
        assert!((CrashClass::PoorErrorHandling.cvss() - 6.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_module_trait_implementation() {
        let module = FuzzingModule::new();
        assert_eq!(module.name(), "fuzzing");
        assert_eq!(module.category(), ModuleCategory::Fuzzing);
        assert!(!module.description().is_empty());
    }

    #[test]
    fn test_unicode_edge_case_strings_are_valid_utf8() {
        let s = generate_fuzzed_string(StringFuzzVariant::UnicodeEdgeCases);
        // Rust strings are always valid UTF-8, but verify the characters are correct
        assert!(s.contains('\u{200D}')); // zero-width joiner
        assert!(s.contains('\u{202E}')); // RTL override
        assert!(s.contains('\u{FEFF}')); // BOM
        assert!(s.contains('\u{200B}')); // zero-width space
        // Verify it round-trips through JSON
        let json_val = serde_json::to_string(&s).unwrap();
        let parsed: String = serde_json::from_str(&json_val).unwrap();
        // Note: null byte gets escaped in JSON, so compare after re-parsing
        assert!(parsed.contains('\u{200D}'));
    }

    #[test]
    fn test_generate_random_args_empty_schema() {
        let schema = json!({});
        let mut rng = StdRng::seed_from_u64(42);
        let args = generate_random_args(&schema, &mut rng);
        assert_eq!(args, json!({}));
    }

    #[test]
    fn test_rapid_fire_message_generation() {
        // Verify we can generate the rapid-fire messages without issue
        let mut messages = Vec::new();
        for i in 0..RAPID_FIRE_COUNT {
            let msg = serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": 50000 + i,
                "method": "ping"
            }))
            .unwrap();
            messages.push(msg);
        }
        assert_eq!(messages.len(), RAPID_FIRE_COUNT);
        // All should be valid JSON
        for msg in &messages {
            let parsed: Value = serde_json::from_str(msg).unwrap();
            assert_eq!(parsed["jsonrpc"], "2.0");
        }
    }
}
