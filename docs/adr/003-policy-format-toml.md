# ADR-003: Policy Format — TOML

**Status:** Accepted

## Context

ClawDefender needs a format for users to define security policies (allow, deny, prompt rules for MCP tool calls). The format must be human-readable, machine-parseable, and appropriate for version control.

## Decision

We use TOML as the policy file format.

### Rationale

**Human-readable.** Policy files are security-critical configuration. Users must be able to read, understand, and audit their policies. TOML's syntax is immediately understandable without documentation.

**Easy to diff in git.** Security policies should be version-controlled and reviewed in PRs. TOML diffs cleanly — each rule is a distinct block, changes are localized, and there's no indentation ambiguity.

**Excellent Rust support.** The `toml` crate with `serde` derives makes parsing TOML into typed Rust structs trivial and type-safe.

**Structured enough for complex rules.** TOML tables and arrays of tables map naturally to a list of rules with nested conditions (tool patterns, argument matchers, server filters).

**Simple enough for beginners.** A user can write their first policy rule in 30 seconds:

```toml
[[rule]]
action = "deny"
tool = "shell_execute"
```

### Rejected alternatives

**YAML.** Indentation-sensitive syntax is error-prone for security configuration. A misplaced space can change semantics silently. YAML's type coercion (`yes` becomes a boolean) has caused real security bugs.

**JSON.** No comments. Policy files need comments explaining *why* a rule exists. JSON also requires trailing commas and quoting that makes manual editing tedious.

**Rego (OPA).** Powerful but complex. Rego is a purpose-built policy language with its own evaluation model. For ClawDefender's use case (pattern matching on tool names and arguments), Rego is overkill. It raises the barrier for users who just want to block a tool. We may offer Rego as an advanced option in the future.

**Custom DSL.** Maximum flexibility but requires building and maintaining a parser, language documentation, editor support, and debugging tools. Not justified for the current scope.

## Consequences

- Policy expressiveness is limited to what TOML's structure supports. Complex conditional logic (e.g., "allow this tool only if another tool was called first") is not representable. This is an acceptable trade-off — keep policies simple, handle complex logic in code.
- Users familiar with TOML from other Rust tools (Cargo.toml, rustfmt.toml) will feel at home.
- Migration to a more expressive format later would require a conversion tool, but the simple structure makes automated conversion feasible.
