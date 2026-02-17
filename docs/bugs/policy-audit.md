# Policy & Audit Bug Report

## Summary

Found and fixed 4 bugs (2 Critical, 1 High, 1 Medium) in the policy engine, matcher, and policy templates. Added 13 new security regression tests.

---

## Bug 1: Symlink Bypass in Path Canonicalization (CRITICAL - FIXED)

**File:** `crates/clawdefender-core/src/policy/matcher.rs:128` (`canonicalize_path`)

**Description:** `canonicalize_path` resolved `.` and `..` segments logically but did NOT resolve symlinks. A symlink like `~/Projects/innocent.txt -> ~/.ssh/id_rsa` would pass through as `~/Projects/innocent.txt`, which does NOT match the SSH key block rule `~/.ssh/id_*`. This allowed a complete bypass of credential protection via symlinks.

**Fix:** Added `std::fs::canonicalize()` as the primary resolution path. When the file exists on disk, the OS resolves all symlinks to the real target path. The logical stack-based algorithm is used as a fallback when the file does not exist (e.g., during policy pattern validation).

**Regression test:** `test_symlink_to_ssh_key_resolves`

---

## Bug 2: Glob `*` Matched Across Directory Boundaries (CRITICAL - FIXED)

**File:** `crates/clawdefender-core/src/policy/matcher.rs:31` (`GlobMatcher::is_match`)

**Description:** The glob crate's `Pattern::matches()` method does NOT require literal path separators by default. This means `*` matches across directory boundaries, making it equivalent to `**`. A policy rule with `resource_path = ["~/tmp/*"]` would match `~/tmp/sub/dir/deep/file.txt`, which is too permissive for allow rules and confusing for policy authors.

**Fix:** Changed `is_match` to use `matches_with(value, MatchOptions { require_literal_separator: true, .. })`. Now `*` matches only within a single directory, while `**` still matches across directories.

**Regression test:** `test_glob_single_star_does_not_cross_directory`

---

## Bug 3: strict.toml Blocked ALL File Writes Including Project Writes (HIGH - FIXED)

**File:** `policies/templates/strict.toml`

**Description:** The `block_writes_outside_project` rule (priority 5) blocked ALL write tool calls (`write_file`, `create_file`, `edit_file`) regardless of target path. The `prompt_project_writes` rule (priority 20) was supposed to allow project writes, but:
1. It had a higher priority number (evaluated later), so the block rule matched first.
2. It required both `tool_name` AND `resource_path` to match, but MCP tool call events do not carry `resource_path` in their context, so the rule could NEVER match tool calls.

**Fix:** Removed the dead `prompt_project_writes` and `block_writes_outside_project` rules. Replaced with a single `prompt_file_writes` rule (priority 20) that prompts on all file write operations. In strict mode, the catch-all `prompt_all_other` (priority 500) handles everything else. Also added missing `message` field to `allow_list_operations`.

---

## Bug 4: strict.toml Missing `message` Field (MEDIUM - FIXED)

**File:** `policies/templates/strict.toml`, line 103

**Description:** The `allow_list_operations` rule was missing the `message` field. While serde defaults it to an empty string, this was inconsistent with all other rules in all templates.

**Fix:** Added `message = "List operation allowed"`.

---

## Verified (No Issues Found)

1. **Policy engine priority ordering:** Rules are sorted by priority (lower first) in `parse_policy_toml`. First-match-wins semantics work correctly.

2. **Reload error resilience:** When `reload()` encounters invalid TOML, `parse_policy_toml` returns `Err` before `self.file_rules` is reassigned (due to `?` operator). Old rules remain active. Verified with `test_reload_with_invalid_toml_preserves_old_rules`.

3. **Session rules:** Correctly inserted at position 0 (highest priority). Persist across `reload()` (file reloads only affect `file_rules`). Expire naturally on process restart since they're in-memory only.

4. **Permanent rules:** Correctly appended to TOML file on disk and added to in-memory `file_rules`. Survive restart via `reload()`.

5. **Null byte rejection:** `canonicalize_path` rejects paths with `\0`.

6. **Path traversal:** `../` segments are resolved before glob matching. Verified with `test_path_traversal_blocked`.

7. **Tilde expansion:** `~` is expanded to `$HOME` in both patterns and values. Gracefully handles missing `HOME` env var.

8. **ReDoS protection:** `RegexMatcher` uses `size_limit(256KB)` which prevents pathologically large patterns. The `regex` crate uses a finite automaton (no backtracking), so even `(a+)+b` is handled efficiently.

9. **Rate limiting:** Correctly enforces 10 prompts per 60s per server. Once blocked, stays blocked for the entire session even after window expiry. Unblock works.

10. **Audit log integrity:** JSON-lines format, ISO 8601 timestamps, session tracking, log rotation at configurable size, corrupt line skipping, concurrent write safety via channel-based async writer.

11. **10MB message size limit:** Enforced in `parser.rs:20`. Messages exceeding 10MB are rejected with a clear error.

12. **128-depth JSON limit:** Enforced via `exceeds_json_depth()` pre-parse check in `parser.rs:41`.

13. **Audit record fields:** Sensitive data (file contents, API keys) are not logged. Only paths, tool names, and metadata are recorded.

14. **All policy templates:** Parse successfully and contain correct rules. Verified with `test_all_policy_templates_parse_successfully`.

---

## New Security Regression Tests Added

File: `crates/clawdefender-core/tests/security_tests.rs`

1. `test_symlink_to_ssh_key_resolves` - Symlink resolution in canonicalize_path
2. `test_tilde_traversal_to_ssh_blocked` - `~/Projects/../../.ssh/test-key` blocked
3. `test_unicode_path_matching` - Unicode characters in paths
4. `test_very_long_path_handled` - 300+ char path components
5. `test_reload_with_invalid_toml_preserves_old_rules` - Error resilience
6. `test_all_policy_templates_parse_successfully` - Template validation
7. `test_default_policy_blocks_ssh_keys` - Default policy SSH protection
8. `test_default_policy_blocks_aws_credentials` - Default policy AWS protection
9. `test_glob_double_star_matches_deeply_nested` - `**` matches deep paths
10. `test_glob_single_star_does_not_cross_directory` - `*` stays in one dir
11. `test_glob_question_mark_matches_single_char` - `?` matches single char
12. `test_regex_substring_match_behavior` - Documents regex anchoring
13. `test_session_rules_cleared_on_reload` - Session rule persistence
