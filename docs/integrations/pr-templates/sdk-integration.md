## Summary

Adds ClawDefender SDK integration to this MCP server for security policy
enforcement and audit logging.

### Changes

- [ ] Added `clawdefender-sdk` / `@clawdefender/sdk` as a dependency
- [ ] Added `checkIntent` calls before all tool actions
- [ ] Added `requestPermission` calls before write/execute/delete operations
- [ ] Added `reportAction` calls after all tool actions
- [ ] Added graceful degradation when ClawDefender is unavailable
- [ ] Updated README with ClawDefender integration notes

### Compliance level

- [ ] Level 1 (Aware) -- checkIntent before actions
- [ ] Level 2 (Guarded) -- Level 1 + requestPermission before sensitive ops
- [ ] Level 3 (Certified) -- Level 2 + reportAction after all actions

### Testing

- [ ] Server works with ClawDefender running
- [ ] Server works without ClawDefender installed (fail-open)
- [ ] `clawdefender certify .` passes at the declared level
- [ ] Existing tests still pass

### Notes

<!-- Any additional context about the integration -->
