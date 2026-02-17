## Summary

Adds a `clawdefender.toml` manifest to declare this server's security profile,
permissions, and tool risk levels.

### Changes

- [ ] Added `clawdefender.toml` to the repository root
- [ ] Declared all required permissions in `[permissions]`
- [ ] Listed all tools with risk levels in `[[tools]]`
- [ ] Set `compliance_level` matching actual SDK integration

### Manifest checklist

- [ ] `server_name` matches the MCP server name
- [ ] `server_version` matches the current release version
- [ ] `compliance_level` is accurate (1, 2, or 3)
- [ ] All file paths in `[permissions]` use glob patterns
- [ ] Every tool exposed by the server is listed in `[[tools]]`
- [ ] Risk levels are appropriate (Low/Medium/High/Critical)

### Validation

```bash
clawdefender certify .
```

- [ ] Certification passes at the declared level

### Notes

<!-- Any additional context about permission choices or risk assessments -->
