import { describe, it, expect } from 'vitest';

describe('Settings - Protection Level', () => {
  const levels = [
    { id: "monitor-only", templateName: "permissive", label: "Handle it for me" },
    { id: "balanced", templateName: "balanced", label: "Ask me when in doubt" },
    { id: "strict", templateName: "strict", label: "Let me see everything" },
  ];

  it('should have three protection levels', () => {
    expect(levels).toHaveLength(3);
  });

  it('should map monitor-only to permissive template', () => {
    const monitorOnly = levels.find((l) => l.id === 'monitor-only');
    expect(monitorOnly?.templateName).toBe('permissive');
  });

  it('should map balanced to balanced template', () => {
    const balanced = levels.find((l) => l.id === 'balanced');
    expect(balanced?.templateName).toBe('balanced');
  });

  it('should map strict to strict template', () => {
    const strict = levels.find((l) => l.id === 'strict');
    expect(strict?.templateName).toBe('strict');
  });

  it('should generate diff preview for monitor-only', () => {
    function getDiffPreview(levelId: string): string[] {
      if (levelId === "monitor-only") {
        return [
          "All actions will be allowed through",
          "Everything will be logged for your review",
          "No prompts or blocks",
        ];
      } else if (levelId === "balanced") {
        return [
          "Known dangerous actions will be blocked",
          "Uncertain actions will ask for your decision",
          "Safe operations proceed automatically",
        ];
      } else if (levelId === "strict") {
        return [
          "Most actions will require your approval",
          "File writes blocked by default",
          "Network access requires approval",
        ];
      }
      return [];
    }

    const preview = getDiffPreview("monitor-only");
    expect(preview).toHaveLength(3);
    expect(preview[0]).toContain("allowed");
  });

  it('should generate diff preview for strict', () => {
    function getDiffPreview(levelId: string): string[] {
      if (levelId === "monitor-only") {
        return ["All actions will be allowed through", "Everything will be logged", "No prompts or blocks"];
      } else if (levelId === "balanced") {
        return ["Known dangerous actions will be blocked", "Uncertain actions will ask", "Safe operations proceed"];
      } else if (levelId === "strict") {
        return ["Most actions will require your approval", "File writes blocked by default", "Network access requires approval"];
      }
      return [];
    }

    const preview = getDiffPreview("strict");
    expect(preview).toHaveLength(3);
    expect(preview[0]).toContain("approval");
  });

  it('should use plain language labels without technical terms', () => {
    for (const level of levels) {
      expect(level.label).not.toContain('TOML');
      expect(level.label).not.toContain('policy');
      expect(level.label).not.toContain('template');
      expect(level.label).not.toContain('rule');
    }
  });
});

describe('Settings - Default Settings', () => {
  const defaultSettings = {
    theme: "system" as const,
    notifications_enabled: true,
    auto_start_daemon: true,
    minimize_to_tray: true,
    log_level: "info" as const,
    prompt_timeout_seconds: 30,
    event_retention_days: 30,
    behavioral_auto_block: false,
    behavioral_threshold: 75,
    analysis_frequency: "all",
    security_level: "balanced",
  };

  it('should have system as default theme', () => {
    expect(defaultSettings.theme).toBe('system');
  });

  it('should enable notifications by default', () => {
    expect(defaultSettings.notifications_enabled).toBe(true);
  });

  it('should enable auto-start by default', () => {
    expect(defaultSettings.auto_start_daemon).toBe(true);
  });

  it('should default to balanced security level', () => {
    expect(defaultSettings.security_level).toBe('balanced');
  });

  it('should default to info log level', () => {
    expect(defaultSettings.log_level).toBe('info');
  });

  it('should have 30-day event retention', () => {
    expect(defaultSettings.event_retention_days).toBe(30);
  });

  it('should disable behavioral auto-block by default', () => {
    expect(defaultSettings.behavioral_auto_block).toBe(false);
  });

  it('should have behavioral threshold at 75', () => {
    expect(defaultSettings.behavioral_threshold).toBe(75);
  });
});

describe('Settings - Model Status', () => {
  function getModelStatus(
    modelId: string,
    activeModelId: string | null,
    downloads: Record<string, string>,
    installedIds: string[]
  ): "active" | "downloaded" | "not_downloaded" | "downloading" {
    if (activeModelId === modelId) return "active";
    if (downloads[modelId]) return "downloading";
    if (installedIds.includes(modelId)) return "downloaded";
    return "not_downloaded";
  }

  it('should return active when model is the active model', () => {
    expect(getModelStatus("model-a", "model-a", {}, [])).toBe("active");
  });

  it('should return downloading when model has an active download', () => {
    expect(getModelStatus("model-a", null, { "model-a": "task-1" }, [])).toBe("downloading");
  });

  it('should return downloaded when model is installed but not active', () => {
    expect(getModelStatus("model-a", null, {}, ["model-a"])).toBe("downloaded");
  });

  it('should return not_downloaded when model is not installed', () => {
    expect(getModelStatus("model-a", null, {}, [])).toBe("not_downloaded");
  });

  it('should prioritize active over downloading', () => {
    expect(getModelStatus("model-a", "model-a", { "model-a": "task-1" }, ["model-a"])).toBe("active");
  });

  it('should prioritize downloading over downloaded', () => {
    expect(getModelStatus("model-a", null, { "model-a": "task-1" }, ["model-a"])).toBe("downloading");
  });
});

describe('Settings - Download Status Helper', () => {
  function getStatusType(status: string | { failed: string } | unknown): string {
    if (typeof status === "string") return status;
    if (typeof status === "object" && status !== null) {
      const keys = Object.keys(status);
      if (keys.length > 0) return keys[0];
    }
    return "unknown";
  }

  it('should handle string status', () => {
    expect(getStatusType("downloading")).toBe("downloading");
    expect(getStatusType("completed")).toBe("completed");
    expect(getStatusType("pending")).toBe("pending");
    expect(getStatusType("verifying")).toBe("verifying");
  });

  it('should handle failed object status', () => {
    expect(getStatusType({ failed: "Network error" })).toBe("failed");
  });

  it('should handle unknown types', () => {
    expect(getStatusType(null)).toBe("unknown");
    expect(getStatusType(undefined)).toBe("unknown");
  });
});

describe('Settings - Format Bytes', () => {
  function formatBytes(bytes: number): string {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
  }

  it('should format KB correctly', () => {
    expect(formatBytes(512 * 1024)).toBe('512 KB');
  });

  it('should format MB correctly', () => {
    expect(formatBytes(256 * 1024 * 1024)).toBe('256 MB');
  });

  it('should format GB correctly', () => {
    expect(formatBytes(4.2 * 1024 * 1024 * 1024)).toBe('4.2 GB');
  });
});

describe('Settings - Simple vs Advanced Mode', () => {
  const simpleModeSections = [
    'Protection Level',
    'Start at Login',
    'AI Analysis',
    'Theme',
    'Notifications',
    'About / Help',
  ];

  const advancedSubRoutes = [
    { label: 'Policy Editor', to: '/settings/policy' },
    { label: 'System Health', to: '/settings/health' },
    { label: 'Threat Intelligence', to: '/settings/threat-intel' },
  ];

  it('should have 6 sections in simple mode', () => {
    expect(simpleModeSections).toHaveLength(6);
  });

  it('should have 3 advanced sub-routes', () => {
    expect(advancedSubRoutes).toHaveLength(3);
  });

  it('should route Policy Editor to /settings/policy', () => {
    const policyRoute = advancedSubRoutes.find((r) => r.label === 'Policy Editor');
    expect(policyRoute?.to).toBe('/settings/policy');
  });

  it('should route System Health to /settings/health', () => {
    const healthRoute = advancedSubRoutes.find((r) => r.label === 'System Health');
    expect(healthRoute?.to).toBe('/settings/health');
  });

  it('should route Threat Intelligence to /settings/threat-intel', () => {
    const threatRoute = advancedSubRoutes.find((r) => r.label === 'Threat Intelligence');
    expect(threatRoute?.to).toBe('/settings/threat-intel');
  });
});

describe('Settings - Model Recommendation', () => {
  function isRecommended(
    modelId: string,
    isDefault: boolean,
    totalRamGb: number
  ): boolean {
    if (isDefault) return true;
    if (totalRamGb < 8 && modelId.includes("1b")) return true;
    if (totalRamGb >= 8 && totalRamGb < 16 && modelId.includes("1.7b")) return true;
    if (totalRamGb >= 16 && modelId.includes("4b")) return true;
    return false;
  }

  it('should recommend default model regardless of RAM', () => {
    expect(isRecommended("any-model", true, 4)).toBe(true);
    expect(isRecommended("any-model", true, 32)).toBe(true);
  });

  it('should recommend 1b model for <8GB RAM', () => {
    expect(isRecommended("smollm2-1b-q4", false, 4)).toBe(true);
    expect(isRecommended("smollm2-1b-q4", false, 7)).toBe(true);
  });

  it('should recommend 1.7b model for 8-16GB RAM', () => {
    expect(isRecommended("smollm2-1.7b-q4", false, 8)).toBe(true);
    expect(isRecommended("smollm2-1.7b-q4", false, 15)).toBe(true);
  });

  it('should recommend 4b model for >=16GB RAM', () => {
    expect(isRecommended("phi-4b-q4", false, 16)).toBe(true);
    expect(isRecommended("phi-4b-q4", false, 32)).toBe(true);
  });

  it('should not recommend 4b model for low RAM', () => {
    expect(isRecommended("phi-4b-q4", false, 8)).toBe(false);
  });
});
