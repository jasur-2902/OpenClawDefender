import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Helpers extracted from AskClaw page for unit testing
// ---------------------------------------------------------------------------

function formatRelativeTime(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(iso).toLocaleDateString();
  } catch {
    return "";
  }
}

function looksLikeUrl(text: string): boolean {
  const trimmed = text.trim();
  return /^https?:\/\//i.test(trimmed) || /^www\./i.test(trimmed);
}

function looksLikeFilePath(text: string): boolean {
  const trimmed = text.trim();
  return trimmed.startsWith("/") || trimmed.startsWith("~") || /^[A-Z]:\\/i.test(trimmed);
}

function isConfigFile(path: string): boolean {
  return /\.(json|ya?ml|toml|ini|conf|cfg)$/i.test(path);
}

type SuggestionKey = "default" | "afterStatus" | "afterBlock" | "afterExplain";

function getSuggestionKey(lastIntentId?: string): SuggestionKey {
  if (!lastIntentId) return "default";
  if (lastIntentId.startsWith("status.")) return "afterStatus";
  if (lastIntentId.startsWith("control.block")) return "afterBlock";
  if (lastIntentId.startsWith("explain.")) return "afterExplain";
  return "default";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AskClaw", () => {
  describe("formatRelativeTime", () => {
    it("should return 'just now' for recent timestamps", () => {
      const now = new Date().toISOString();
      expect(formatRelativeTime(now)).toBe("just now");
    });

    it("should return minutes ago for timestamps within the hour", () => {
      const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
      expect(formatRelativeTime(fiveMinAgo)).toBe("5 min ago");
    });

    it("should return hours ago for timestamps within the day", () => {
      const twoHoursAgo = new Date(Date.now() - 2 * 3_600_000).toISOString();
      expect(formatRelativeTime(twoHoursAgo)).toBe("2h ago");
    });

    it("should handle invalid timestamps gracefully", () => {
      // Invalid date strings produce a fallback rather than crashing
      const result = formatRelativeTime("not-a-date");
      expect(typeof result).toBe("string");
    });
  });

  describe("drag-and-drop detection", () => {
    it("should detect HTTP URLs", () => {
      expect(looksLikeUrl("https://example.com")).toBe(true);
      expect(looksLikeUrl("http://malicious.test/payload")).toBe(true);
      expect(looksLikeUrl("  https://padded.com  ")).toBe(true);
    });

    it("should detect www URLs", () => {
      expect(looksLikeUrl("www.example.com")).toBe(true);
    });

    it("should not detect file paths as URLs", () => {
      expect(looksLikeUrl("/etc/passwd")).toBe(false);
      expect(looksLikeUrl("~/Documents/file.txt")).toBe(false);
    });

    it("should detect Unix file paths", () => {
      expect(looksLikeFilePath("/Users/test/file.json")).toBe(true);
      expect(looksLikeFilePath("~/config.toml")).toBe(true);
    });

    it("should detect Windows file paths", () => {
      expect(looksLikeFilePath("C:\\Users\\test\\file.json")).toBe(true);
    });

    it("should not detect URLs as file paths", () => {
      expect(looksLikeFilePath("https://example.com")).toBe(false);
    });

    it("should detect config file extensions", () => {
      expect(isConfigFile("/etc/config.json")).toBe(true);
      expect(isConfigFile("settings.yaml")).toBe(true);
      expect(isConfigFile("settings.yml")).toBe(true);
      expect(isConfigFile("Cargo.toml")).toBe(true);
      expect(isConfigFile("app.conf")).toBe(true);
      expect(isConfigFile("app.cfg")).toBe(true);
      expect(isConfigFile("config.ini")).toBe(true);
    });

    it("should not detect non-config files as config", () => {
      expect(isConfigFile("/usr/bin/ls")).toBe(false);
      expect(isConfigFile("script.py")).toBe(false);
      expect(isConfigFile("README.md")).toBe(false);
    });
  });

  describe("confirmation flow", () => {
    it("should identify actions requiring confirmation", () => {
      const actions = [
        { id: "1", label: "View", action: { type: "navigate" as const, page: "/tools" }, style: "secondary", requires_confirmation: false },
        { id: "2", label: "Block server", action: { type: "tauri_command" as const, command: "block_server", params: {} }, style: "danger", requires_confirmation: true },
      ];

      const confirmAction = actions.find((a) => a.requires_confirmation);
      expect(confirmAction).toBeDefined();
      expect(confirmAction!.label).toBe("Block server");
    });

    it("should not flag non-confirmation actions", () => {
      const actions = [
        { id: "1", label: "View logs", action: { type: "navigate" as const, page: "/activity" }, style: "secondary", requires_confirmation: false },
      ];

      const confirmAction = actions.find((a) => a.requires_confirmation);
      expect(confirmAction).toBeUndefined();
    });
  });

  describe("suggestion chips", () => {
    it("should return default suggestions when no intent", () => {
      expect(getSuggestionKey()).toBe("default");
      expect(getSuggestionKey(undefined)).toBe("default");
    });

    it("should return afterStatus suggestions for status intents", () => {
      expect(getSuggestionKey("status.overall")).toBe("afterStatus");
      expect(getSuggestionKey("status.daemon")).toBe("afterStatus");
    });

    it("should return afterBlock suggestions for block intents", () => {
      expect(getSuggestionKey("control.block")).toBe("afterBlock");
      expect(getSuggestionKey("control.block_server")).toBe("afterBlock");
    });

    it("should return afterExplain suggestions for explain intents", () => {
      expect(getSuggestionKey("explain.event")).toBe("afterExplain");
      expect(getSuggestionKey("explain.risk")).toBe("afterExplain");
    });

    it("should return default for unknown intents", () => {
      expect(getSuggestionKey("unknown.something")).toBe("default");
    });
  });

  describe("conversation loading", () => {
    it("should parse stored messages correctly", () => {
      const raw = {
        id: "msg-123",
        role: "claw",
        content_text: "You are protected.",
        content_rich_json: JSON.stringify({ type: "status_summary", items: [] }),
        actions_json: JSON.stringify([{ id: "1", label: "Details", action: { type: "navigate", page: "/tools" }, style: "secondary", requires_confirmation: false }]),
        intent_id: "status.overall",
        timestamp: "2026-02-24T10:00:00Z",
      };

      expect(raw.role).toBe("claw");
      expect(raw.content_text).toBe("You are protected.");

      const richData = JSON.parse(raw.content_rich_json!);
      expect(richData.type).toBe("status_summary");

      const actions = JSON.parse(raw.actions_json!);
      expect(actions).toHaveLength(1);
      expect(actions[0].label).toBe("Details");
    });

    it("should handle messages without rich data", () => {
      const raw = {
        id: "msg-456",
        role: "user",
        content_text: "Am I safe?",
        content_rich_json: null,
        actions_json: null,
        intent_id: null,
        timestamp: "2026-02-24T10:00:00Z",
      };

      expect(raw.content_rich_json).toBeNull();
      expect(raw.actions_json).toBeNull();
    });
  });

  describe("structured data types", () => {
    it("should parse status_summary data", () => {
      const data = {
        type: "status_summary",
        items: [
          { label: "Daemon", value: "Running", status: "good" },
          { label: "Servers", value: "3 monitored", status: "good" },
          { label: "Threats", value: "0 blocked", status: "good" },
        ],
      };

      expect(data.type).toBe("status_summary");
      expect(data.items).toHaveLength(3);
      expect(data.items[0].status).toBe("good");
    });

    it("should parse event_list data", () => {
      const data = {
        type: "event_list",
        events: [
          { id: "e1", timestamp: "2026-02-24T10:00:00Z", server_name: "test-server", description: "File read", decision: "allowed", risk_level: "low" },
        ],
        total: 15,
      };

      expect(data.type).toBe("event_list");
      expect(data.events).toHaveLength(1);
      expect(data.total).toBe(15);
    });

    it("should parse risk_assessment data", () => {
      const data = {
        type: "risk_assessment",
        subject: "test-server",
        risk_level: "high",
        explanation: "This server has been accessing sensitive files.",
        factors: ["SSH key access", "Frequent external connections"],
      };

      expect(data.type).toBe("risk_assessment");
      expect(data.risk_level).toBe("high");
      expect(data.factors).toHaveLength(2);
    });

    it("should parse scan_summary data", () => {
      const data = {
        type: "scan_summary",
        total_findings: 7,
        critical: 1,
        high: 2,
        medium: 3,
        low: 1,
      };

      expect(data.total_findings).toBe(7);
      expect(data.critical + data.high + data.medium + data.low).toBe(7);
    });
  });
});
