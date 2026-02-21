import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Policy, PolicyRule } from "../types";
import { RuleEditorModal } from "../components/RuleEditorModal";
import { SecurityLevelChooser } from "../components/SecurityLevelChooser";
import { TemplateBrowser } from "../components/TemplateBrowser";

const actionConfig: Record<PolicyRule["action"], { icon: string; color: string; label: string }> = {
  deny: { icon: "\u2717", color: "var(--color-danger)", label: "Block" },
  prompt: { icon: "!", color: "var(--color-warning)", label: "Prompt" },
  allow: { icon: "\u2713", color: "var(--color-success)", label: "Allow" },
  audit: { icon: "\u270E", color: "var(--color-accent)", label: "Audit" },
};

export function PolicyEditor() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<PolicyRule | null>(null);
  const [levelOpen, setLevelOpen] = useState(false);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  function showFeedback(type: "success" | "error", message: string) {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 3000);
  }

  const loadPolicy = useCallback(async () => {
    try {
      const p = await invoke<Policy>("get_policy");
      setPolicy(p);
    } catch (_err) {
      setPolicy({
        name: "default",
        version: "1.0",
        rules: [
          { name: "Block file writes", description: "Prevent writing to sensitive files", action: "deny", resource: "*", pattern: "/etc/**", priority: 90, enabled: true },
          { name: "Prompt network access", description: "Ask before outbound connections", action: "prompt", resource: "*", pattern: "tcp://*", priority: 80, enabled: true },
          { name: "Allow read operations", description: "Safe read access is permitted", action: "allow", resource: "*", pattern: "read://**", priority: 50, enabled: true },
          { name: "Audit tool calls", description: "Log all tool invocations", action: "audit", resource: "*", pattern: "tool://**", priority: 30, enabled: true },
          { name: "Block env access", description: "Prevent access to environment files", action: "deny", resource: "*", pattern: "**/.env*", priority: 95, enabled: false },
        ],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicy();
  }, [loadPolicy]);

  function openNewRule() {
    setEditingRule(null);
    setEditorOpen(true);
  }

  function openEditRule(rule: PolicyRule) {
    setEditingRule(rule);
    setEditorOpen(true);
    setMenuOpen(null);
  }

  async function handleDeleteRule(ruleName: string) {
    try {
      await invoke("delete_rule", { ruleName });
      showFeedback("success", `Rule "${ruleName}" deleted`);
    } catch (err) {
      showFeedback("error", `Failed to delete rule: ${err}`);
    }
    setPolicy((prev) =>
      prev ? { ...prev, rules: prev.rules.filter((r) => r.name !== ruleName) } : prev
    );
    setMenuOpen(null);
  }

  function handleDuplicate(rule: PolicyRule) {
    const dup: PolicyRule = { ...rule, name: `${rule.name} (copy)` };
    setPolicy((prev) =>
      prev ? { ...prev, rules: [...prev.rules, dup] } : prev
    );
    setMenuOpen(null);
  }

  function toggleEnabled(ruleName: string) {
    setPolicy((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        rules: prev.rules.map((r) =>
          r.name === ruleName ? { ...r, enabled: !r.enabled } : r
        ),
      };
    });
    setMenuOpen(null);
  }

  function moveRule(index: number, direction: -1 | 1) {
    setPolicy((prev) => {
      if (!prev) return prev;
      const rules = [...prev.rules];
      const target = index + direction;
      if (target < 0 || target >= rules.length) return prev;
      [rules[index], rules[target]] = [rules[target], rules[index]];
      return { ...prev, rules };
    });
    setMenuOpen(null);
  }

  const currentLevel = policy?.name ?? "balanced";

  if (loading) {
    return (
      <div className="p-6">
        <p className="text-[var(--color-text-secondary)]">Loading policy...</p>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Security Policy</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {policy?.rules.length ?? 0} rules configured
          </p>
        </div>
        <button
          onClick={openNewRule}
          className="px-4 py-2 rounded-lg text-sm text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)]"
        >
          + New Rule
        </button>
      </div>

      {/* Security level indicator */}
      <div className="flex items-center gap-3 p-4 mb-6 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
        <span className="inline-block w-3 h-3 rounded-full bg-[var(--color-warning)]" />
        <div className="flex-1">
          <span className="text-sm font-medium capitalize">{currentLevel.replace("-", " ")}</span>
          <span className="text-xs text-[var(--color-text-secondary)] ml-2">security level</span>
        </div>
        <button
          onClick={() => setLevelOpen(true)}
          className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
        >
          Change Level
        </button>
      </div>

      {/* Feedback toast */}
      {feedback && (
        <div
          className={`mb-4 px-4 py-2 rounded-lg text-sm ${
            feedback.type === "success"
              ? "bg-[var(--color-success)]/15 text-[var(--color-success)]"
              : "bg-[var(--color-danger)]/15 text-[var(--color-danger)]"
          }`}
        >
          {feedback.message}
        </div>
      )}

      {/* Rules list */}
      {policy?.rules.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 mb-6 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
          <p className="text-sm text-[var(--color-text-secondary)] mb-1">No rules configured</p>
          <p className="text-xs text-[var(--color-text-secondary)] mb-4">
            Add a rule or apply a template to get started.
          </p>
          <div className="flex gap-2">
            <button
              onClick={openNewRule}
              className="px-3 py-1.5 rounded-md text-xs text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)]"
            >
              + Add Rule
            </button>
            <button
              onClick={() => setTemplateOpen(true)}
              className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]"
            >
              Browse Templates
            </button>
          </div>
        </div>
      ) : null}

      <div className="space-y-2 mb-6">
        {policy?.rules.map((rule, index) => {
          const config = actionConfig[rule.action];
          return (
            <div
              key={rule.name}
              className={`flex items-center gap-3 p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] transition-opacity ${
                !rule.enabled ? "opacity-50" : ""
              }`}
            >
              {/* Action icon */}
              <span
                className="flex items-center justify-center w-8 h-8 rounded-full text-sm font-bold shrink-0"
                style={{ backgroundColor: `${config.color}20`, color: config.color }}
              >
                {config.icon}
              </span>

              {/* Rule info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium truncate">{rule.name}</span>
                  {!rule.enabled && (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
                      Disabled
                    </span>
                  )}
                </div>
                <p className="text-xs text-[var(--color-text-secondary)] truncate">{rule.pattern}</p>
              </div>

              {/* Priority badge */}
              <span className="text-xs px-2 py-1 rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] shrink-0">
                P{rule.priority}
              </span>

              {/* Hit count (mock) */}
              <span className="text-xs text-[var(--color-text-secondary)] w-16 text-right shrink-0">
                {Math.floor(Math.random() * 100 + index * 10)} hits
              </span>

              {/* Edit button */}
              <button
                onClick={() => openEditRule(rule)}
                className="px-2 py-1 rounded text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)]"
              >
                Edit
              </button>

              {/* Three-dot menu */}
              <div className="relative">
                <button
                  onClick={() => setMenuOpen(menuOpen === rule.name ? null : rule.name)}
                  className="px-2 py-1 rounded text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)]"
                >
                  &#8942;
                </button>
                {menuOpen === rule.name && (
                  <div className="absolute right-0 top-8 z-10 w-40 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] shadow-xl py-1">
                    <button onClick={() => handleDuplicate(rule)} className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--color-bg-tertiary)]">
                      Duplicate
                    </button>
                    <button onClick={() => toggleEnabled(rule.name)} className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--color-bg-tertiary)]">
                      {rule.enabled ? "Disable" : "Enable"}
                    </button>
                    <button onClick={() => moveRule(index, -1)} disabled={index === 0} className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--color-bg-tertiary)] disabled:opacity-30">
                      Move Up
                    </button>
                    <button onClick={() => moveRule(index, 1)} disabled={index === (policy?.rules.length ?? 1) - 1} className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--color-bg-tertiary)] disabled:opacity-30">
                      Move Down
                    </button>
                    <hr className="my-1 border-[var(--color-border)]" />
                    <button onClick={() => handleDeleteRule(rule.name)} className="w-full text-left px-3 py-1.5 text-xs text-[var(--color-danger)] hover:bg-[var(--color-bg-tertiary)]">
                      Delete
                    </button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Template section */}
      <div className="flex items-center gap-3 p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
        <div className="flex-1">
          <span className="text-sm font-medium">Template:</span>
          <span className="text-sm text-[var(--color-text-secondary)] ml-2 capitalize">
            {currentLevel.replace("-", " ")}
          </span>
        </div>
        <button
          onClick={() => setTemplateOpen(true)}
          className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
        >
          Change Template
        </button>
        <button
          onClick={() => {
            invoke("reload_policy")
              .then(() => { loadPolicy(); showFeedback("success", "Policy reloaded from disk"); })
              .catch((err) => showFeedback("error", `Reload failed: ${err}`));
          }}
          className="px-3 py-1.5 rounded-md text-xs border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
        >
          Reset
        </button>
      </div>

      {/* Modals */}
      <RuleEditorModal
        rule={editingRule}
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        onSaved={loadPolicy}
      />
      <SecurityLevelChooser
        currentLevel={currentLevel}
        open={levelOpen}
        onClose={() => setLevelOpen(false)}
        onApplied={loadPolicy}
      />
      <TemplateBrowser
        open={templateOpen}
        onClose={() => setTemplateOpen(false)}
        onApplied={loadPolicy}
      />
    </div>
  );
}
