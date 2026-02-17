import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { PolicyRule } from "../types";

interface RuleEditorModalProps {
  rule: PolicyRule | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}

const actions: { value: PolicyRule["action"]; label: string; icon: string; color: string }[] = [
  { value: "deny", label: "Block", icon: "\u2717", color: "var(--color-danger)" },
  { value: "prompt", label: "Prompt", icon: "!", color: "var(--color-warning)" },
  { value: "allow", label: "Allow", icon: "\u2713", color: "var(--color-success)" },
  { value: "audit", label: "Audit", icon: "\u270E", color: "var(--color-accent)" },
];

export function RuleEditorModal({ rule, open, onClose, onSaved }: RuleEditorModalProps) {
  const isEditing = rule !== null;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [action, setAction] = useState<PolicyRule["action"]>("deny");
  const [resource, setResource] = useState("");
  const [patterns, setPatterns] = useState<string[]>([""]);
  const [priority, setPriority] = useState(50);
  const [applyAll, setApplyAll] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (rule) {
      setName(rule.name);
      setDescription(rule.description);
      setAction(rule.action);
      setResource(rule.resource);
      setPatterns(rule.pattern ? rule.pattern.split(",") : [""]);
      setPriority(rule.priority);
      setApplyAll(rule.resource === "*");
    } else {
      setName("");
      setDescription("");
      setAction("deny");
      setResource("");
      setPatterns([""]);
      setPriority(50);
      setApplyAll(true);
    }
  }, [rule, open]);

  if (!open) return null;

  function addPattern() {
    setPatterns([...patterns, ""]);
  }

  function updatePattern(index: number, value: string) {
    const next = [...patterns];
    next[index] = value;
    setPatterns(next);
  }

  function removePattern(index: number) {
    if (patterns.length <= 1) return;
    setPatterns(patterns.filter((_, i) => i !== index));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const ruleData: PolicyRule = {
        name,
        description,
        action,
        resource: applyAll ? "*" : resource,
        pattern: patterns.filter(Boolean).join(","),
        priority,
        enabled: rule?.enabled ?? true,
      };

      if (isEditing) {
        await invoke("update_rule", { rule: ruleData });
      } else {
        await invoke("add_rule", { rule: ruleData });
      }
      onSaved();
      onClose();
    } catch (_err) {
      // Tauri command may not be available yet
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold mb-4">
          {isEditing ? "Edit Rule" : "New Rule"}
        </h2>

        {/* Action selector */}
        <label className="block text-xs text-[var(--color-text-secondary)] mb-1">Action</label>
        <div className="flex gap-2 mb-4">
          {actions.map((a) => (
            <button
              key={a.value}
              onClick={() => setAction(a.value)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm border transition-colors ${
                action === a.value
                  ? "border-[var(--color-accent)] bg-[var(--color-bg-tertiary)]"
                  : "border-[var(--color-border)] bg-[var(--color-bg-primary)] hover:border-[var(--color-text-secondary)]"
              }`}
            >
              <span style={{ color: a.color }} className="font-bold">{a.icon}</span>
              {a.label}
            </button>
          ))}
        </div>

        {/* Rule name */}
        <label className="block text-xs text-[var(--color-text-secondary)] mb-1">Rule Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Block file writes"
          className="w-full mb-3 px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
        />

        {/* Description */}
        <label className="block text-xs text-[var(--color-text-secondary)] mb-1">Block Message / Description</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Reason shown to user when blocked"
          rows={2}
          className="w-full mb-3 px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] resize-none"
        />

        {/* Path patterns */}
        <label className="block text-xs text-[var(--color-text-secondary)] mb-1">Path Pattern(s)</label>
        {patterns.map((p, i) => (
          <div key={i} className="flex gap-2 mb-2">
            <input
              type="text"
              value={p}
              onChange={(e) => updatePattern(i, e.target.value)}
              placeholder="/home/**/*.env"
              className="flex-1 px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
            />
            {patterns.length > 1 && (
              <button
                onClick={() => removePattern(i)}
                className="px-2 text-[var(--color-text-secondary)] hover:text-[var(--color-danger)]"
              >
                \u2717
              </button>
            )}
          </div>
        ))}
        <button
          onClick={addPattern}
          className="text-xs text-[var(--color-accent)] hover:underline mb-4"
        >
          + Add pattern
        </button>

        {/* Apply scope */}
        <div className="flex items-center gap-3 mb-3">
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="radio"
              checked={applyAll}
              onChange={() => setApplyAll(true)}
              className="accent-[var(--color-accent)]"
            />
            Apply to all servers
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="radio"
              checked={!applyAll}
              onChange={() => setApplyAll(false)}
              className="accent-[var(--color-accent)]"
            />
            Specific server
          </label>
        </div>

        {!applyAll && (
          <input
            type="text"
            value={resource}
            onChange={(e) => setResource(e.target.value)}
            placeholder="Server name or pattern"
            className="w-full mb-3 px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
          />
        )}

        {/* Priority */}
        <label className="block text-xs text-[var(--color-text-secondary)] mb-1">Priority ({priority})</label>
        <input
          type="range"
          min={1}
          max={100}
          value={priority}
          onChange={(e) => setPriority(Number(e.target.value))}
          className="w-full mb-4 accent-[var(--color-accent)]"
        />

        {/* Footer buttons */}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)]"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !name.trim()}
            className="px-4 py-2 rounded-lg text-sm text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            {saving ? "Saving..." : isEditing ? "Update Rule" : "Add Rule"}
          </button>
        </div>
      </div>
    </div>
  );
}
