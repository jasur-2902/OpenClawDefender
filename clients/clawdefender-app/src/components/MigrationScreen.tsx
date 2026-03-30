import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ExistingInstallation {
  config_found: boolean;
  policy_found: boolean;
  policy_rule_count: number;
  event_count: number;
  profiles_found: boolean;
  models: string[];
  onboarding_complete: boolean;
}

interface MigrationLog {
  changes: string[];
  warnings: string[];
}

interface MigrationScreenProps {
  installation: ExistingInstallation;
  onUseExisting: () => void;
  onStartFresh: () => void;
}

export function MigrationScreen({
  installation,
  onUseExisting,
  onStartFresh,
}: MigrationScreenProps) {
  const [migrating, setMigrating] = useState(false);
  const [migrationDone, setMigrationDone] = useState(false);
  const [migrationLogs, setMigrationLogs] = useState<MigrationLog[]>([]);
  const [error, setError] = useState<string | null>(null);

  const items: { label: string; detail: string }[] = [];

  if (installation.config_found) {
    items.push({ label: "Settings", detail: "Existing configuration found" });
  }
  if (installation.policy_found) {
    items.push({
      label: "Policy rules",
      detail: `${installation.policy_rule_count} custom rule${installation.policy_rule_count !== 1 ? "s" : ""}`,
    });
  }
  if (installation.event_count > 0) {
    items.push({
      label: "Event history",
      detail: `${installation.event_count.toLocaleString()} event${installation.event_count !== 1 ? "s" : ""} recorded`,
    });
  }
  if (installation.profiles_found) {
    items.push({
      label: "Behavioral profiles",
      detail: "Existing profiles database found",
    });
  }
  if (installation.models.length > 0) {
    items.push({
      label: "AI models",
      detail: `${installation.models.length} model${installation.models.length !== 1 ? "s" : ""} installed`,
    });
  }

  async function handleUseExisting() {
    setMigrating(true);
    setError(null);
    try {
      const configLog = await invoke<MigrationLog>("migrate_config");
      const policyLog = await invoke<MigrationLog>("migrate_policy");
      setMigrationLogs([configLog, policyLog]);
      setMigrationDone(true);
    } catch (e) {
      setError(String(e));
      setMigrating(false);
    }
  }

  function handleContinue() {
    onUseExisting();
  }

  return (
    <div
      className="flex flex-col items-center justify-center min-h-screen p-8"
      style={{ backgroundColor: "var(--color-bg-primary)" }}
    >
      <div
        className="w-full max-w-lg rounded-xl p-8"
        style={{
          backgroundColor: "var(--color-bg-secondary)",
          border: "1px solid var(--color-border)",
        }}
      >
        <div className="text-center mb-6">
          <div
            className="inline-flex items-center justify-center w-12 h-12 rounded-full mb-4"
            style={{
              backgroundColor: "var(--color-success-subtle)",
              color: "var(--color-success)",
            }}
          >
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
            </svg>
          </div>
          <h1
            className="text-xl font-semibold mb-2"
            style={{ color: "var(--color-text-primary)" }}
          >
            Existing installation found
          </h1>
          <p
            className="text-sm"
            style={{ color: "var(--color-text-secondary)" }}
          >
            ClawDefender found your existing configuration and data.
          </p>
        </div>

        <div
          className="rounded-lg p-4 mb-6 space-y-3"
          style={{
            backgroundColor: "var(--color-bg-tertiary)",
            border: "1px solid var(--color-border)",
          }}
        >
          {items.map((item) => (
            <div key={item.label} className="flex items-center justify-between">
              <span
                className="text-sm font-medium"
                style={{ color: "var(--color-text-primary)" }}
              >
                {item.label}
              </span>
              <span
                className="text-sm"
                style={{ color: "var(--color-text-secondary)" }}
              >
                {item.detail}
              </span>
            </div>
          ))}
          {items.length === 0 && (
            <p
              className="text-sm text-center"
              style={{ color: "var(--color-text-tertiary)" }}
            >
              No significant data found.
            </p>
          )}
        </div>

        {error && (
          <div
            className="rounded-lg p-3 mb-4 text-sm"
            style={{
              backgroundColor: "var(--color-danger-subtle)",
              color: "var(--color-danger)",
              border: "1px solid var(--color-danger-border)",
            }}
          >
            Migration error: {error}
          </div>
        )}

        {migrationDone && (
          <div
            className="rounded-lg p-3 mb-4 text-sm"
            style={{
              backgroundColor: "var(--color-success-subtle)",
              color: "var(--color-success)",
              border: "1px solid var(--color-success-border)",
            }}
          >
            Migration complete. Your settings have been updated for
            compatibility.
            {migrationLogs.map((log, i) =>
              log.changes
                .filter((c) => !c.includes("up to date") && !c.includes("nothing to migrate"))
                .map((c, j) => (
                  <div key={`${i}-${j}`} className="mt-1 opacity-80">
                    {c}
                  </div>
                ))
            )}
          </div>
        )}

        <div className="flex gap-3">
          {!migrationDone ? (
            <>
              <button
                onClick={handleUseExisting}
                disabled={migrating}
                className="flex-1 px-4 py-2.5 rounded-lg text-sm font-medium transition-opacity"
                style={{
                  backgroundColor: "var(--color-accent)",
                  color: "var(--color-text-on-accent)",
                  opacity: migrating ? 0.6 : 1,
                }}
              >
                {migrating ? "Migrating..." : "Use my existing settings"}
              </button>
              <button
                onClick={onStartFresh}
                disabled={migrating}
                className="flex-1 px-4 py-2.5 rounded-lg text-sm font-medium transition-opacity"
                style={{
                  backgroundColor: "var(--color-bg-tertiary)",
                  color: "var(--color-text-primary)",
                  border: "1px solid var(--color-border)",
                  opacity: migrating ? 0.6 : 1,
                }}
              >
                Start fresh
              </button>
            </>
          ) : (
            <button
              onClick={handleContinue}
              className="flex-1 px-4 py-2.5 rounded-lg text-sm font-medium"
              style={{
                backgroundColor: "var(--color-accent)",
                color: "var(--color-text-on-accent)",
              }}
            >
              Continue to ClawDefender
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Hook that checks for an existing installation on mount.
 * Returns { loading, installation } — installation is null if nothing found
 * or if onboarding was already completed.
 */
export function useExistingInstallation() {
  const [loading, setLoading] = useState(true);
  const [installation, setInstallation] =
    useState<ExistingInstallation | null>(null);

  useEffect(() => {
    async function check() {
      try {
        const result = await invoke<ExistingInstallation>(
          "check_existing_installation"
        );
        // Only show migration screen if there's meaningful data and
        // onboarding hasn't been completed yet
        const hasData =
          result.config_found ||
          result.policy_found ||
          result.event_count > 0 ||
          result.profiles_found ||
          result.models.length > 0;

        if (hasData && !result.onboarding_complete) {
          setInstallation(result);
        }
      } catch {
        // If the command fails, skip migration screen
      }
      setLoading(false);
    }
    check();
  }, []);

  return { loading, installation };
}
