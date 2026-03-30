import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

import { ASK_CLAW } from "../../constants/messages";
import { ConfirmationCard } from "./ConfirmationCard";
import type { ConversationMessage, ActionButton as ActionButtonType } from "./types";

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

function renderBoldAndLinks(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  const regex = /(\*\*(.+?)\*\*|\[(.+?)\]\((.+?)\))/g;
  let lastIndex = 0;
  let match;
  let key = 0;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    if (match[2]) {
      parts.push(<strong key={key++}>{match[2]}</strong>);
    } else if (match[3] && match[4]) {
      parts.push(
        <a
          key={key++}
          href={match[4]}
          className="text-[var(--color-accent)] hover:underline"
          target="_blank"
          rel="noopener noreferrer"
        >
          {match[3]}
        </a>,
      );
    }
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return parts;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    good: { label: "OK", cls: "bg-[var(--color-safe-subtle)] text-[var(--color-safe)]" },
    warning: { label: "Warning", cls: "bg-[var(--color-warning-subtle)] text-[var(--color-warning)]" },
    error: { label: "Error", cls: "bg-[var(--color-danger-subtle)] text-[var(--color-danger)]" },
  };
  const s = map[status] ?? { label: status, cls: "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]" };
  return (
    <span className={`inline-flex items-center text-xs px-2 py-0.5 rounded-full ${s.cls}`}>
      {s.label}
    </span>
  );
}

function StructuredDataCard({ data }: { data: Record<string, unknown> }) {
  const type = data.type as string;

  if (type === "status_summary") {
    const items = (data.items ?? []) as Array<{ label: string; value: string; status: string }>;
    return (
      <div className="mt-2 space-y-1">
        {items.map((item) => (
          <div key={item.label} className="flex items-center justify-between text-sm">
            <span className="text-[var(--color-text-secondary)]">{item.label}</span>
            <div className="flex items-center gap-2">
              <span className="text-[var(--color-text-primary)]">{item.value}</span>
              <StatusBadge status={item.status} />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (type === "event_list") {
    const events = (data.events ?? []) as Array<{
      id: string;
      timestamp: string;
      server_name: string;
      description: string;
      decision: string;
      risk_level: string;
    }>;
    const total = (data.total ?? events.length) as number;
    return (
      <div className="mt-2 space-y-1">
        {events.map((evt) => (
          <div
            key={evt.id}
            className="flex items-center gap-2 text-xs px-2 py-1.5 rounded bg-[var(--color-bg-tertiary)]"
          >
            <span className="text-[var(--color-text-secondary)] w-16 shrink-0 font-mono">
              {formatRelativeTime(evt.timestamp)}
            </span>
            <span className="text-[var(--color-accent)] w-24 truncate shrink-0">{evt.server_name}</span>
            <span className="text-[var(--color-text-primary)] flex-1 truncate">{evt.description}</span>
            <DecisionBadge decision={evt.decision} />
          </div>
        ))}
        {total > events.length && (
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            ...and {total - events.length} more
          </p>
        )}
      </div>
    );
  }

  if (type === "server_list") {
    const servers = (data.servers ?? []) as Array<{
      name: string;
      wrapped: boolean;
      status: string;
      events_count: number;
    }>;
    return (
      <div className="mt-2 grid grid-cols-2 gap-2">
        {servers.map((srv) => (
          <div
            key={srv.name}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-tertiary)] p-3"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-[var(--color-text-primary)]">{srv.name}</span>
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  srv.status === "running" ? "bg-[var(--color-safe)]" : "bg-[var(--color-text-secondary)]"
                }`}
              />
            </div>
            <div className="text-xs text-[var(--color-text-secondary)]">
              {srv.events_count} events {srv.wrapped && " | wrapped"}
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (type === "metric") {
    return (
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold text-[var(--color-text-primary)]">
          {data.value as string}
        </span>
        <span className="text-sm text-[var(--color-text-secondary)]">{data.label as string}</span>
        {data.trend != null && (
          <span className="text-xs text-[var(--color-text-muted)]">{String(data.trend)}</span>
        )}
      </div>
    );
  }

  if (type === "risk_assessment") {
    const riskColor =
      (data.risk_level as string) === "critical" || (data.risk_level as string) === "high"
        ? "var(--color-danger)"
        : (data.risk_level as string) === "medium"
          ? "var(--color-warning)"
          : "var(--color-safe)";
    return (
      <div className="mt-2 rounded-lg border p-3" style={{ borderColor: riskColor }}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium" style={{ color: riskColor }}>
            {(data.risk_level as string).toUpperCase()}
          </span>
          <span className="text-sm text-[var(--color-text-primary)]">{data.subject as string}</span>
        </div>
        <p className="text-sm text-[var(--color-text-secondary)]">{data.explanation as string}</p>
        {(data.factors as string[] | undefined)?.length ? (
          <ul className="mt-1 list-disc list-inside text-xs text-[var(--color-text-muted)]">
            {(data.factors as string[]).map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        ) : null}
      </div>
    );
  }

  if (type === "scan_summary") {
    return (
      <div className="mt-2 flex items-center gap-4 text-sm">
        <span className="text-[var(--color-text-primary)] font-medium">
          {data.total_findings as number} findings
        </span>
        {(data.critical as number) > 0 && (
          <span className="text-[var(--color-danger)]">{data.critical as number} critical</span>
        )}
        {(data.high as number) > 0 && (
          <span className="text-[var(--color-warning)]">{data.high as number} high</span>
        )}
        {(data.medium as number) > 0 && (
          <span className="text-[var(--color-info)]">{data.medium as number} medium</span>
        )}
        {(data.low as number) > 0 && (
          <span className="text-[var(--color-text-secondary)]">{data.low as number} low</span>
        )}
      </div>
    );
  }

  return null;
}

function DecisionBadge({ decision }: { decision: string }) {
  const d = decision.toLowerCase();
  if (d === "allowed" || d === "allow") {
    return (
      <span className="text-xs px-1.5 py-0.5 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)]">
        allowed
      </span>
    );
  }
  if (d === "blocked" || d === "block" || d === "denied" || d === "deny") {
    return (
      <span className="text-xs px-1.5 py-0.5 rounded-full bg-[var(--color-danger-subtle)] text-[var(--color-danger)]">
        blocked
      </span>
    );
  }
  return (
    <span className="text-xs px-1.5 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]">
      {decision}
    </span>
  );
}

function ActionButtonRow({
  actions,
  onAction,
}: {
  actions: ActionButtonType[];
  onAction: (action: ActionButtonType) => void;
}) {
  if (!actions.length) return null;

  const styleClasses: Record<string, string> = {
    primary:
      "bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)]",
    secondary:
      "border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)]",
    danger:
      "bg-[var(--color-danger)] text-white hover:opacity-90",
  };

  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {actions.map((action) => (
        <button
          key={action.id}
          onClick={() => onAction(action)}
          className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors duration-150 ${
            styleClasses[action.style] ?? styleClasses.secondary
          }`}
        >
          {action.label}
        </button>
      ))}
    </div>
  );
}

interface ConversationFeedProps {
  messages: ConversationMessage[];
  onAction: (action: ActionButtonType) => void;
  onConfirm: (actionJson: string) => void;
  onCancelConfirm: (turnId: string) => void;
  pendingConfirmations: Map<string, string>;
}

export function ConversationFeed({
  messages,
  onAction,
  onConfirm,
  onCancelConfirm,
  pendingConfirmations,
}: ConversationFeedProps) {
  const feedRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [messages.length]);

  const handleAction = (action: ActionButtonType) => {
    if (action.action.type === "navigate") {
      const nav = action.action as { type: "navigate"; page: string };
      navigate(nav.page);
      return;
    }
    onAction(action);
  };

  if (messages.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <p className="text-sm text-[var(--color-text-muted)]">
          {ASK_CLAW.firstTimeGreeting}
        </p>
      </div>
    );
  }

  return (
    <div ref={feedRef} className="flex-1 overflow-y-auto scroll-smooth space-y-4 py-4">
      {messages.map((msg) => {
        if (msg.role === "user") {
          return (
            <div key={msg.turnId} className="flex justify-end">
              <div className="max-w-[70%] rounded-lg bg-[var(--color-accent-subtle)] px-4 py-2.5">
                <p className="text-sm text-[var(--color-text-primary)]">{msg.message}</p>
                <p className="text-xs text-[var(--color-text-muted)] mt-1 text-right">
                  {formatRelativeTime(msg.timestamp)}
                </p>
              </div>
            </div>
          );
        }

        const confirmAction = pendingConfirmations.get(msg.turnId);

        return (
          <div key={msg.turnId} className="flex justify-start gap-2">
            <div className="w-6 h-6 rounded-full bg-[var(--color-accent-subtle)] flex items-center justify-center shrink-0 mt-1">
              <span className="text-xs text-[var(--color-accent)]">C</span>
            </div>
            <div className="max-w-[75%] space-y-1">
              <div className="rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)] px-4 py-2.5 max-h-[60vh] overflow-y-auto">
                <p className="text-sm text-[var(--color-text-primary)] whitespace-pre-wrap">
                  {renderBoldAndLinks(msg.message)}
                </p>

                {msg.structuredData && <StructuredDataCard data={msg.structuredData} />}

                {msg.actions && msg.actions.length > 0 && !confirmAction && (
                  <ActionButtonRow actions={msg.actions} onAction={handleAction} />
                )}

                {msg.suggestions && msg.suggestions.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {msg.suggestions.map((s) => (
                      <button
                        key={s}
                        onClick={() => handleAction({
                          id: `suggestion-${s}`,
                          label: s,
                          action: { type: "follow_up", message: s },
                          style: "secondary",
                          requires_confirmation: false,
                        })}
                        className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors duration-150"
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {confirmAction && (
                <ConfirmationCard
                  description={msg.message}
                  onConfirm={() => onConfirm(confirmAction)}
                  onCancel={() => onCancelConfirm(msg.turnId)}
                />
              )}

              <p className="text-xs text-[var(--color-text-muted)]">
                {formatRelativeTime(msg.timestamp)}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
