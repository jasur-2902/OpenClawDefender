import { useEffect, useRef, useState, useCallback } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import {
  useConversationStore,
  ConversationMessage,
} from "../stores/conversationStore";
import { useEventStore } from "../stores/eventStore";
import { ASK_CLAW } from "../constants/messages";
import { DragDropZone } from "../components/conversation/DragDropZone";
import { ConfirmationCard } from "../components/conversation/ConfirmationCard";

// ---------------------------------------------------------------------------
// Types matching the Rust ActionType enum
// ---------------------------------------------------------------------------

interface ActionButtonData {
  id: string;
  label: string;
  action: ActionTypeData;
  style: string; // "primary" | "secondary" | "danger"
  requires_confirmation: boolean;
}

type ActionTypeData =
  | { type: "tauri_command"; command: string; params: Record<string, unknown> }
  | { type: "navigate"; page: string; params?: Record<string, string> }
  | { type: "follow_up"; message: string }
  | { type: "copy_to_clipboard"; text: string };

// ---------------------------------------------------------------------------
// Helpers
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

function renderMarkdown(text: string): React.ReactNode[] {
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
  return parts.length > 0 ? parts : [text];
}

function getSuggestions(lastIntentId?: string): readonly string[] {
  if (!lastIntentId) return ASK_CLAW.suggestions.default;
  if (lastIntentId.startsWith("status.")) return ASK_CLAW.suggestions.afterStatus;
  if (lastIntentId.startsWith("control.block")) return ASK_CLAW.suggestions.afterBlock;
  if (lastIntentId.startsWith("explain.")) return ASK_CLAW.suggestions.afterExplain;
  return ASK_CLAW.suggestions.default;
}

// ---------------------------------------------------------------------------
// Rich Data Renderers
// ---------------------------------------------------------------------------

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
      id: string; timestamp: string; server_name: string;
      description: string; decision: string; risk_level: string;
    }>;
    const total = (data.total ?? events.length) as number;
    return (
      <div className="mt-2 space-y-1">
        {events.map((evt) => (
          <div key={evt.id} className="flex items-center gap-2 text-xs px-2 py-1.5 rounded bg-[var(--color-bg-tertiary)]">
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
      name: string; wrapped: boolean; status: string; events_count: number;
    }>;
    return (
      <div className="mt-2 grid grid-cols-2 gap-2">
        {servers.map((srv) => (
          <div key={srv.name} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-tertiary)] p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-[var(--color-text-primary)]">{srv.name}</span>
              <span className={`inline-block w-2 h-2 rounded-full ${
                srv.status === "running" ? "bg-[var(--color-safe)]" : "bg-[var(--color-text-secondary)]"
              }`} />
            </div>
            <div className="text-xs text-[var(--color-text-secondary)]">
              {srv.events_count} events{srv.wrapped ? " | wrapped" : ""}
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (type === "metric") {
    return (
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold text-[var(--color-text-primary)]">{data.value as string}</span>
        <span className="text-sm text-[var(--color-text-secondary)]">{data.label as string}</span>
        {data.trend != null && <span className="text-xs text-[var(--color-text-muted)]">{String(data.trend)}</span>}
      </div>
    );
  }

  if (type === "risk_assessment") {
    const riskLevel = data.risk_level as string;
    const riskColor = riskLevel === "critical" || riskLevel === "high"
      ? "var(--color-danger)" : riskLevel === "medium" ? "var(--color-warning)" : "var(--color-safe)";
    return (
      <div className="mt-2 rounded-lg border p-3" style={{ borderColor: riskColor }}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium" style={{ color: riskColor }}>{riskLevel.toUpperCase()}</span>
          <span className="text-sm text-[var(--color-text-primary)]">{data.subject as string}</span>
        </div>
        <p className="text-sm text-[var(--color-text-secondary)]">{data.explanation as string}</p>
        {(data.factors as string[] | undefined)?.length ? (
          <ul className="mt-1 list-disc list-inside text-xs text-[var(--color-text-muted)]">
            {(data.factors as string[]).map((f, i) => <li key={i}>{f}</li>)}
          </ul>
        ) : null}
      </div>
    );
  }

  if (type === "scan_summary") {
    return (
      <div className="mt-2 flex items-center gap-4 text-sm">
        <span className="text-[var(--color-text-primary)] font-medium">{data.total_findings as number} findings</span>
        {(data.critical as number) > 0 && <span className="text-[var(--color-danger)]">{data.critical as number} critical</span>}
        {(data.high as number) > 0 && <span className="text-[var(--color-warning)]">{data.high as number} high</span>}
        {(data.medium as number) > 0 && <span className="text-[var(--color-info)]">{data.medium as number} medium</span>}
        {(data.low as number) > 0 && <span className="text-[var(--color-text-secondary)]">{data.low as number} low</span>}
      </div>
    );
  }

  return null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AskClaw() {
  const location = useLocation();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const feedRef = useRef<HTMLDivElement>(null);
  const [inputValue, setInputValue] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [messageHistory, setMessageHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [pendingConfirmations, setPendingConfirmations] = useState<Map<string, string>>(new Map());

  const daemonRunning = useEventStore((s) => s.daemonRunning);
  const {
    messages,
    isLoading,
    loadLatestConversation,
    startNewConversation,
    addUserMessage,
    addClawResponse,
    setCurrentPage,
  } = useConversationStore();

  // Track current page in context
  useEffect(() => {
    setCurrentPage("/ask");
  }, [setCurrentPage]);

  // Load conversation on mount
  useEffect(() => {
    loadLatestConversation();
  }, [loadLatestConversation]);

  // Handle pre-populated question from navigation state (AskClawButton)
  useEffect(() => {
    const state = location.state as { question?: string; context?: string } | null;
    if (state?.question) {
      setInputValue(state.question);
      window.history.replaceState({}, "");
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [location.state]);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [messages, isThinking]);

  // Focus input after response renders
  useEffect(() => {
    if (!isThinking && messages.length > 0) {
      inputRef.current?.focus();
    }
  }, [isThinking, messages.length]);

  // Auto-resize textarea
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    const maxHeight = 4 * 24;
    el.style.height = `${Math.min(el.scrollHeight, maxHeight)}px`;
  }, [inputValue]);

  // Get the last intent ID for context-sensitive suggestions
  const lastIntentId = [...messages].reverse().find((m) => m.role === "claw")?.intentId;

  // Submit a message
  const submitMessage = useCallback(
    async (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || isThinking) return;

      setInputValue("");
      setError(null);
      setMessageHistory((prev) => [...prev, trimmed]);
      setHistoryIndex(-1);
      setIsThinking(true);

      await addUserMessage(trimmed);

      try {
        const contextJson = useConversationStore.getState().getContextJson();
        const responseJson = await invoke<string>("ask_claw", {
          input: trimmed,
          contextJson,
        });
        const response = JSON.parse(responseJson);

        const clawMsg: ConversationMessage = {
          id: response.turn_id || `claw-${Date.now()}`,
          role: "claw",
          contentText: response.message,
          contentRichJson: response.structured_data
            ? JSON.stringify(response.structured_data)
            : undefined,
          actionsJson: response.actions?.length
            ? JSON.stringify(response.actions)
            : undefined,
          intentId: response.intent_id,
          timestamp: response.timestamp || new Date().toISOString(),
        };

        await addClawResponse(clawMsg);

        // Check if any action requires confirmation
        const actions: ActionButtonData[] = response.actions ?? [];
        const confirmAction = actions.find((a: ActionButtonData) => a.requires_confirmation);
        if (confirmAction) {
          setPendingConfirmations((prev) => {
            const next = new Map(prev);
            next.set(clawMsg.id, JSON.stringify(confirmAction.action));
            return next;
          });
        }
      } catch (e) {
        setError(String(e));
      } finally {
        setIsThinking(false);
      }
    },
    [isThinking, addUserMessage, addClawResponse],
  );

  // Handle action button clicks
  const handleAction = useCallback(
    async (action: ActionTypeData, requiresConfirmation: boolean, msgId?: string) => {
      if (requiresConfirmation && msgId) {
        setPendingConfirmations((prev) => {
          const next = new Map(prev);
          next.set(msgId, JSON.stringify(action));
          return next;
        });
        return;
      }

      switch (action.type) {
        case "navigate":
          navigate(action.page);
          break;
        case "tauri_command":
          try {
            setIsThinking(true);
            const contextJson = useConversationStore.getState().getContextJson();
            const responseJson = await invoke<string>("confirm_action", {
              actionJson: JSON.stringify(action),
              state: contextJson,
            });
            const response = JSON.parse(responseJson);
            const clawMsg: ConversationMessage = {
              id: response.turn_id || `claw-${Date.now()}`,
              role: "claw",
              contentText: response.message,
              contentRichJson: response.structured_data
                ? JSON.stringify(response.structured_data)
                : undefined,
              actionsJson: response.actions?.length
                ? JSON.stringify(response.actions)
                : undefined,
              intentId: response.intent_id,
              timestamp: response.timestamp || new Date().toISOString(),
            };
            await addClawResponse(clawMsg);
          } catch (e) {
            setError(String(e));
          } finally {
            setIsThinking(false);
          }
          break;
        case "follow_up":
          await submitMessage(action.message);
          break;
        case "copy_to_clipboard":
          await navigator.clipboard.writeText(action.text);
          break;
      }
    },
    [navigate, submitMessage, addClawResponse],
  );

  // Handle confirmation
  const handleConfirm = useCallback(
    async (msgId: string) => {
      const actionJson = pendingConfirmations.get(msgId);
      if (!actionJson) return;

      setPendingConfirmations((prev) => {
        const next = new Map(prev);
        next.delete(msgId);
        return next;
      });

      setIsThinking(true);
      try {
        const contextJson = useConversationStore.getState().getContextJson();
        const responseJson = await invoke<string>("confirm_action", {
          actionJson,
          state: contextJson,
        });
        const response = JSON.parse(responseJson);
        const clawMsg: ConversationMessage = {
          id: response.turn_id || `claw-${Date.now()}`,
          role: "claw",
          contentText: response.message,
          contentRichJson: response.structured_data
            ? JSON.stringify(response.structured_data)
            : undefined,
          actionsJson: response.actions?.length
            ? JSON.stringify(response.actions)
            : undefined,
          intentId: response.intent_id,
          timestamp: response.timestamp || new Date().toISOString(),
        };
        await addClawResponse(clawMsg);
      } catch (e) {
        setError(String(e));
      } finally {
        setIsThinking(false);
      }
    },
    [pendingConfirmations, addClawResponse],
  );

  // Handle cancel confirmation
  const handleCancelConfirm = useCallback(
    async (msgId: string) => {
      setPendingConfirmations((prev) => {
        const next = new Map(prev);
        next.delete(msgId);
        return next;
      });

      const clawMsg: ConversationMessage = {
        id: `cancel-${Date.now()}`,
        role: "claw",
        contentText: ASK_CLAW.confirmCancelled,
        timestamp: new Date().toISOString(),
      };
      await addClawResponse(clawMsg);
    },
    [addClawResponse],
  );

  // Handle file drop
  const handleFileDrop = useCallback(
    async (path: string) => {
      await addUserMessage(`[Dropped file: ${path}]`);
      setIsThinking(true);

      try {
        const isConfig = /\.(json|ya?ml|toml|ini|conf|cfg)$/i.test(path);
        const command = isConfig ? "analyze_config" : "analyze_file";
        const resultRaw = await invoke<string>(command, { path });
        const result = JSON.parse(resultRaw);

        const clawMsg: ConversationMessage = {
          id: `analysis-${Date.now()}`,
          role: "claw",
          contentText: result.summary ?? result.message ?? "Analysis complete.",
          contentRichJson: result.structured_data
            ? JSON.stringify(result.structured_data)
            : undefined,
          actionsJson: result.actions?.length
            ? JSON.stringify(result.actions)
            : undefined,
          intentId: "analyze.file",
          timestamp: new Date().toISOString(),
        };
        await addClawResponse(clawMsg);
      } catch {
        const errorMsg: ConversationMessage = {
          id: `error-${Date.now()}`,
          role: "claw",
          contentText: ASK_CLAW.errorGeneric,
          timestamp: new Date().toISOString(),
        };
        await addClawResponse(errorMsg);
      } finally {
        setIsThinking(false);
      }
    },
    [addUserMessage, addClawResponse],
  );

  // Handle URL drop
  const handleUrlDrop = useCallback(
    async (url: string) => {
      await addUserMessage(`[Dropped URL: ${url}]`);
      setIsThinking(true);

      try {
        const resultRaw = await invoke<string>("analyze_url", { url });
        const result = JSON.parse(resultRaw);

        const clawMsg: ConversationMessage = {
          id: `analysis-${Date.now()}`,
          role: "claw",
          contentText: result.summary ?? result.message ?? "Analysis complete.",
          contentRichJson: result.structured_data
            ? JSON.stringify(result.structured_data)
            : undefined,
          actionsJson: result.actions?.length
            ? JSON.stringify(result.actions)
            : undefined,
          intentId: "analyze.url",
          timestamp: new Date().toISOString(),
        };
        await addClawResponse(clawMsg);
      } catch {
        const errorMsg: ConversationMessage = {
          id: `error-${Date.now()}`,
          role: "claw",
          contentText: ASK_CLAW.errorGeneric,
          timestamp: new Date().toISOString(),
        };
        await addClawResponse(errorMsg);
      } finally {
        setIsThinking(false);
      }
    },
    [addUserMessage, addClawResponse],
  );

  // Keyboard handling for the input
  function handleInputKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submitMessage(inputValue);
    } else if (e.key === "Escape") {
      setInputValue("");
    } else if (e.key === "ArrowUp" && inputValue === "") {
      e.preventDefault();
      if (messageHistory.length > 0) {
        const newIndex =
          historyIndex === -1
            ? messageHistory.length - 1
            : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setInputValue(messageHistory[newIndex]);
      }
    }
  }

  // Parse actions from a message
  function parseActions(msg: ConversationMessage): ActionButtonData[] {
    if (!msg.actionsJson) return [];
    try {
      return JSON.parse(msg.actionsJson);
    } catch {
      return [];
    }
  }

  // Parse rich data from a message
  function parseRichData(msg: ConversationMessage): Record<string, unknown> | null {
    if (!msg.contentRichJson) return null;
    try {
      return JSON.parse(msg.contentRichJson);
    } catch {
      return null;
    }
  }

  // -- Render ---------------------------------------------------------------

  const isEmpty = messages.length === 0 && !isLoading;
  const showDaemonWarning = !daemonRunning;
  const suggestions = getSuggestions(lastIntentId);

  const actionStyleClasses: Record<string, string> = {
    primary: "bg-[var(--color-accent)] text-white hover:opacity-90",
    secondary: "border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
    danger: "bg-[var(--color-danger)] text-white hover:opacity-90",
  };

  return (
    <DragDropZone onFileDrop={handleFileDrop} onUrlDrop={handleUrlDrop}>
      <div className="flex flex-col h-full max-h-screen">
        {/* Header */}
        <header className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border)]">
          <div>
            <h1 className="text-lg font-semibold text-[var(--color-text-primary)]">
              Ask Claw
            </h1>
            <p className="text-xs text-[var(--color-text-secondary)]">
              Ask anything about your security — Cmd+K from anywhere
            </p>
          </div>
          <button
            onClick={() => {
              startNewConversation();
              setPendingConfirmations(new Map());
            }}
            className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors duration-150"
          >
            {ASK_CLAW.newConversation}
          </button>
        </header>

        {/* Daemon warning */}
        {showDaemonWarning && (
          <div
            className="mx-6 mt-4 px-4 py-3 rounded-md bg-[var(--color-warning-light)] border border-[var(--color-warning)] text-sm text-[var(--color-text-primary)]"
            role="alert"
          >
            {ASK_CLAW.offlineMessage}
          </div>
        )}

        {/* Conversation feed */}
        <div
          ref={feedRef}
          className="flex-1 overflow-y-auto px-6 py-4 space-y-4 scroll-smooth"
          role="log"
          aria-label="Conversation with Claw"
          aria-live="polite"
        >
          {isLoading && (
            <div className="flex items-center justify-center py-12 text-[var(--color-text-secondary)]">
              Loading conversation...
            </div>
          )}

          {/* Empty / first-time state */}
          {isEmpty && !isLoading && (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="w-12 h-12 rounded-full bg-[var(--color-accent-subtle)] flex items-center justify-center mb-4">
                <span className="text-lg text-[var(--color-accent)]">{"\u25C8"}</span>
              </div>
              <p className="text-[var(--color-text-primary)] text-base mb-2">
                {ASK_CLAW.firstTimeGreeting}
              </p>
              <div className="flex flex-wrap justify-center gap-2 mt-6" role="group" aria-label="Suggested questions">
                {ASK_CLAW.suggestions.default.map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() => submitMessage(suggestion)}
                    className="px-3 py-1.5 text-sm rounded-full border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors duration-150"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Messages */}
          {messages.map((msg) => {
            const actions = parseActions(msg);
            const richData = parseRichData(msg);
            const isUser = msg.role === "user";
            const hasConfirmation = pendingConfirmations.has(msg.id);

            return (
              <div
                key={msg.id}
                className={`flex ${isUser ? "justify-end" : "justify-start gap-2"}`}
                aria-label={isUser ? `You said: ${msg.contentText}` : `Claw said: ${msg.contentText}`}
              >
                {/* Claw avatar */}
                {!isUser && (
                  <div className="w-6 h-6 rounded-full bg-[var(--color-accent-subtle)] flex items-center justify-center shrink-0 mt-1">
                    <span className="text-xs text-[var(--color-accent)]">C</span>
                  </div>
                )}

                <div className={`max-w-[75%] space-y-1`}>
                  <div
                    className={`rounded-lg px-4 py-3 text-sm ${
                      isUser
                        ? "bg-[var(--color-accent-subtle)] text-[var(--color-text-primary)]"
                        : "bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                    }`}
                  >
                    <p className="whitespace-pre-wrap">{renderMarkdown(msg.contentText)}</p>

                    {/* Structured rich data */}
                    {richData && <StructuredDataCard data={richData} />}

                    {/* Action buttons */}
                    {actions.length > 0 && !hasConfirmation && (
                      <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="Suggested actions">
                        {actions.map((action) => (
                          <button
                            key={action.id}
                            onClick={() =>
                              handleAction(action.action, action.requires_confirmation, msg.id)
                            }
                            className={`px-3 py-1 text-xs rounded-md transition-colors duration-150 ${
                              actionStyleClasses[action.style] ?? actionStyleClasses.secondary
                            }`}
                          >
                            {action.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Confirmation card */}
                  {hasConfirmation && (
                    <ConfirmationCard
                      description={msg.contentText}
                      onConfirm={() => handleConfirm(msg.id)}
                      onCancel={() => handleCancelConfirm(msg.id)}
                    />
                  )}

                  {/* Timestamp */}
                  <p className={`text-xs text-[var(--color-text-muted)] ${isUser ? "text-right" : ""}`}>
                    {formatRelativeTime(msg.timestamp)}
                  </p>
                </div>
              </div>
            );
          })}

          {/* Thinking indicator */}
          {isThinking && (
            <div className="flex justify-start gap-2" role="status" aria-label="Claw is thinking">
              <div className="w-6 h-6 rounded-full bg-[var(--color-accent-subtle)] flex items-center justify-center shrink-0 mt-1">
                <span className="text-xs text-[var(--color-accent)]">C</span>
              </div>
              <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg px-4 py-3 text-sm text-[var(--color-text-secondary)]">
                <span className="inline-flex items-center gap-1.5">
                  <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-analysis-pulse" aria-hidden="true" />
                  {ASK_CLAW.thinkingIndicator}
                </span>
              </div>
            </div>
          )}

          {/* Error state */}
          {error && (
            <div className="flex justify-start gap-2" role="alert">
              <div className="w-6 h-6 rounded-full bg-[var(--color-accent-subtle)] flex items-center justify-center shrink-0 mt-1">
                <span className="text-xs text-[var(--color-accent)]">C</span>
              </div>
              <div className="bg-[var(--color-bg-secondary)] rounded-lg px-4 py-3 text-sm text-[var(--color-text-primary)] border border-[var(--color-danger)]">
                <p>{ASK_CLAW.errorGeneric}</p>
                <div className="mt-2 flex gap-2">
                  <button
                    onClick={() => {
                      setError(null);
                      if (messageHistory.length > 0) {
                        submitMessage(messageHistory[messageHistory.length - 1]);
                      }
                    }}
                    className="px-3 py-1 text-xs rounded-md bg-[var(--color-accent)] text-white hover:opacity-90 transition-opacity duration-150"
                  >
                    {ASK_CLAW.errorRetry}
                  </button>
                  <button
                    onClick={() => setError(null)}
                    className="px-3 py-1 text-xs rounded-md border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors duration-150"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Context-sensitive suggestions */}
        {messages.length > 0 && !isThinking && (
          <div className="px-6 py-2 border-t border-[var(--color-border)]">
            <div className="flex flex-wrap gap-2">
              {suggestions.map((s) => (
                <button
                  key={s}
                  onClick={() => submitMessage(s)}
                  disabled={isThinking}
                  className="rounded-full border border-[var(--color-border)] bg-[var(--color-bg-tertiary)] px-3 py-1 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors duration-150"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input area */}
        <div className="border-t border-[var(--color-border)] px-6 py-4">
          <div className="flex items-end gap-3">
            <label htmlFor="ask-claw-input" className="sr-only">
              Message Claw
            </label>
            <textarea
              ref={inputRef}
              id="ask-claw-input"
              data-ask-claw-input
              rows={1}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleInputKeyDown}
              placeholder={ASK_CLAW.inputPlaceholder}
              disabled={isThinking}
              className="flex-1 resize-none rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-[var(--color-text-primary)] text-sm px-4 py-2.5 placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)] disabled:opacity-50 transition-colors duration-150"
              aria-label="Ask Claw a question"
            />
            <button
              onClick={() => submitMessage(inputValue)}
              disabled={!inputValue.trim() || isThinking}
              className="px-4 py-2.5 rounded-lg bg-[var(--color-accent)] text-white text-sm font-medium hover:opacity-90 disabled:opacity-50 transition-opacity duration-150"
              aria-label="Send message"
            >
              Send
            </button>
          </div>
          <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
            Enter to send, Shift+Enter for new line, Escape to clear
          </p>
        </div>
      </div>
    </DragDropZone>
  );
}
