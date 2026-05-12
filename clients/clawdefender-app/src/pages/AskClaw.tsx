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
import { useAiStatus } from "../hooks/useAiStatus";
import { Icon, Rook, Badge, Btn } from "../components/design";
import type { AskClawAIResponse, SuggestedAction, ToolCallInfo, ContextReference } from "../types";

// ---------------------------------------------------------------------------
// Types matching the Rust ActionType enum
// ---------------------------------------------------------------------------

interface ActionButtonData {
  id: string;
  label: string;
  action: ActionTypeData;
  style: string;
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
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(iso).toLocaleDateString();
  } catch {
    return "";
  }
}

function groupByDate(iso: string): string {
  try {
    const date = new Date(iso);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - date.getTime()) / 86_400_000);
    if (diffDays === 0) return "Today";
    if (diffDays === 1) return "Yesterday";
    if (diffDays < 7) return "Earlier this week";
    return "Older";
  } catch {
    return "Older";
  }
}

function renderMarkdown(text: string | undefined | null): React.ReactNode[] {
  if (!text) return [text ?? ""];
  const parts: React.ReactNode[] = [];
  // Handle bold, italic, inline code, and links
  const regex = /(\*\*(.+?)\*\*|_(.+?)_|`([^`]+)`|\[(.+?)\]\((.+?)\))/g;
  let lastIndex = 0;
  let match;
  let key = 0;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    if (match[2]) {
      // Bold
      parts.push(<strong key={key++}>{match[2]}</strong>);
    } else if (match[3]) {
      // Italic
      parts.push(<em key={key++}>{match[3]}</em>);
    } else if (match[4]) {
      // Inline code
      parts.push(
        <code key={key++} style={{
          fontFamily: "var(--font-mono)", fontSize: "0.9em",
          padding: "1px 5px", borderRadius: 3,
          background: "var(--bg-1)", color: "var(--ink-0)",
        }}>{match[4]}</code>
      );
    } else if (match[5] && match[6]) {
      // Link
      parts.push(
        <a key={key++} href={match[6]} style={{ color: "var(--accent)" }} target="_blank" rel="noopener noreferrer">
          {match[5]}
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

const EMPTY_SUGGESTIONS = [
  "What happened today?",
  "Should I worry about shell-runner?",
  "Run a quick checkup",
];

// ---------------------------------------------------------------------------
// Rich Data Renderers
// ---------------------------------------------------------------------------

function StructuredDataCard({ data }: { data: Record<string, unknown> }) {
  const type = data.type as string;

  if (type === "status_summary") {
    const items = (data.items ?? []) as Array<{ label: string; value: string; status: string }>;
    return (
      <div style={{ marginTop: 10, display: "grid", gap: 4 }}>
        {items.map((item) => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 12.5 }}>
            <span style={{ color: "var(--ink-2)" }}>{item.label}</span>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "var(--ink-0)" }}>{item.value}</span>
              <Badge color={item.status === "good" ? "var(--green)" : item.status === "warning" ? "var(--amber)" : "var(--red)"}>
                {item.status === "good" ? "OK" : item.status}
              </Badge>
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
      <div style={{ marginTop: 10, display: "grid", gap: 4 }}>
        {events.map((evt) => (
          <div key={evt.id} style={{
            display: "flex", alignItems: "center", gap: 8, fontSize: 11,
            fontFamily: "var(--font-mono)", padding: "6px 10px",
            background: "var(--bg-1)", borderRadius: 6,
          }}>
            <span style={{ color: "var(--ink-3)", width: 60, flexShrink: 0 }}>{formatRelativeTime(evt.timestamp)}</span>
            <span style={{ color: "var(--accent)", width: 90, flexShrink: 0 }}>{evt.server_name}</span>
            <span style={{ color: "var(--ink-1)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{evt.description}</span>
            <Badge color={evt.decision === "allowed" || evt.decision === "allow" ? "var(--green)" : "var(--red)"}>{evt.decision}</Badge>
          </div>
        ))}
        {total > events.length && (
          <p style={{ fontSize: 10.5, color: "var(--ink-3)", marginTop: 4 }}>...and {total - events.length} more</p>
        )}
      </div>
    );
  }

  if (type === "server_list") {
    const servers = (data.servers ?? []) as Array<{ name: string; wrapped: boolean; status: string; events_count: number }>;
    return (
      <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8 }}>
        {servers.map((srv) => (
          <div key={srv.name} style={{ padding: 12, background: "var(--bg-1)", borderRadius: 8, border: "1px solid var(--line)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--ink-0)" }}>{srv.name}</span>
              <span style={{ width: 7, height: 7, borderRadius: 999, background: srv.status === "running" ? "var(--green)" : "var(--ink-3)" }} />
            </div>
            <div style={{ fontSize: 11, color: "var(--ink-2)" }}>{srv.events_count} events{srv.wrapped ? " | wrapped" : ""}</div>
          </div>
        ))}
      </div>
    );
  }

  if (type === "metric") {
    return (
      <div style={{ marginTop: 10, display: "flex", alignItems: "baseline", gap: 8 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--ink-0)" }}>{data.value as string}</span>
        <span style={{ fontSize: 12.5, color: "var(--ink-2)" }}>{data.label as string}</span>
      </div>
    );
  }

  if (type === "risk_assessment") {
    const riskLevel = data.risk_level as string;
    const riskColor = riskLevel === "critical" || riskLevel === "high" ? "var(--red)" : riskLevel === "medium" ? "var(--amber)" : "var(--green)";
    return (
      <div style={{ marginTop: 10, padding: 12, borderRadius: 10, border: `1px solid ${riskColor}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <Badge color={riskColor}>{riskLevel.toUpperCase()}</Badge>
          <span style={{ fontSize: 12.5, color: "var(--ink-0)" }}>{data.subject as string}</span>
        </div>
        <p style={{ fontSize: 12.5, color: "var(--ink-2)", margin: 0 }}>{data.explanation as string}</p>
      </div>
    );
  }

  if (type === "ai_tool_calls") {
    const suggestedActions = (data.suggested_actions ?? []) as Array<{ id: string; action_type: string; label: string; description: string; requires_confirmation: boolean }>;
    const contextRefs = (data.context_references ?? data.context_refs ?? []) as Array<{ ref_type: string; id: string; label: string }>;

    return (
      <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
        {suggestedActions.length > 0 && (
          <div style={{ display: "grid", gap: 4 }}>
            {suggestedActions.map((action) => (
              <div key={action.id} style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: 10, borderRadius: 8, border: "1px solid var(--accent-line)", background: "var(--bg-1)",
              }}>
                <div style={{ flex: 1 }}>
                  <Icon name="sparkles" size={13} color="var(--accent)" />
                  <span style={{ fontSize: 12, marginLeft: 6, color: "var(--ink-0)" }}>{action.label || action.description}</span>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  <Btn size="sm" kind="primary" onClick={async () => { try { await invoke("approve_claw_action", { actionId: action.id }); } catch { /* ok */ } }}>Apply</Btn>
                  <Btn size="sm" kind="ghost" onClick={async () => { try { await invoke("reject_claw_action", { actionId: action.id }); } catch { /* ok */ } }}>Not now</Btn>
                </div>
              </div>
            ))}
          </div>
        )}
        {contextRefs.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {contextRefs.map((ref, i) => (
              <span key={i} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: "var(--bg-1)", color: "var(--accent)" }} title={`${ref.ref_type}: ${ref.id}`}>
                {ref.label}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (type === "scan_summary") {
    return (
      <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 12, fontSize: 12.5 }}>
        <span style={{ color: "var(--ink-0)", fontWeight: 500 }}>{data.total_findings as number} findings</span>
        {(data.critical as number) > 0 && <span style={{ color: "var(--red)" }}>{data.critical as number} critical</span>}
        {(data.high as number) > 0 && <span style={{ color: "var(--amber)" }}>{data.high as number} high</span>}
      </div>
    );
  }

  return null;
}

// ---------------------------------------------------------------------------
// ToolChip — inline tool-use display inside Rook bubbles
// ---------------------------------------------------------------------------

function ToolChip({ tool }: { tool: { tool_name: string; summary: string; args?: string; result?: string } }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex", alignItems: "center", gap: 6,
          fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-2)",
          background: "none", border: "none", cursor: "pointer", padding: "2px 0",
        }}
      >
        <Icon name="wrench" size={11} color="var(--accent)" />
        <span style={{ color: "var(--accent)" }}>{tool.tool_name}</span>
        {tool.args && <span style={{ color: "var(--ink-3)" }}>({tool.args})</span>}
        <span style={{ color: "var(--green)" }}>&#10003;</span>
        {tool.summary && <span>{tool.summary}</span>}
      </button>
      {expanded && (tool.result || tool.args) && (
        <div style={{
          marginTop: 4, marginLeft: 17, padding: "8px 10px",
          fontFamily: "var(--font-mono)", fontSize: 10.5,
          background: "var(--bg-0)", border: "1px solid var(--line)",
          borderRadius: 8, color: "var(--ink-1)", whiteSpace: "pre-wrap",
          maxHeight: 200, overflowY: "auto",
        }} className="cd-scroll">
          {tool.result ?? tool.args ?? ""}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SystemRow — centered status line with hairlines
// ---------------------------------------------------------------------------

function SystemRow({ text }: { text: string }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      maxWidth: 360, margin: "0 auto", padding: "4px 0",
    }}>
      <div style={{ flex: 1, height: 1, background: "var(--line-soft)" }} />
      <span style={{ fontSize: 11.5, color: "var(--ink-3)", whiteSpace: "nowrap" }}>{text}</span>
      <div style={{ flex: 1, height: 1, background: "var(--line-soft)" }} />
    </div>
  );
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
  const [aiMode, setAiMode] = useState<string | null>(null);
  const [, setBackendPref] = useState<"cloud" | "local" | "auto">("auto");
  const [, setLastToolCalls] = useState<ToolCallInfo[]>([]);
  const [, setLastSuggestedActions] = useState<SuggestedAction[]>([]);
  const [, setLastContextRefs] = useState<ContextReference[]>([]);
  const [composerFocused, setComposerFocused] = useState(false);
  const userScrolledRef = useRef(false);

  const daemonRunning = useEventStore((s) => s.daemonRunning);
  const { status: aiStatus } = useAiStatus();
  const {
    messages, isLoading, conversationId, conversations,
    loadLatestConversation, startNewConversation, addUserMessage, addClawResponse,
    setCurrentPage, loadConversation, listConversations, deleteConversation,
  } = useConversationStore();

  useEffect(() => { setCurrentPage("/ask"); }, [setCurrentPage]);

  useEffect(() => {
    invoke<string>("get_ask_claw_mode")
      .then((mode) => { try { setAiMode(JSON.parse(mode)); } catch { setAiMode(mode); } })
      .catch(() => setAiMode("Pattern"));
    invoke<string>("get_ask_claw_backend")
      .then((pref) => setBackendPref(pref as "cloud" | "local" | "auto"))
      .catch(() => {});
  }, []);

  useEffect(() => { loadLatestConversation(); }, [loadLatestConversation]);
  useEffect(() => { listConversations(); }, [listConversations]);

  useEffect(() => {
    const state = location.state as { question?: string } | null;
    if (state?.question) {
      setInputValue(state.question);
      window.history.replaceState({}, "");
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [location.state]);

  // Auto-scroll: scroll to bottom on new messages unless user scrolled up
  useEffect(() => {
    if (feedRef.current && !userScrolledRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [messages, isThinking]);

  // Detect user scroll to freeze auto-scroll
  useEffect(() => {
    const el = feedRef.current;
    if (!el) return;
    const onScroll = () => {
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
      userScrolledRef.current = !atBottom;
    };
    el.addEventListener("scroll", onScroll);
    return () => el.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!isThinking && messages.length > 0) inputRef.current?.focus();
  }, [isThinking, messages.length]);

  // Auto-grow textarea
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`; // max ~5 lines
  }, [inputValue]);

  // ⌘N for new chat
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "n") {
        e.preventDefault();
        startNewConversation();
        setPendingConfirmations(new Map());
        requestAnimationFrame(() => inputRef.current?.focus());
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [startNewConversation]);

  const lastIntentId = [...messages].reverse().find((m) => m.role === "claw")?.intentId;

  // Derive the "Powered by" pill from the latest Rook message
  const latestClawMsg = [...messages].reverse().find((m) => m.role === "claw");
  const poweredByCloud = aiMode === "Cloud" || (latestClawMsg?.contentRichJson?.includes("ai_tool_calls"));
  const poweredByLabel = poweredByCloud
    ? (aiStatus?.cloud.provider ? `claude-haiku-4-5` : "Claude")
    : (aiStatus?.local.model_name ?? "local-llama-7b");

  const submitMessage = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isThinking) return;
    setInputValue("");
    setError(null);
    setMessageHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setIsThinking(true);
    userScrolledRef.current = false; // re-enable auto-scroll on send
    await addUserMessage(trimmed);

    try {
      let aiHandled = false;
      if (aiMode === "Cloud" || aiMode === "LocalSlm") {
        try {
          const contextJson = useConversationStore.getState().getContextJson();
          const aiResponseStr = await invoke<string>("ask_claw_ai", { input: trimmed, contextJson });
          const aiResponse: AskClawAIResponse = JSON.parse(aiResponseStr);
          setLastToolCalls(aiResponse.tool_calls ?? []);
          setLastSuggestedActions(aiResponse.suggested_actions ?? []);
          setLastContextRefs(aiResponse.context_refs ?? []);
          const clawMsg: ConversationMessage = {
            id: aiResponse.turn_id || `claw-ai-${Date.now()}`,
            role: "claw",
            contentText: aiResponse.message,
            contentRichJson: aiResponse.tool_calls?.length
              ? JSON.stringify({ type: "ai_tool_calls", tool_calls: aiResponse.tool_calls, suggested_actions: aiResponse.suggested_actions, context_references: aiResponse.context_refs })
              : undefined,
            timestamp: aiResponse.timestamp || new Date().toISOString(),
          };
          await addClawResponse(clawMsg);
          aiHandled = true;
        } catch { /* Fall through */ }
      }

      if (!aiHandled) {
        const contextJson = useConversationStore.getState().getContextJson();
        const responseJson = await invoke<string>("ask_claw", { input: trimmed, contextJson });
        const response = JSON.parse(responseJson);
        const clawMsg: ConversationMessage = {
          id: response.turn_id || `claw-${Date.now()}`,
          role: "claw",
          contentText: response.message,
          contentRichJson: response.structured_data ? JSON.stringify(response.structured_data) : undefined,
          actionsJson: response.actions?.length ? JSON.stringify(response.actions) : undefined,
          intentId: response.intent_id,
          timestamp: response.timestamp || new Date().toISOString(),
        };
        await addClawResponse(clawMsg);
        const actions: ActionButtonData[] = response.actions ?? [];
        const confirmAction = actions.find((a: ActionButtonData) => a.requires_confirmation);
        if (confirmAction) {
          setPendingConfirmations((prev) => { const next = new Map(prev); next.set(clawMsg.id, JSON.stringify(confirmAction.action)); return next; });
        }
      }
    } catch (e) { setError(String(e)); }
    finally { setIsThinking(false); }
  }, [isThinking, addUserMessage, addClawResponse, aiMode]);

  const handleAction = useCallback(async (action: ActionTypeData, requiresConfirmation: boolean, msgId?: string) => {
    if (requiresConfirmation && msgId) {
      setPendingConfirmations((prev) => { const next = new Map(prev); next.set(msgId, JSON.stringify(action)); return next; });
      return;
    }
    switch (action.type) {
      case "navigate": navigate(action.page); break;
      case "tauri_command":
        try {
          setIsThinking(true);
          const contextJson = useConversationStore.getState().getContextJson();
          const responseJson = await invoke<string>("confirm_action", { actionJson: JSON.stringify(action), state: contextJson });
          const response = JSON.parse(responseJson);
          await addClawResponse({
            id: response.turn_id || `claw-${Date.now()}`, role: "claw", contentText: response.message,
            contentRichJson: response.structured_data ? JSON.stringify(response.structured_data) : undefined,
            actionsJson: response.actions?.length ? JSON.stringify(response.actions) : undefined,
            intentId: response.intent_id, timestamp: response.timestamp || new Date().toISOString(),
          });
        } catch (e) { setError(String(e)); }
        finally { setIsThinking(false); }
        break;
      case "follow_up": await submitMessage(action.message); break;
      case "copy_to_clipboard": await navigator.clipboard.writeText(action.text); break;
    }
  }, [navigate, submitMessage, addClawResponse]);

  const handleConfirm = useCallback(async (msgId: string) => {
    const actionJson = pendingConfirmations.get(msgId);
    if (!actionJson) return;
    setPendingConfirmations((prev) => { const next = new Map(prev); next.delete(msgId); return next; });
    setIsThinking(true);
    try {
      const contextJson = useConversationStore.getState().getContextJson();
      const responseJson = await invoke<string>("confirm_action", { actionJson, state: contextJson });
      const response = JSON.parse(responseJson);
      await addClawResponse({
        id: response.turn_id || `claw-${Date.now()}`, role: "claw", contentText: response.message,
        contentRichJson: response.structured_data ? JSON.stringify(response.structured_data) : undefined,
        actionsJson: response.actions?.length ? JSON.stringify(response.actions) : undefined,
        intentId: response.intent_id, timestamp: response.timestamp || new Date().toISOString(),
      });
    } catch (e) { setError(String(e)); }
    finally { setIsThinking(false); }
  }, [pendingConfirmations, addClawResponse]);

  const handleCancelConfirm = useCallback(async (msgId: string) => {
    setPendingConfirmations((prev) => { const next = new Map(prev); next.delete(msgId); return next; });
    await addClawResponse({ id: `cancel-${Date.now()}`, role: "claw", contentText: ASK_CLAW.confirmCancelled, timestamp: new Date().toISOString() });
  }, [addClawResponse]);

  const handleFileDrop = useCallback(async (path: string) => {
    await addUserMessage(`Analyze this file for security risks:\n${path}`);
    setIsThinking(true);
    try {
      const isConfig = /\.(json|ya?ml|toml|ini|conf|cfg)$/i.test(path);
      const resultRaw = await invoke<string>(isConfig ? "analyze_config" : "analyze_file", { path });
      const result = JSON.parse(resultRaw);
      await addClawResponse({
        id: `analysis-${Date.now()}`, role: "claw", contentText: result.summary ?? result.message ?? "Analysis complete.",
        contentRichJson: result.structured_data ? JSON.stringify(result.structured_data) : undefined,
        actionsJson: result.actions?.length ? JSON.stringify(result.actions) : undefined,
        intentId: "analyze.file", timestamp: new Date().toISOString(),
      });
    } catch {
      await addClawResponse({ id: `error-${Date.now()}`, role: "claw", contentText: ASK_CLAW.errorGeneric, timestamp: new Date().toISOString() });
    } finally { setIsThinking(false); }
  }, [addUserMessage, addClawResponse]);

  const handleUrlDrop = useCallback(async (url: string) => {
    await addUserMessage(`[Dropped URL: ${url}]`);
    setIsThinking(true);
    try {
      const resultRaw = await invoke<string>("analyze_url", { url });
      const result = JSON.parse(resultRaw);
      await addClawResponse({
        id: `analysis-${Date.now()}`, role: "claw", contentText: result.summary ?? result.message ?? "Analysis complete.",
        contentRichJson: result.structured_data ? JSON.stringify(result.structured_data) : undefined,
        actionsJson: result.actions?.length ? JSON.stringify(result.actions) : undefined,
        intentId: "analyze.url", timestamp: new Date().toISOString(),
      });
    } catch {
      await addClawResponse({ id: `error-${Date.now()}`, role: "claw", contentText: ASK_CLAW.errorGeneric, timestamp: new Date().toISOString() });
    } finally { setIsThinking(false); }
  }, [addUserMessage, addClawResponse]);

  function handleInputKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      submitMessage(inputValue);
    } else if (e.key === "Escape") {
      inputRef.current?.blur();
    } else if (e.key === "ArrowUp" && inputValue === "") {
      e.preventDefault();
      if (messageHistory.length > 0) {
        const newIndex = historyIndex === -1 ? messageHistory.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setInputValue(messageHistory[newIndex]);
      }
    }
  }

  function parseActions(msg: ConversationMessage): ActionButtonData[] {
    if (!msg.actionsJson) return [];
    try { return JSON.parse(msg.actionsJson); } catch { return []; }
  }

  function parseRichData(msg: ConversationMessage): Record<string, unknown> | null {
    if (!msg.contentRichJson) return null;
    try { return JSON.parse(msg.contentRichJson); } catch { return null; }
  }

  const isEmpty = messages.length === 0 && !isLoading;
  const showDaemonWarning = !daemonRunning;
  const suggestions = getSuggestions(lastIntentId);

  // Group conversations by date
  const grouped = conversations.reduce<Record<string, typeof conversations>>((acc, conv) => {
    const group = groupByDate(conv.updatedAt);
    if (!acc[group]) acc[group] = [];
    acc[group].push(conv);
    return acc;
  }, {});
  const groupOrder = ["Today", "Yesterday", "Earlier this week", "Older"];

  return (
    <DragDropZone onFileDrop={handleFileDrop} onUrlDrop={handleUrlDrop}>
      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", height: "100%" }}>
        {/* ─── Left sidebar ─── */}
        <aside style={{
          borderRight: "1px solid var(--line)",
          background: "var(--bg-1)",
          display: "flex", flexDirection: "column",
          overflow: "hidden",
        }}>
          {/* New chat button */}
          <div style={{ padding: "14px 14px 10px" }}>
            <button
              onClick={() => { startNewConversation(); setPendingConfirmations(new Map()); requestAnimationFrame(() => inputRef.current?.focus()); }}
              style={{
                width: "100%", display: "flex", alignItems: "center", gap: 10,
                padding: "10px 12px", borderRadius: 8,
                background: "transparent", border: "1px solid var(--line)",
                cursor: "pointer", color: "var(--ink-0)",
              }}
            >
              <div style={{
                width: 24, height: 24, borderRadius: 6,
                background: "var(--accent-soft)",
                display: "grid", placeItems: "center", flexShrink: 0,
              }}>
                <Rook size={13} color="var(--accent)" />
              </div>
              <span style={{ flex: 1, fontSize: 13, fontWeight: 500, textAlign: "left" }}>New chat</span>
              <kbd style={{
                fontSize: 10, color: "var(--ink-3)",
                padding: "2px 5px", borderRadius: 4,
                background: "var(--bg-2)", border: "1px solid var(--line)",
                fontFamily: "var(--font-ui)",
              }}>&#8984;N</kbd>
            </button>
          </div>

          {/* Conversation list */}
          <div style={{ flex: 1, overflowY: "auto", padding: "0 10px 14px" }} className="cd-scroll">
            {conversations.length === 0 && (
              <p style={{ fontSize: 11, color: "var(--ink-3)", textAlign: "center", padding: "20px 4px" }}>No conversations yet</p>
            )}
            {groupOrder.map((group) => {
              const items = grouped[group];
              if (!items || items.length === 0) return null;
              return (
                <div key={group}>
                  <div style={{
                    fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase",
                    letterSpacing: 0.5, padding: "12px 4px 6px", fontWeight: 500,
                  }}>{group}</div>
                  {items.map((conv) => {
                    const isActive = conv.id === conversationId;
                    return (
                      <button
                        key={conv.id}
                        onClick={() => { loadConversation(conv.id); setPendingConfirmations(new Map()); }}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          if (confirm("Delete this conversation?")) {
                            deleteConversation(conv.id);
                          }
                        }}
                        style={{
                          width: "100%", textAlign: "left",
                          padding: "9px 10px", borderRadius: 6, marginBottom: 1,
                          background: isActive ? "var(--accent-soft)" : "transparent",
                          color: isActive ? "var(--ink-0)" : "var(--ink-2)",
                          border: "none", cursor: "pointer",
                          display: "flex", alignItems: "stretch", gap: 0,
                          position: "relative",
                        }}
                      >
                        {/* Active left edge */}
                        {isActive && (
                          <div style={{
                            position: "absolute", left: 0, top: 0, bottom: 0,
                            width: 4, borderRadius: 2,
                            background: "var(--accent)",
                          }} />
                        )}
                        <div style={{ flex: 1, minWidth: 0, paddingLeft: isActive ? 6 : 0 }}>
                          <div style={{
                            fontSize: 14, fontWeight: 500,
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                            color: isActive ? "var(--ink-0)" : "var(--ink-1)",
                          }}>
                            {conv.lastMessagePreview || conv.summary || "Empty conversation"}
                          </div>
                          <div style={{
                            fontSize: 12, color: "var(--ink-3)", marginTop: 2,
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                          }}>
                            {conv.lastMessagePreview ? conv.lastMessagePreview.slice(0, 60) : ""}
                          </div>
                        </div>
                        <span style={{
                          fontSize: 10, color: "var(--ink-3)", fontFamily: "var(--font-mono)",
                          flexShrink: 0, marginLeft: 8, alignSelf: "flex-start", marginTop: 3,
                        }}>
                          {formatRelativeTime(conv.updatedAt)}
                        </span>
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </aside>

        {/* ─── Right pane ─── */}
        <div style={{ display: "grid", gridTemplateRows: "auto 1fr auto", overflow: "hidden" }}>
          {/* Header bar — 56px, sticky */}
          <div style={{
            height: 56, padding: "0 20px",
            borderBottom: "1px solid var(--line)",
            background: "var(--bg-1)",
            display: "flex", alignItems: "center", gap: 10,
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: "var(--accent-soft)",
              display: "grid", placeItems: "center", flexShrink: 0,
            }}>
              <Rook size={18} color="var(--accent)" />
            </div>
            <div style={{ flex: 1 }}>
              <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: "var(--ink-0)" }}>
                {conversations.find((c) => c.id === conversationId)?.summary
                  ?? conversations.find((c) => c.id === conversationId)?.lastMessagePreview
                  ?? "Ask Rook"}
              </h2>
              <div style={{ fontSize: 12, color: "var(--ink-3)" }}>Asking Rook</div>
            </div>
            {/* Powered by pill */}
            <div
              title={poweredByCloud ? "Cloud AI model in use" : "Local model answering"}
              style={{
                display: "inline-flex", alignItems: "center", gap: 5,
                padding: "4px 10px", borderRadius: 999,
                background: poweredByCloud ? "color-mix(in oklch, var(--violet) 10%, transparent)" : "var(--bg-2)",
                border: `1px solid ${poweredByCloud ? "color-mix(in oklch, var(--violet) 25%, transparent)" : "var(--line)"}`,
                fontSize: 11, fontFamily: "var(--font-mono)",
                color: poweredByCloud ? "var(--violet)" : "var(--ink-2)",
              }}
            >
              {poweredByCloud && <Icon name="cloud" size={10} color="var(--violet)" />}
              {poweredByLabel}
            </div>
          </div>

          {/* Messages area */}
          <div ref={feedRef} className="cd-scroll" style={{ overflowY: "auto", padding: "20px 24px" }}>
            {showDaemonWarning && (
              <div style={{ padding: 12, marginBottom: 16, borderRadius: 10, background: "var(--amber-soft)", border: "1px solid color-mix(in oklch, var(--amber) 30%, transparent)", fontSize: 12.5, color: "var(--ink-1)", maxWidth: 760, margin: "0 auto 16px" }}>
                {ASK_CLAW.offlineMessage}
              </div>
            )}
            {isLoading && <div style={{ display: "flex", justifyContent: "center", padding: "40px 0", color: "var(--ink-3)" }}>Loading conversation...</div>}

            {/* Empty state */}
            {isEmpty && !isLoading && (
              <div style={{
                display: "flex", flexDirection: "column", alignItems: "center",
                justifyContent: "center", padding: "80px 0", textAlign: "center",
              }}>
                <div style={{
                  width: 56, height: 56, borderRadius: 14,
                  background: "var(--accent-soft)",
                  display: "grid", placeItems: "center", marginBottom: 20,
                }}>
                  <Rook size={28} color="var(--accent)" />
                </div>
                <h2 style={{ margin: 0, fontSize: 22, fontWeight: 600, color: "var(--ink-0)" }}>
                  What can I help you check?
                </h2>
                <div style={{ display: "grid", gap: 8, marginTop: 24 }}>
                  {EMPTY_SUGGESTIONS.map((s) => (
                    <button key={s} onClick={() => submitMessage(s)}
                      style={{
                        padding: "8px 14px", fontSize: 13.5,
                        borderRadius: 999, border: "1px solid var(--line)",
                        background: "transparent", color: "var(--ink-1)",
                        cursor: "pointer",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-2)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >{s}</button>
                  ))}
                </div>
              </div>
            )}

            {/* Message bubbles */}
            <div style={{ maxWidth: 760, margin: "0 auto", display: "grid", gap: 16 }}>
              {messages.map((msg) => {
                const actions = parseActions(msg);
                const richData = parseRichData(msg);
                const isUser = msg.role === "user";
                const hasConfirmation = pendingConfirmations.has(msg.id);
                const toolCalls = richData?.type === "ai_tool_calls"
                  ? (richData.tool_calls as Array<{ tool_name: string; summary: string; args?: string; result?: string }>) ?? []
                  : [];

                return (
                  <div key={msg.id}>
                    {isUser ? (
                      /* ── User bubble ── */
                      <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <div style={{ maxWidth: "80%" }}>
                          <div style={{
                            padding: "10px 14px",
                            background: "var(--accent)", color: "white",
                            borderRadius: 16, borderBottomRightRadius: 4,
                            fontSize: 14, lineHeight: 1.5,
                          }}>
                            <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{msg.contentText}</p>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--ink-3)", textAlign: "right", marginTop: 4 }}>
                            {formatRelativeTime(msg.timestamp)}
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* ── Rook bubble ── */
                      <div style={{ display: "flex", gap: 10 }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: 7,
                          background: "var(--accent-soft)",
                          display: "grid", placeItems: "center",
                          flexShrink: 0, marginTop: 2,
                        }}>
                          <Rook size={16} color="var(--accent)" />
                        </div>
                        <div style={{ flex: 1, minWidth: 0, maxWidth: "80%" }}>
                          {/* Tool-use chips */}
                          {toolCalls.length > 0 && (
                            <div style={{ marginBottom: 8, display: "grid", gap: 4 }}>
                              {toolCalls.map((t, j) => (
                                <ToolChip key={j} tool={t} />
                              ))}
                            </div>
                          )}
                          <div style={{
                            padding: "10px 14px",
                            background: "var(--bg-2)", color: "var(--ink-0)",
                            border: "1px solid var(--line-soft)",
                            borderRadius: 16, borderBottomLeftRadius: 4,
                            fontSize: 14, lineHeight: 1.5,
                          }}>
                            <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{renderMarkdown(msg.contentText)}</p>
                            {richData && <StructuredDataCard data={richData} />}
                            {/* Action buttons */}
                            {actions.length > 0 && !hasConfirmation && (
                              <div style={{ marginTop: 12, display: "flex", flexWrap: "wrap", gap: 6 }}>
                                {actions.map((action) => (
                                  <Btn key={action.id} size="sm"
                                    kind={action.style === "primary" ? "primary" : action.style === "danger" ? "danger" : "soft"}
                                    onClick={() => handleAction(action.action, action.requires_confirmation, msg.id)}>
                                    {action.label}
                                  </Btn>
                                ))}
                              </div>
                            )}
                          </div>
                          {hasConfirmation && <ConfirmationCard description={msg.contentText} onConfirm={() => handleConfirm(msg.id)} onCancel={() => handleCancelConfirm(msg.id)} />}
                          <div style={{ fontSize: 11, color: "var(--ink-3)", marginTop: 4 }}>
                            {formatRelativeTime(msg.timestamp)}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Typing indicator */}
              {isThinking && (
                <div style={{ display: "flex", gap: 10 }}>
                  <div style={{
                    width: 28, height: 28, borderRadius: 7,
                    background: "var(--accent-soft)",
                    display: "grid", placeItems: "center", flexShrink: 0,
                  }}>
                    <Rook size={16} color="var(--accent)" />
                  </div>
                  <div style={{
                    padding: "12px 16px",
                    background: "var(--bg-2)",
                    border: "1px solid var(--line-soft)",
                    borderRadius: 16, borderBottomLeftRadius: 4,
                    display: "flex", gap: 5, alignItems: "center",
                  }}>
                    {[0, 1, 2].map((i) => (
                      <span key={i} className="cd-typing-dot" style={{
                        width: 6, height: 6, borderRadius: 999,
                        background: "var(--accent)",
                        animationDelay: `${i * 0.15}s`,
                      }} />
                    ))}
                  </div>
                </div>
              )}

              {/* Error */}
              {error && (
                <div>
                  <SystemRow text="Something went wrong" />
                  <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: 7,
                      background: "var(--red-soft)",
                      display: "grid", placeItems: "center", flexShrink: 0,
                    }}>
                      <Rook size={16} color="var(--red)" />
                    </div>
                    <div style={{
                      padding: "10px 14px", borderRadius: 16, borderBottomLeftRadius: 4,
                      background: "var(--bg-2)", border: "1px solid var(--line-soft)",
                      fontSize: 14, color: "var(--ink-0)",
                    }}>
                      <p style={{ margin: 0 }}>{ASK_CLAW.errorGeneric}</p>
                      <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
                        <Btn size="sm" kind="primary" onClick={() => { setError(null); if (messageHistory.length > 0) submitMessage(messageHistory[messageHistory.length - 1]); }}>{ASK_CLAW.errorRetry}</Btn>
                        <Btn size="sm" kind="ghost" onClick={() => setError(null)}>Dismiss</Btn>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ─── Composer ─── */}
          <div style={{ padding: "16px 20px", borderTop: "1px solid var(--line)" }}>
            {/* Suggestion chips (shown after messages, not during thinking) */}
            {messages.length > 0 && !isThinking && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10, maxWidth: 760, margin: "0 auto 10px" }}>
                {suggestions.map((s) => (
                  <button key={s} onClick={() => submitMessage(s)} disabled={isThinking}
                    style={{
                      padding: "5px 12px", fontSize: 11, borderRadius: 999,
                      border: "1px solid var(--line)", background: "var(--bg-2)",
                      color: "var(--ink-2)", cursor: "pointer",
                    }}>
                    {s}
                  </button>
                ))}
              </div>
            )}
            <div style={{
              maxWidth: 760, margin: "0 auto",
              borderRadius: 14,
              border: `1px solid ${composerFocused ? "var(--accent)" : "var(--line)"}`,
              background: "var(--bg-1)",
              transition: "border-color 0.15s",
              overflow: "hidden",
            }}>
              {/* Textarea */}
              <textarea
                ref={inputRef}
                id="ask-claw-input"
                data-ask-claw-input
                rows={1}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleInputKeyDown}
                onFocus={() => setComposerFocused(true)}
                onBlur={() => setComposerFocused(false)}
                placeholder={"Ask Rook anything\u2026"}
                disabled={isThinking}
                style={{
                  width: "100%", display: "block",
                  background: "transparent", border: "none", outline: "none",
                  color: "var(--ink-0)", fontSize: 14, lineHeight: 1.5,
                  resize: "none", padding: "12px 14px",
                  minHeight: 22, maxHeight: 120,
                }}
              />
              {/* Bottom row */}
              <div style={{
                display: "flex", alignItems: "center",
                padding: "8px 10px",
                borderTop: "1px solid var(--line-soft)",
              }}>
                <div style={{ display: "flex", gap: 2 }}>
                  <button
                    title="Add context"
                    style={{
                      width: 30, height: 30, borderRadius: 6,
                      display: "grid", placeItems: "center",
                      background: "transparent", border: "none",
                      color: "var(--ink-3)", cursor: "pointer",
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-2)"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  >
                    <Icon name="paperclip" size={15} color="var(--ink-3)" />
                  </button>
                  <button
                    title="Suggest a question"
                    style={{
                      width: 30, height: 30, borderRadius: 6,
                      display: "grid", placeItems: "center",
                      background: "transparent", border: "none",
                      color: "var(--ink-3)", cursor: "pointer",
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-2)"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  >
                    <Icon name="sparkles" size={15} color="var(--ink-3)" />
                  </button>
                </div>
                <div style={{ flex: 1 }} />
                <button
                  onClick={() => submitMessage(inputValue)}
                  disabled={!inputValue.trim() || isThinking}
                  style={{
                    width: 32, height: 32, borderRadius: 8,
                    background: inputValue.trim() ? "var(--accent)" : "var(--bg-3)",
                    color: "white",
                    display: "grid", placeItems: "center",
                    cursor: inputValue.trim() ? "pointer" : "default",
                    opacity: inputValue.trim() ? 1 : 0.4,
                    border: "none",
                    transition: "background 0.15s, opacity 0.15s",
                  }}
                >
                  <Icon name="send" size={15} color="white" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DragDropZone>
  );
}
