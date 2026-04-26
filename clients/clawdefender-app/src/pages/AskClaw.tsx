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
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(iso).toLocaleDateString();
  } catch {
    return "";
  }
}

function renderMarkdown(text: string | undefined | null): React.ReactNode[] {
  if (!text) return [text ?? ""];
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
        <a key={key++} href={match[4]} style={{ color: "var(--accent)" }} target="_blank" rel="noopener noreferrer">
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
            background: "var(--bg-2)", borderRadius: 6,
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
          <div key={srv.name} style={{ padding: 12, background: "var(--bg-2)", borderRadius: 8, border: "1px solid var(--line)" }}>
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
              <span key={i} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: "var(--bg-2)", color: "var(--accent)" }} title={`${ref.ref_type}: ${ref.id}`}>
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
  const [backendPref, setBackendPref] = useState<"cloud" | "local" | "auto">("auto");
  const [switchingBackend, setSwitchingBackend] = useState(false);
  const [, setLastToolCalls] = useState<ToolCallInfo[]>([]);
  const [, setLastSuggestedActions] = useState<SuggestedAction[]>([]);
  const [, setLastContextRefs] = useState<ContextReference[]>([]);

  const daemonRunning = useEventStore((s) => s.daemonRunning);
  const { status: aiStatus, cloudActive, localActive } = useAiStatus();
  const {
    messages, isLoading, conversationId, conversations,
    loadLatestConversation, startNewConversation, addUserMessage, addClawResponse,
    setCurrentPage, loadConversation, listConversations,
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

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [messages, isThinking]);

  useEffect(() => {
    if (!isThinking && messages.length > 0) inputRef.current?.focus();
  }, [isThinking, messages.length]);

  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 96)}px`;
  }, [inputValue]);

  const lastIntentId = [...messages].reverse().find((m) => m.role === "claw")?.intentId;

  const switchBackend = useCallback(async (target: "cloud" | "local") => {
    if (target === backendPref || switchingBackend) return;
    setSwitchingBackend(true);
    try {
      const modeStr = await invoke<string>("set_ask_claw_backend", { backend: target });
      setBackendPref(target);
      try { setAiMode(JSON.parse(modeStr)); } catch { setAiMode(modeStr); }
    } catch (err) { console.error("Failed to switch backend:", err); }
    finally { setSwitchingBackend(false); }
  }, [backendPref, switchingBackend]);

  const submitMessage = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isThinking) return;
    setInputValue("");
    setError(null);
    setMessageHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setIsThinking(true);
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
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submitMessage(inputValue); }
    else if (e.key === "Escape") { setInputValue(""); }
    else if (e.key === "ArrowUp" && inputValue === "") {
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

  return (
    <DragDropZone onFileDrop={handleFileDrop} onUrlDrop={handleUrlDrop}>
      <div style={{ display: "grid", gridTemplateColumns: "240px 1fr", height: "100%" }}>
        {/* Conversation sidebar */}
        <aside style={{ borderRight: "1px solid var(--line)", padding: 14, background: "var(--bg-1)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <Btn kind="accent" icon="sparkles" style={{ width: "100%", justifyContent: "center", marginBottom: 12 }}
            onClick={() => { startNewConversation(); setPendingConfirmations(new Map()); }}>
            New conversation
          </Btn>
          <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8, padding: "0 4px" }}>History</div>
          <div style={{ flex: 1, overflowY: "auto" }} className="cd-scroll">
            {conversations.length === 0 && (
              <p style={{ fontSize: 11, color: "var(--ink-3)", textAlign: "center", padding: "20px 4px" }}>No conversations yet</p>
            )}
            {conversations.map((conv) => {
              const isActive = conv.id === conversationId;
              return (
                <button key={conv.id}
                  onClick={() => { loadConversation(conv.id); setPendingConfirmations(new Map()); }}
                  style={{
                    width: "100%", textAlign: "left", padding: "9px 10px", borderRadius: 6, marginBottom: 2,
                    background: isActive ? "var(--bg-2)" : "transparent",
                    color: isActive ? "var(--ink-0)" : "var(--ink-2)",
                    border: "none", cursor: "pointer",
                  }}>
                  <div style={{ fontSize: 12, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {conv.lastMessagePreview || conv.summary || "Empty conversation"}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--ink-3)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                    {formatRelativeTime(conv.updatedAt)}
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        {/* Chat area */}
        <div style={{ display: "grid", gridTemplateRows: "auto 1fr auto", overflow: "hidden" }}>
          {/* Header */}
          <div style={{ padding: "14px 24px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 10 }}>
            <Icon name="chat" size={15} color="var(--accent)" />
            <h2 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "var(--ink-0)", flex: 1 }}>Ask Rook</h2>
            <Badge color="var(--violet)" mono>
              <Icon name="cloud" size={10} color="var(--violet)" />
              {aiMode === "Cloud" ? `Powered by ${aiStatus?.cloud.provider ?? "Claude"}` : aiMode === "LocalSlm" ? `Local: ${aiStatus?.local.model_name ?? "SLM"}` : "Offline"}
            </Badge>
            {(cloudActive || localActive) && (
              <div style={{ display: "flex", borderRadius: 6, border: "1px solid var(--line)", overflow: "hidden" }}>
                <button onClick={() => switchBackend("cloud")} disabled={!cloudActive || switchingBackend}
                  style={{
                    padding: "4px 10px", fontSize: 11, fontWeight: 500, border: "none", cursor: cloudActive ? "pointer" : "not-allowed",
                    background: (backendPref === "cloud" || (backendPref === "auto" && aiMode === "Cloud")) ? "var(--accent)" : "transparent",
                    color: (backendPref === "cloud" || (backendPref === "auto" && aiMode === "Cloud")) ? "white" : "var(--ink-2)",
                    opacity: cloudActive ? 1 : 0.4,
                  }}>Cloud</button>
                <button onClick={() => switchBackend("local")} disabled={!localActive || switchingBackend}
                  style={{
                    padding: "4px 10px", fontSize: 11, fontWeight: 500, border: "none", cursor: localActive ? "pointer" : "not-allowed",
                    background: (backendPref === "local" || (backendPref === "auto" && aiMode === "LocalSlm")) ? "var(--accent)" : "transparent",
                    color: (backendPref === "local" || (backendPref === "auto" && aiMode === "LocalSlm")) ? "white" : "var(--ink-2)",
                    opacity: localActive ? 1 : 0.4,
                  }}>Local</button>
              </div>
            )}
          </div>

          {/* Messages */}
          <div ref={feedRef} className="cd-scroll" style={{ overflowY: "auto", padding: "20px 24px" }}>
            {showDaemonWarning && (
              <div style={{ padding: 12, marginBottom: 16, borderRadius: 10, background: "var(--amber-soft)", border: "1px solid color-mix(in oklch, var(--amber) 30%, transparent)", fontSize: 12.5, color: "var(--ink-1)" }}>
                {ASK_CLAW.offlineMessage}
              </div>
            )}
            {isLoading && <div style={{ display: "flex", justifyContent: "center", padding: "40px 0", color: "var(--ink-3)" }}>Loading conversation...</div>}

            {isEmpty && !isLoading && (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", textAlign: "center" }}>
                <div style={{ width: 48, height: 48, borderRadius: 999, background: "var(--accent-soft)", display: "grid", placeItems: "center", marginBottom: 16 }}>
                  <Rook size={24} color="var(--accent)" />
                </div>
                <p style={{ fontSize: 14, color: "var(--ink-0)", marginBottom: 4 }}>{ASK_CLAW.firstTimeGreeting}</p>
                <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: 8, marginTop: 20 }}>
                  {ASK_CLAW.suggestions.default.map((s) => (
                    <button key={s} onClick={() => submitMessage(s)}
                      style={{ padding: "7px 14px", fontSize: 12, borderRadius: 999, border: "1px solid var(--line)", background: "transparent", color: "var(--ink-2)", cursor: "pointer" }}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div style={{ maxWidth: 760, margin: "0 auto", display: "grid", gap: 16 }}>
              {messages.map((msg) => {
                const actions = parseActions(msg);
                const richData = parseRichData(msg);
                const isUser = msg.role === "user";
                const hasConfirmation = pendingConfirmations.has(msg.id);
                return (
                  <div key={msg.id}>
                    {isUser ? (
                      <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <div style={{ maxWidth: "75%", padding: "10px 14px", background: "var(--accent-soft)", border: "1px solid var(--accent-line)", borderRadius: 10, fontSize: 13, color: "var(--ink-0)" }}>
                          <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{renderMarkdown(msg.contentText)}</p>
                        </div>
                      </div>
                    ) : (
                      <div style={{ display: "flex", gap: 10 }}>
                        <div style={{ width: 28, height: 28, borderRadius: 999, flexShrink: 0, background: "var(--accent-soft)", display: "grid", placeItems: "center", marginTop: 2 }}>
                          <Rook size={16} color="var(--accent)" />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          {/* Tool call chips */}
                          {richData && richData.type === "ai_tool_calls" && (richData.tool_calls as Array<{ tool_name: string; summary: string }>)?.length > 0 && (
                            <div style={{ marginBottom: 10, display: "grid", gap: 4 }}>
                              {(richData.tool_calls as Array<{ tool_name: string; summary: string }>).map((t, j) => (
                                <div key={j} style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-3)" }}>
                                  <Icon name="search" size={11} color="var(--accent)" />
                                  <span style={{ color: "var(--accent)" }}>{t.tool_name}</span>
                                  <span>&rarr;</span>
                                  <span>{t.summary}</span>
                                </div>
                              ))}
                            </div>
                          )}
                          <div style={{ padding: "10px 14px", borderRadius: 10, background: "var(--bg-2)", fontSize: 13.5, color: "var(--ink-0)", lineHeight: 1.6 }}>
                            <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{renderMarkdown(msg.contentText)}</p>
                            {richData && <StructuredDataCard data={richData} />}
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
                          <div style={{ fontSize: 10, color: "var(--ink-3)", marginTop: 4 }}>{formatRelativeTime(msg.timestamp)}</div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {isThinking && (
                <div style={{ display: "flex", gap: 10 }}>
                  <div style={{ width: 28, height: 28, borderRadius: 999, flexShrink: 0, background: "var(--accent-soft)", display: "grid", placeItems: "center" }}>
                    <Rook size={16} color="var(--accent)" />
                  </div>
                  <div style={{ padding: "10px 14px", borderRadius: 10, background: "var(--bg-2)", fontSize: 13, color: "var(--ink-2)" }}>
                    <span className="cd-pulse">{ASK_CLAW.thinkingIndicator}</span>
                  </div>
                </div>
              )}

              {error && (
                <div style={{ display: "flex", gap: 10 }}>
                  <div style={{ width: 28, height: 28, borderRadius: 999, flexShrink: 0, background: "var(--red-soft)", display: "grid", placeItems: "center" }}>
                    <Rook size={16} color="var(--red)" />
                  </div>
                  <div style={{ padding: "10px 14px", borderRadius: 10, background: "var(--bg-2)", border: "1px solid var(--red)", fontSize: 13, color: "var(--ink-0)" }}>
                    <p style={{ margin: 0 }}>{ASK_CLAW.errorGeneric}</p>
                    <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
                      <Btn size="sm" kind="primary" onClick={() => { setError(null); if (messageHistory.length > 0) submitMessage(messageHistory[messageHistory.length - 1]); }}>{ASK_CLAW.errorRetry}</Btn>
                      <Btn size="sm" kind="ghost" onClick={() => setError(null)}>Dismiss</Btn>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Composer */}
          <div style={{ padding: "14px 24px", borderTop: "1px solid var(--line)" }}>
            {messages.length > 0 && !isThinking && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
                {suggestions.map((s) => (
                  <button key={s} onClick={() => submitMessage(s)} disabled={isThinking}
                    style={{ padding: "5px 12px", fontSize: 11, borderRadius: 999, border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--ink-2)", cursor: "pointer" }}>
                    {s}
                  </button>
                ))}
              </div>
            )}
            <div style={{ maxWidth: 760, margin: "0 auto", display: "flex", gap: 8, alignItems: "flex-end", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12, padding: 10 }}>
              <textarea ref={inputRef} id="ask-claw-input" data-ask-claw-input rows={1}
                value={inputValue} onChange={(e) => setInputValue(e.target.value)} onKeyDown={handleInputKeyDown}
                placeholder="Ask Rook anything -- 'is FileManager safe?', 'block all network for shell-runner'..."
                disabled={isThinking}
                style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "var(--ink-0)", fontSize: 13, resize: "none", minHeight: 22, maxHeight: 120, lineHeight: 1.5 }} />
              <Btn kind={inputValue.trim() ? "primary" : "soft"} icon="send" onClick={() => submitMessage(inputValue)} disabled={!inputValue.trim() || isThinking}>Send</Btn>
            </div>
          </div>
        </div>
      </div>
    </DragDropZone>
  );
}
