/**
 * Frontend types for the Ask Rook conversation UI.
 * These mirror the Rust types from the architecture doc.
 */

export interface ActionButton {
  id: string;
  label: string;
  action: ActionType;
  style: string;
  requires_confirmation: boolean;
}

export type ActionType =
  | { type: "tauri_command"; command: string; params: Record<string, unknown> }
  | { type: "navigate"; page: string; params?: Record<string, string> }
  | { type: "follow_up"; message: string }
  | { type: "copy_to_clipboard"; text: string };

export interface ConversationMessage {
  turnId: string;
  role: "user" | "claw";
  message: string;
  timestamp: string;
  intentId?: string;
  structuredData?: Record<string, unknown>;
  actions?: ActionButton[];
  suggestions?: string[];
}

export interface ConversationResponse {
  turn_id: string;
  message: string;
  structured_data?: Record<string, unknown>;
  actions: ActionButton[];
  intent_id: string;
  confidence: number;
  response_strategy: string;
  timestamp: string;
}

export interface IntentClassification {
  intent_id: string;
  confidence: number;
  entities: Record<string, string>;
  method: string;
}

export interface QueryResult {
  data: Record<string, unknown>;
  errors: Record<string, string>;
  complete: boolean;
}

export interface ConversationSummary {
  session_id: string;
  started_at: string;
  last_activity: string;
  turn_count: number;
  summary?: string;
}
