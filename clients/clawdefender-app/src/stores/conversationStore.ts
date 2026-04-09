import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';

export interface ConversationMessage {
  id: string;
  role: 'user' | 'claw';
  contentText: string;
  contentRichJson?: string;
  actionsJson?: string;
  intentId?: string;
  entitiesJson?: string;
  timestamp: string;
}

export interface ConversationSummary {
  id: string;
  createdAt: string;
  updatedAt: string;
  summary?: string;
  messageCount: number;
  lastMessagePreview?: string;
}

interface ConversationState {
  // Current conversation
  conversationId: string | null;
  messages: ConversationMessage[];
  isLoading: boolean;
  error: string | null;

  // Conversation list
  conversations: ConversationSummary[];

  // Context
  currentPage: string | null;
  lastServer: string | null;
  lastEvent: string | null;
  lastEntities: Record<string, string>;

  // Actions
  loadLatestConversation: () => Promise<void>;
  startNewConversation: () => Promise<void>;
  addUserMessage: (text: string) => Promise<void>;
  addClawResponse: (response: ConversationMessage) => Promise<void>;
  loadConversation: (id: string) => Promise<void>;
  listConversations: () => Promise<void>;
  deleteConversation: (id: string) => Promise<void>;
  searchConversations: (query: string) => Promise<void>;

  // Proactive alerts
  injectAlert: (text: string, richJson?: string, actionsJson?: string) => Promise<void>;

  // Context management
  setCurrentPage: (page: string) => void;
  setLastServer: (server: string) => void;
  setLastEvent: (event: string) => void;
  updateEntities: (entities: Record<string, string>) => void;
  getContextJson: () => string;
}

/** Convert a backend StoredMessage JSON object to our frontend shape. */
function parseMessage(raw: Record<string, unknown>): ConversationMessage {
  return {
    id: raw.id as string,
    role: raw.role as 'user' | 'claw',
    contentText: (raw.content_text as string) ?? "",
    contentRichJson: (raw.content_rich_json as string) || undefined,
    actionsJson: (raw.actions_json as string) || undefined,
    intentId: (raw.intent_id as string) || undefined,
    entitiesJson: (raw.entities_json as string) || undefined,
    timestamp: raw.timestamp as string,
  };
}

/** Convert a backend ConversationSummary JSON to our frontend shape. */
function parseSummary(raw: Record<string, unknown>): ConversationSummary {
  return {
    id: raw.id as string,
    createdAt: raw.created_at as string,
    updatedAt: raw.updated_at as string,
    summary: (raw.summary as string) || undefined,
    messageCount: raw.message_count as number,
    lastMessagePreview: (raw.last_message_preview as string) || undefined,
  };
}

export const useConversationStore = create<ConversationState>((set, get) => ({
  conversationId: null,
  messages: [],
  isLoading: false,
  error: null,
  conversations: [],
  currentPage: null,
  lastServer: null,
  lastEvent: null,
  lastEntities: {},

  loadLatestConversation: async () => {
    set({ isLoading: true, error: null });
    try {
      const resultJson = await invoke<string>('get_latest_conversation_id');
      const id = JSON.parse(resultJson) as string | null;
      if (id) {
        await get().loadConversation(id);
      } else {
        set({ conversationId: null, messages: [], isLoading: false });
      }
    } catch (e) {
      set({ error: String(e), isLoading: false });
    }
  },

  startNewConversation: async () => {
    set({ isLoading: true, error: null });
    try {
      const resultJson = await invoke<string>('create_new_conversation');
      const id = JSON.parse(resultJson) as string;
      set({ conversationId: id, messages: [], isLoading: false });
    } catch (e) {
      set({ error: String(e), isLoading: false });
    }
  },

  addUserMessage: async (text: string) => {
    const state = get();
    let convId = state.conversationId;

    // Auto-create a conversation if none exists
    if (!convId) {
      try {
        const resultJson = await invoke<string>('create_new_conversation');
        convId = JSON.parse(resultJson) as string;
        set({ conversationId: convId });
      } catch (e) {
        set({ error: String(e) });
        return;
      }
    }

    const msg: ConversationMessage = {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      role: 'user',
      contentText: text,
      timestamp: new Date().toISOString(),
    };

    // Optimistically add to local state
    set((s) => ({ messages: [...s.messages, msg] }));

    // Persist to backend
    try {
      const payload = {
        id: msg.id,
        conversation_id: convId,
        role: msg.role,
        content_text: msg.contentText,
        content_rich_json: null,
        actions_json: null,
        intent_id: null,
        entities_json: null,
        timestamp: msg.timestamp,
      };
      await invoke('save_conversation_message', {
        messageJson: JSON.stringify(payload),
      });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  addClawResponse: async (response: ConversationMessage) => {
    const state = get();
    const convId = state.conversationId;
    if (!convId) return;

    set((s) => ({ messages: [...s.messages, response] }));

    try {
      const payload = {
        id: response.id,
        conversation_id: convId,
        role: response.role,
        content_text: response.contentText,
        content_rich_json: response.contentRichJson || null,
        actions_json: response.actionsJson || null,
        intent_id: response.intentId || null,
        entities_json: response.entitiesJson || null,
        timestamp: response.timestamp,
      };
      await invoke('save_conversation_message', {
        messageJson: JSON.stringify(payload),
      });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  loadConversation: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const resultJson = await invoke<string>('load_conversation', {
        conversationId: id,
      });
      const raw = JSON.parse(resultJson) as Record<string, unknown>[];
      const messages = raw.map(parseMessage);
      set({ conversationId: id, messages, isLoading: false });
    } catch (e) {
      set({ error: String(e), isLoading: false });
    }
  },

  listConversations: async () => {
    try {
      const resultJson = await invoke<string>('list_conversations', {
        limit: 50,
      });
      const raw = JSON.parse(resultJson) as Record<string, unknown>[];
      const conversations = raw.map(parseSummary);
      set({ conversations });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  deleteConversation: async (id: string) => {
    try {
      await invoke('delete_conversation', { conversationId: id });
      set((s) => {
        const conversations = s.conversations.filter((c) => c.id !== id);
        const cleared =
          s.conversationId === id
            ? { conversationId: null, messages: [] }
            : {};
        return { conversations, ...cleared };
      });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  searchConversations: async (query: string) => {
    try {
      const resultJson = await invoke<string>('search_conversations', {
        query,
      });
      const raw = JSON.parse(resultJson) as Record<string, unknown>[];
      const conversations = raw.map(parseSummary);
      set({ conversations });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  injectAlert: async (text: string, richJson?: string, actionsJson?: string) => {
    const state = get();
    let convId = state.conversationId;

    // Auto-create a conversation if none exists
    if (!convId) {
      try {
        const resultJson = await invoke<string>('create_new_conversation');
        convId = JSON.parse(resultJson) as string;
        set({ conversationId: convId });
      } catch (e) {
        set({ error: String(e) });
        return;
      }
    }

    const msg: ConversationMessage = {
      id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      role: 'claw',
      contentText: text,
      contentRichJson: richJson,
      actionsJson: actionsJson,
      intentId: 'proactive.alert',
      timestamp: new Date().toISOString(),
    };

    set((s) => ({ messages: [...s.messages, msg] }));

    try {
      const payload = {
        id: msg.id,
        conversation_id: convId,
        role: msg.role,
        content_text: msg.contentText,
        content_rich_json: msg.contentRichJson || null,
        actions_json: msg.actionsJson || null,
        intent_id: msg.intentId || null,
        entities_json: null,
        timestamp: msg.timestamp,
      };
      await invoke('save_conversation_message', {
        messageJson: JSON.stringify(payload),
      });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  setCurrentPage: (page: string) => set({ currentPage: page }),
  setLastServer: (server: string) => set({ lastServer: server }),
  setLastEvent: (event: string) => set({ lastEvent: event }),
  updateEntities: (entities: Record<string, string>) =>
    set((s) => ({ lastEntities: { ...s.lastEntities, ...entities } })),

  getContextJson: () => {
    const s = get();
    return JSON.stringify({
      conversationId: s.conversationId,
      currentPage: s.currentPage,
      lastServer: s.lastServer,
      lastEvent: s.lastEvent,
      lastEntities: s.lastEntities,
      messageCount: s.messages.length,
    });
  },
}));
