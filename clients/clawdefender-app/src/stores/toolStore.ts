import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type {
  ToolCardData,
  NewToolInfo,
  TrustLevel,
  PermissionAction,
  TrustLevelInfo,
  PermissionChange,
  ServerSummary,
} from "../types";

interface ToolStore {
  tools: ToolCardData[];
  newTools: NewToolInfo[];
  loading: boolean;
  error: string | null;

  fetchTools: () => Promise<void>;
  fetchNewTools: () => Promise<void>;
  setTrustLevel: (serverName: string, level: TrustLevel) => Promise<void>;
  setPermission: (serverName: string, permission: string, action: PermissionAction) => Promise<void>;
  resetPermission: (serverName: string, permission: string) => Promise<void>;
  protectTool: (serverName: string, clientName: string) => Promise<void>;
  dismissNewTool: (serverName: string) => Promise<void>;
  getTrustLevel: (serverName: string) => Promise<TrustLevelInfo | null>;
  previewTrustChange: (serverName: string, newLevel: TrustLevel) => Promise<PermissionChange[]>;
  getServerSummary: (serverName: string) => Promise<ServerSummary | null>;
}

export const useToolStore = create<ToolStore>((set, get) => ({
  tools: [],
  newTools: [],
  loading: true,
  error: null,

  fetchTools: async () => {
    try {
      const tools = await invoke<ToolCardData[]>("get_tool_cards");
      set({ tools, loading: false, error: null });
    } catch (e) {
      set({ loading: false, error: String(e) });
    }
  },

  fetchNewTools: async () => {
    try {
      const newTools = await invoke<NewToolInfo[]>("get_new_tools");
      set({ newTools });
    } catch {
      // Command may not exist yet
    }
  },

  setTrustLevel: async (serverName, level) => {
    try {
      await invoke("set_trust_level", { serverName, trustLevel: level });
      await get().fetchTools();
    } catch (e) {
      set({ error: String(e) });
    }
  },

  setPermission: async (serverName, permission, action) => {
    try {
      await invoke("set_permission_override", { serverName, permission, action });
      await get().fetchTools();
    } catch (e) {
      set({ error: String(e) });
    }
  },

  resetPermission: async (serverName, permission) => {
    try {
      await invoke("reset_permission_override", { serverName, permission });
      await get().fetchTools();
    } catch (e) {
      set({ error: String(e) });
    }
  },

  protectTool: async (serverName, clientName) => {
    try {
      await invoke("wrap_server", { serverName, clientName });
      await get().fetchTools();
      set((s) => ({
        newTools: s.newTools.filter((t) => t.server_name !== serverName),
      }));
    } catch (e) {
      set({ error: String(e) });
    }
  },

  dismissNewTool: async (serverName) => {
    try {
      await invoke("dismiss_new_tool", { serverName });
      set((s) => ({
        newTools: s.newTools.filter((t) => t.server_name !== serverName),
      }));
    } catch {
      // Remove locally even if backend fails
      set((s) => ({
        newTools: s.newTools.filter((t) => t.server_name !== serverName),
      }));
    }
  },

  getTrustLevel: async (serverName) => {
    try {
      return await invoke<TrustLevelInfo>("get_trust_level", { serverName });
    } catch {
      return null;
    }
  },

  previewTrustChange: async (serverName, newLevel) => {
    try {
      return await invoke<PermissionChange[]>("preview_trust_change", {
        serverName,
        newLevel,
      });
    } catch {
      return [];
    }
  },

  getServerSummary: async (serverName) => {
    try {
      return await invoke<ServerSummary>("get_server_summary", { serverName });
    } catch {
      return null;
    }
  },
}));
