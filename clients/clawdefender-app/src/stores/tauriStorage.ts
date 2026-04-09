import { invoke } from "@tauri-apps/api/core";
import type { StateStorage } from "zustand/middleware";

/**
 * Zustand persist storage adapter backed by Tauri IPC.
 * Data is persisted to ~/.local/share/clawdefender/ui_state.json
 * via atomic writes on the Rust side.
 */
export const tauriStorage: StateStorage = {
  getItem: async (name: string): Promise<string | null> => {
    try {
      return await invoke<string | null>("get_ui_state", { key: name });
    } catch {
      return null;
    }
  },
  setItem: async (name: string, value: string): Promise<void> => {
    try {
      await invoke("set_ui_state", { key: name, value });
    } catch {
      // Silently fail — UI state persistence is best-effort
    }
  },
  removeItem: async (name: string): Promise<void> => {
    try {
      await invoke("remove_ui_state", { key: name });
    } catch {
      // Silently fail
    }
  },
};
