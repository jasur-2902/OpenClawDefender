import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { McpClient, McpServer } from "../types";

export interface ServerInfo {
  name: string;
  clientName: string;
  wrapped: boolean;
  status: string;
  eventCount: number;
  trustLevel?: string;
  anomalyScore?: number;
}

const SERVER_TTL_MS = 30_000; // 30s TTL

interface ServerStore {
  servers: ServerInfo[];
  hasNewUnwrapped: boolean;
  _fetchedAt: number;
  setServers: (servers: ServerInfo[]) => void;
  setHasNewUnwrapped: (val: boolean) => void;
  fetchServers: (force?: boolean) => Promise<void>;
}

export const useServerStore = create<ServerStore>((set, get) => ({
  servers: [],
  hasNewUnwrapped: false,
  _fetchedAt: 0,

  setServers: (servers) => set({ servers }),
  setHasNewUnwrapped: (val) => set({ hasNewUnwrapped: val }),

  fetchServers: async (force) => {
    const now = Date.now();
    if (!force && now - get()._fetchedAt < SERVER_TTL_MS && get().servers.length > 0) return;
    try {
      const clients = await invoke<McpClient[]>("detect_mcp_clients");
      const allServers: ServerInfo[] = [];

      for (const client of clients) {
        try {
          const servers = await invoke<McpServer[]>("list_mcp_servers", {
            clientName: client.name,
          });
          for (const server of servers) {
            allServers.push({
              name: server.name,
              clientName: client.name,
              wrapped: server.wrapped,
              status: server.status,
              eventCount: server.events_count,
            });
          }
        } catch {
          // Skip clients that fail
        }
      }

      const hasNew = allServers.some((s) => !s.wrapped);
      set({ servers: allServers, hasNewUnwrapped: hasNew, _fetchedAt: Date.now() });
    } catch {
      // If detect fails, leave state unchanged
    }
  },
}));
