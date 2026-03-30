import { create } from "zustand";
import { Toast, type ToastData } from "./Toast";

const MAX_VISIBLE = 3;

let nextId = 0;

interface ToastInput {
  title: string;
  severity: ToastData["severity"];
  duration?: number;
  action?: ToastData["action"];
}

interface ToastStore {
  toasts: ToastData[];
  addToast: (input: ToastInput) => void;
  removeToast: (id: string) => void;
  clearAll: () => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],

  addToast: (input) =>
    set((state) => {
      const toast: ToastData = {
        id: `toast-${++nextId}`,
        title: input.title,
        severity: input.severity,
        duration: input.duration ?? 5000,
        action: input.action,
      };
      const toasts = [...state.toasts, toast];
      // Keep only the most recent MAX_VISIBLE * 2 to avoid unbounded growth
      if (toasts.length > MAX_VISIBLE * 2) {
        return { toasts: toasts.slice(-MAX_VISIBLE * 2) };
      }
      return { toasts };
    }),

  removeToast: (id) =>
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    })),

  clearAll: () => set({ toasts: [] }),
}));

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const removeToast = useToastStore((s) => s.removeToast);

  // Only show the most recent MAX_VISIBLE toasts
  const visible = toasts.slice(-MAX_VISIBLE);

  if (visible.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2" role="region" aria-label="Notifications" aria-live="polite">
      {visible.map((toast) => (
        <Toast key={toast.id} toast={toast} onDismiss={removeToast} />
      ))}
    </div>
  );
}
