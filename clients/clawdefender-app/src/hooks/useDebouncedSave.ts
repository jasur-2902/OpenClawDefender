import { useRef, useCallback, useState, useEffect } from "react";

/**
 * Debounced save hook.
 *
 * Batches rapid changes so that only one save fires after
 * `delayMs` of inactivity. Returns a `saving` state for UI feedback.
 *
 * Usage:
 *   const { trigger, saving } = useDebouncedSave(saveFn, 500);
 *   // Call trigger(data) on every change; saveFn runs once after 500ms idle.
 */
export function useDebouncedSave<T>(
  saveFn: (data: T) => Promise<void>,
  delayMs = 500,
): { trigger: (data: T) => void; saving: boolean } {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latestRef = useRef<T | null>(null);
  const [saving, setSaving] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const trigger = useCallback(
    (data: T) => {
      latestRef.current = data;
      setSaving(true);

      if (timerRef.current) clearTimeout(timerRef.current);

      timerRef.current = setTimeout(async () => {
        if (latestRef.current === null) return;
        try {
          await saveFn(latestRef.current);
        } catch {
          // Caller should handle errors in saveFn if needed
        }
        if (mountedRef.current) {
          setSaving(false);
        }
      }, delayMs);
    },
    [saveFn, delayMs],
  );

  return { trigger, saving };
}
