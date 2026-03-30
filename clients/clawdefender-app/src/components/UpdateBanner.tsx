import { useState, useEffect, useCallback, useRef } from "react";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

const DISMISS_KEY = "clawdefender-update-dismissed-at";
const DISMISS_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

interface UpdateInfo {
  version: string;
  body: string | null;
}

/**
 * Non-intrusive update banner.
 *
 * - Checks for updates periodically (every hour)
 * - Shows a dismissable banner when an update is available
 * - "Later" dismisses for 24 hours
 * - Downloads in background, installs on restart
 * - Never force-restarts during an active session
 */
export function UpdateBanner() {
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [showNotes, setShowNotes] = useState(false);
  const checkerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isDismissedRecently = useCallback(() => {
    const dismissedAt = localStorage.getItem(DISMISS_KEY);
    if (!dismissedAt) return false;
    return Date.now() - parseInt(dismissedAt, 10) < DISMISS_DURATION_MS;
  }, []);

  const checkForUpdate = useCallback(async () => {
    if (isDismissedRecently()) return;
    try {
      const result = await check();
      if (result?.available) {
        setUpdate({
          version: result.version,
          body: result.body ?? null,
        });
      }
    } catch {
      // Silently fail -- update checks should never break the app
    }
  }, [isDismissedRecently]);

  useEffect(() => {
    // Initial check after a short delay (don't slow down startup)
    const timeout = setTimeout(checkForUpdate, 10_000);
    // Periodic checks
    checkerRef.current = setInterval(checkForUpdate, CHECK_INTERVAL_MS);
    return () => {
      clearTimeout(timeout);
      if (checkerRef.current) clearInterval(checkerRef.current);
    };
  }, [checkForUpdate]);

  const handleDismiss = () => {
    localStorage.setItem(DISMISS_KEY, String(Date.now()));
    setDismissed(true);
  };

  const handleDownloadAndInstall = async () => {
    setDownloading(true);
    try {
      const result = await check();
      if (result?.available) {
        await result.downloadAndInstall();
        setDownloaded(true);
        setDownloading(false);
      }
    } catch {
      setDownloading(false);
    }
  };

  const handleRestart = () => {
    relaunch();
  };

  if (!update || dismissed) return null;

  return (
    <div className="px-4 py-2.5 bg-[var(--color-accent-subtle)] border-b border-[var(--color-accent)] flex items-center justify-between gap-4">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-[var(--color-text-primary)]">
          {downloaded
            ? `ClawDefender ${update.version} is ready. Restart to complete the update.`
            : `ClawDefender ${update.version} is available.`}
        </p>
        {update.body && showNotes && (
          <p className="text-xs text-[var(--color-text-secondary)] mt-1 max-h-20 overflow-y-auto whitespace-pre-wrap">
            {update.body}
          </p>
        )}
        {update.body && !showNotes && (
          <button
            onClick={() => setShowNotes(true)}
            className="text-xs text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] mt-0.5"
          >
            What's new
          </button>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {downloaded ? (
          <button
            onClick={handleRestart}
            className="text-xs px-3 py-1.5 rounded-md bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors"
          >
            Restart Now
          </button>
        ) : (
          <button
            onClick={handleDownloadAndInstall}
            disabled={downloading}
            className="text-xs px-3 py-1.5 rounded-md bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors disabled:opacity-50"
          >
            {downloading ? "Downloading..." : "Update"}
          </button>
        )}
        {!downloaded && (
          <button
            onClick={handleDismiss}
            className="text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
            aria-label="Dismiss update notification for 24 hours"
          >
            Later
          </button>
        )}
      </div>
    </div>
  );
}
