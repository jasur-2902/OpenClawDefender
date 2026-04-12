import { useState, useCallback, useEffect } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { ASK_CLAW } from "../../constants/messages";

interface DragDropZoneProps {
  onFileDrop: (path: string) => void;
  onUrlDrop: (url: string) => void;
  children: React.ReactNode;
}

function looksLikeUrl(text: string): boolean {
  const trimmed = text.trim();
  return /^https?:\/\//i.test(trimmed) || /^www\./i.test(trimmed);
}

function looksLikeFilePath(text: string): boolean {
  const trimmed = text.trim();
  return trimmed.startsWith("/") || trimmed.startsWith("~") || /^[A-Z]:\\/i.test(trimmed);
}

export function DragDropZone({ onFileDrop, onUrlDrop, children }: DragDropZoneProps) {
  const [dragOver, setDragOver] = useState(false);

  // -----------------------------------------------------------------------
  // Tauri native drag-drop event — provides actual file system paths
  // -----------------------------------------------------------------------
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    getCurrentWebviewWindow()
      .onDragDropEvent((event) => {
        if (event.payload.type === "over") {
          setDragOver(true);
        } else if (event.payload.type === "leave") {
          setDragOver(false);
        } else if (event.payload.type === "drop") {
          setDragOver(false);
          const paths = event.payload.paths;
          if (paths && paths.length > 0) {
            onFileDrop(paths[0]);
          }
        }
      })
      .then((fn) => {
        unlisten = fn;
      });

    return () => {
      unlisten?.();
    };
  }, [onFileDrop]);

  // -----------------------------------------------------------------------
  // HTML5 drag handlers — used only for visual overlay and text/URL drops
  // -----------------------------------------------------------------------
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOver(false);

      // Only handle text/URL drops via HTML5 — file drops are handled by Tauri
      const text = e.dataTransfer.getData("text/plain") || e.dataTransfer.getData("text/uri-list");
      if (text) {
        const trimmed = text.trim();
        if (looksLikeUrl(trimmed)) {
          onUrlDrop(trimmed);
        } else if (looksLikeFilePath(trimmed)) {
          onFileDrop(trimmed);
        }
      }
    },
    [onFileDrop, onUrlDrop],
  );

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className="relative flex-1 flex flex-col"
    >
      {children}

      {dragOver && (
        <div className="absolute inset-0 z-[var(--z-overlay)] flex items-center justify-center bg-[var(--color-bg-primary)]/80 backdrop-blur-sm rounded-lg border-2 border-dashed border-[var(--color-accent)]">
          <p className="text-sm font-medium text-[var(--color-accent)]">
            {ASK_CLAW.dragOverlay}
          </p>
        </div>
      )}
    </div>
  );
}
