import { useState, useCallback } from "react";
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

      // Check for files first
      if (e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        // In Tauri, we get the file path from the name
        // The actual path is available through Tauri's drag-and-drop API
        const path = (file as File & { path?: string }).path ?? file.name;
        if (path) {
          onFileDrop(path);
          return;
        }
      }

      // Check for text data (URLs or paths)
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
