import { useEffect, useRef } from "react";

/**
 * Traps keyboard focus within a container element when active.
 * Returns a ref to attach to the container element.
 *
 * When the trap activates, it auto-focuses the first focusable element
 * (or the element matching `initialFocusSelector` if provided).
 * When deactivated, focus returns to the element that was focused before the trap.
 */
export function useFocusTrap(
  active: boolean,
  options?: { initialFocusSelector?: string }
) {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!active || !containerRef.current) return;

    // Store the element that had focus before the trap
    previousFocusRef.current = document.activeElement as HTMLElement | null;

    const container = containerRef.current;

    function getFocusableElements(): HTMLElement[] {
      const elements = container.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'
      );
      return Array.from(elements).filter(
        (el) => el.offsetParent !== null // visible
      );
    }

    // Set initial focus
    if (options?.initialFocusSelector) {
      const target = container.querySelector<HTMLElement>(
        options.initialFocusSelector
      );
      if (target) {
        target.focus();
      } else {
        const focusable = getFocusableElements();
        focusable[0]?.focus();
      }
    } else {
      const focusable = getFocusableElements();
      focusable[0]?.focus();
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key !== "Tab") return;

      const focusable = getFocusableElements();
      if (focusable.length === 0) {
        e.preventDefault();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    container.addEventListener("keydown", handleKeyDown);

    return () => {
      container.removeEventListener("keydown", handleKeyDown);
      // Restore focus to the previously focused element
      previousFocusRef.current?.focus();
    };
  }, [active, options?.initialFocusSelector]);

  return containerRef;
}
