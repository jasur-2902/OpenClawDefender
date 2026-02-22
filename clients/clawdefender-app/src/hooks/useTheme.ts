import { useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type ThemeSetting = "system" | "light" | "dark";

function resolveTheme(setting: ThemeSetting): "light" | "dark" {
  if (setting === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }
  return setting;
}

function applyTheme(effective: "light" | "dark") {
  document.documentElement.setAttribute("data-theme", effective);
  localStorage.setItem("clawdefender-theme-effective", effective);
}

export function useTheme() {
  const settingRef = useRef<ThemeSetting>("system");

  useEffect(() => {
    // Load saved theme from backend
    invoke<{ theme: ThemeSetting }>("get_settings")
      .then((s) => {
        settingRef.current = s.theme;
        applyTheme(resolveTheme(s.theme));
        localStorage.setItem("clawdefender-theme-setting", s.theme);
      })
      .catch(() => {
        // Use cached setting from localStorage
        const cached = localStorage.getItem("clawdefender-theme-setting") as ThemeSetting | null;
        if (cached) {
          settingRef.current = cached;
          applyTheme(resolveTheme(cached));
        }
      });
  }, []);

  // Listen for settings changes from the Settings page
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    listen<ThemeSetting>("clawdefender://theme-changed", (event) => {
      settingRef.current = event.payload;
      applyTheme(resolveTheme(event.payload));
      localStorage.setItem("clawdefender-theme-setting", event.payload);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
    };
  }, []);

  // Listen for OS theme changes (relevant when setting is "system")
  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

    function handleChange() {
      if (settingRef.current === "system") {
        applyTheme(resolveTheme("system"));
      }
    }

    mediaQuery.addEventListener("change", handleChange);
    return () => {
      mediaQuery.removeEventListener("change", handleChange);
    };
  }, []);
}
