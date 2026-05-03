import { useEffect, useCallback, useState } from "react";
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Layout } from "./components/Layout";
import { Home } from "./pages/Home";
import { Activity } from "./pages/Activity";
import { EventDetail } from "./pages/EventDetail";
import { Alerts } from "./pages/Alerts";
import { AlertDetail } from "./pages/AlertDetail";
import { Onboarding } from "./pages/Onboarding";
import { NotificationLayer } from "./components/NotificationLayer";
import { Settings } from "./pages/Settings";
import { useTheme } from "./hooks/useTheme";
import { useAlertStore } from "./stores/alertStore";
import { useEventStore } from "./stores/eventStore";
import { useTauriEvent } from "./hooks/useTauriEvent";
import type { AuditEvent } from "./types";
import { AskClaw } from "./pages/AskClaw";
import { MyTools } from "./pages/MyTools";
import { ToolDetail } from "./pages/ToolDetail";
import { ToolActivity } from "./pages/ToolActivity";
import { Scanner } from "./pages/Scanner";
import { AuditLog } from "./pages/AuditLog";
import { SetupPermissions } from "./pages/SetupPermissions";

function TrayNavigationListener() {
  const navigate = useNavigate();

  useEffect(() => {
    let unlisten: (() => void) | undefined;

    listen<string>("rookbot://navigate", (event) => {
      navigate(event.payload);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
    };
  }, [navigate]);

  return null;
}

/** Listen for intelligent-alert events and refresh the alert store. */
function IntelligentAlertListener() {
  const fetchAlerts = useAlertStore((s) => s.fetchAlerts);
  const fetchStats = useAlertStore((s) => s.fetchStats);

  const handleIntelligentAlert = () => {
    fetchAlerts();
    fetchStats();
  };

  useTauriEvent("rookbot://intelligent-alert", handleIntelligentAlert);

  return null;
}

/** Listen for live events globally and feed them into the event store. */
function GlobalEventListener() {
  const addRawEvent = useEventStore((s) => s.addRawEvent);

  const handleEvent = useCallback((payload: AuditEvent) => {
    addRawEvent(payload);
  }, [addRawEvent]);

  useTauriEvent<AuditEvent>("rookbot://event", handleEvent);

  return null;
}

function OnboardingRedirect({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    async function checkOnboarding() {
      try {
        const complete = await invoke<boolean>("check_onboarding_complete");
        if (!complete && location.pathname !== "/onboarding") {
          navigate("/onboarding", { replace: true });
        }
      } catch {
        // If the command fails (e.g. daemon not running), proceed normally
      }
      setChecked(true);
    }
    checkOnboarding();
  }, [navigate, location.pathname]);

  if (!checked) {
    return null;
  }

  return <>{children}</>;
}

function App() {
  useTheme();

  return (
    <BrowserRouter>
      <TrayNavigationListener />
      <IntelligentAlertListener />
      <GlobalEventListener />
      <OnboardingRedirect>
        <Routes>
          <Route path="/onboarding" element={<Onboarding />} />
          <Route element={<Layout />}>
            <Route path="/" element={<Home />} />
            <Route path="/activity" element={<Activity />} />
            <Route path="/activity/:id" element={<EventDetail />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/ask" element={<AskClaw />} />
            <Route path="/tools" element={<MyTools />} />
            <Route path="/tools/:name" element={<ToolDetail />} />
            <Route path="/tools/:name/activity" element={<ToolActivity />} />
            <Route path="/scan" element={<Scanner />} />
            <Route path="/transparency" element={<AuditLog />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/setup-permissions" element={<SetupPermissions />} />
          </Route>
        </Routes>
      </OnboardingRedirect>
      <NotificationLayer />
    </BrowserRouter>
  );
}

export default App;
