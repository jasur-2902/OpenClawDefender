import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Sidebar } from "./components/Sidebar";
import { Home } from "./pages/Home";
import { Activity } from "./pages/Activity";
import { EventDetail } from "./pages/EventDetail";
import { Alerts } from "./pages/Alerts";
import { AlertDetail } from "./pages/AlertDetail";
import { Onboarding } from "./pages/Onboarding";
import { NotificationLayer } from "./components/NotificationLayer";
import { PolicyEditor } from "./pages/PolicyEditor";
import { Settings } from "./pages/Settings";
import { SystemHealth } from "./pages/SystemHealth";
import { ThreatIntel } from "./pages/ThreatIntel";
import { useTheme } from "./hooks/useTheme";
import { useAlertStore } from "./stores/alertStore";
import { useTauriEvent } from "./hooks/useTauriEvent";
import { AskClaw } from "./pages/AskClaw";
import { MyTools } from "./pages/MyTools";
import { ToolDetail } from "./pages/ToolDetail";
import { Scanner } from "./pages/Scanner";

function TrayNavigationListener() {
  const navigate = useNavigate();

  useEffect(() => {
    let unlisten: (() => void) | undefined;

    listen<string>("clawdefender://navigate", (event) => {
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

  useTauriEvent("clawdefender://intelligent-alert", handleIntelligentAlert);

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
      <OnboardingRedirect>
        <Routes>
          <Route
            path="/onboarding"
            element={<Onboarding />}
          />
          <Route
            path="*"
            element={
              <div className="flex h-screen bg-[var(--color-bg-primary)]">
                <Sidebar />
                <main className="flex-1 overflow-y-auto">
                  <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/activity" element={<Activity />} />
                    <Route path="/activity/:id" element={<EventDetail />} />
                    <Route path="/alerts" element={<Alerts />} />
                    <Route path="/alerts/:id" element={<AlertDetail />} />
                    <Route path="/ask" element={<AskClaw />} />
                    <Route path="/tools" element={<MyTools />} />
                    <Route path="/tools/:name" element={<ToolDetail />} />
                    <Route path="/policy" element={<PolicyEditor />} />
                    <Route path="/threat-intel" element={<ThreatIntel />} />
                    <Route path="/health" element={<SystemHealth />} />
                    <Route path="/scanner" element={<Scanner />} />
                    <Route path="/settings" element={<Settings />} />
                  </Routes>
                </main>
              </div>
            }
          />
        </Routes>
      </OnboardingRedirect>
      <NotificationLayer />
    </BrowserRouter>
  );
}

export default App;
