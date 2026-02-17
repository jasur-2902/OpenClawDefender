import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { Timeline } from "./pages/Timeline";
import { Onboarding } from "./pages/Onboarding";
import { NotificationLayer } from "./components/NotificationLayer";
import { PolicyEditor } from "./pages/PolicyEditor";
import { Settings } from "./pages/Settings";
import { Behavioral } from "./pages/Behavioral";
import { Scanner } from "./pages/Scanner";
import { Guards } from "./pages/Guards";
import { AuditLog } from "./pages/AuditLog";
import { SystemHealth } from "./pages/SystemHealth";
import { ThreatIntel } from "./pages/ThreatIntel";

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
  return (
    <BrowserRouter>
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
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/timeline" element={<Timeline />} />
                    <Route path="/policy" element={<PolicyEditor />} />
                    <Route path="/behavioral" element={<Behavioral />} />
                    <Route path="/scanner" element={<Scanner />} />
                    <Route path="/guards" element={<Guards />} />
                    <Route path="/audit" element={<AuditLog />} />
                    <Route path="/threat-intel" element={<ThreatIntel />} />
                    <Route path="/health" element={<SystemHealth />} />
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
