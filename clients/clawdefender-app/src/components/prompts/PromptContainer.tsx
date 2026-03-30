import { useEventStore } from "../../stores/eventStore";
import { StandardPrompt } from "./StandardPrompt";
import { CriticalPrompt } from "./CriticalPrompt";

export function PromptContainer() {
  const pendingPrompts = useEventStore((s) => s.pendingPrompts);

  if (pendingPrompts.length === 0) return null;

  const current = pendingPrompts[0];
  const queueCount = pendingPrompts.length - 1;
  const isHighRisk = current.risk_level === "high" || current.risk_level === "critical";

  if (isHighRisk) {
    return (
      <div aria-live="assertive">
        <CriticalPrompt key={current.id} prompt={current} queueCount={queueCount} />
      </div>
    );
  }

  return (
    <div aria-live="polite">
      <StandardPrompt key={current.id} prompt={current} queueCount={queueCount} />
    </div>
  );
}
