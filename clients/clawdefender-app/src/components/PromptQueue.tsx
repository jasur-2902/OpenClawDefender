import { useEventStore } from "../stores/eventStore";
import { PromptWindow } from "./PromptWindow";

export function PromptQueue() {
  const pendingPrompts = useEventStore((s) => s.pendingPrompts);

  if (pendingPrompts.length === 0) return null;

  const current = pendingPrompts[0];
  const queueCount = pendingPrompts.length - 1;

  return <PromptWindow key={current.id} prompt={current} queueCount={queueCount} />;
}
