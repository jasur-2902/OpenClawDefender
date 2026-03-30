import { useAppStore } from "../../stores/appStore";
import { InlineHint } from "./InlineHint";

interface GuidanceAnchorProps {
  /** Unique anchor ID that matches delivery_meta.anchor from the backend. */
  id: string;
}

/**
 * A named slot where an inline guidance hint can appear.
 * Checks if there is a pending hint for this anchor ID and renders InlineHint.
 * If no hint is pending, renders nothing.
 */
export function GuidanceAnchor({ id }: GuidanceAnchorProps) {
  const hint = useAppStore((s) => s.guidanceHints[id]);

  if (!hint) return null;

  return (
    <div data-guidance-anchor={id}>
      <InlineHint
        milestoneId={hint.milestoneId}
        message={hint.message}
        actionLabel={hint.actionLabel}
        actionRoute={hint.actionRoute}
      />
    </div>
  );
}
