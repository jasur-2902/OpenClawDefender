import { ASK_CLAW } from "../../constants/messages";

interface ConfirmationCardProps {
  description: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmationCard({ description, onConfirm, onCancel }: ConfirmationCardProps) {
  return (
    <div className="rounded-lg border border-[var(--color-warning-border)] bg-[var(--color-warning-light)] p-3 space-y-2">
      <p className="text-sm text-[var(--color-text-primary)]">{description}</p>
      <div className="flex gap-2">
        <button
          onClick={onConfirm}
          className="rounded-md px-3 py-1.5 text-xs font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors duration-150"
        >
          {ASK_CLAW.confirmDo}
        </button>
        <button
          onClick={onCancel}
          className="rounded-md px-3 py-1.5 text-xs font-medium border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors duration-150"
        >
          {ASK_CLAW.confirmCancel}
        </button>
      </div>
    </div>
  );
}
