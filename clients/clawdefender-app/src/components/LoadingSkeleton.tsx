/**
 * Content skeleton displayed as Suspense fallback during lazy page loading.
 * Matches generic page layout: header bar + content placeholders.
 */
export function LoadingSkeleton() {
  return (
    <div className="flex flex-col gap-6 p-6 animate-[pulse_1.5s_ease-in-out_infinite] motion-reduce:animate-none">
      {/* Header skeleton */}
      <div className="flex items-center gap-4">
        <div className="h-7 w-48 rounded bg-[var(--color-bg-tertiary)]" />
        <div className="h-5 w-24 rounded bg-[var(--color-bg-tertiary)] opacity-60" />
      </div>

      {/* Content area skeletons */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-24 rounded-xl bg-[var(--color-bg-secondary)] border border-[var(--color-border)]"
          />
        ))}
      </div>

      {/* Main content block */}
      <div className="space-y-3">
        <div className="h-4 w-full rounded bg-[var(--color-bg-tertiary)]" />
        <div className="h-4 w-5/6 rounded bg-[var(--color-bg-tertiary)] opacity-80" />
        <div className="h-4 w-4/6 rounded bg-[var(--color-bg-tertiary)] opacity-60" />
      </div>

      <div className="h-48 rounded-xl bg-[var(--color-bg-secondary)] border border-[var(--color-border)]" />
    </div>
  );
}
