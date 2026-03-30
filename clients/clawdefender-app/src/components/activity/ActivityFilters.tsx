interface ActivityFiltersProps {
  searchText: string;
  onSearchChange: (value: string) => void;
  serverFilter: string[];
  onServerFilterChange: (servers: string[]) => void;
  serverNames: string[];
  statusFilter: string;
  onStatusFilterChange: (status: string) => void;
  riskFilter: string;
  onRiskFilterChange: (risk: string) => void;
  timeRange: string;
  onTimeRangeChange: (range: string) => void;
  onlyNotable: boolean;
  onOnlyNotableChange: (value: boolean) => void;
  hiddenCount: number;
  correlationFilter?: string;
  onCorrelationFilterChange?: (value: string) => void;
}

export function ActivityFilters({
  searchText,
  onSearchChange,
  serverFilter,
  onServerFilterChange,
  serverNames,
  statusFilter,
  onStatusFilterChange,
  riskFilter,
  onRiskFilterChange,
  timeRange,
  onTimeRangeChange,
  onlyNotable,
  onOnlyNotableChange,
  hiddenCount,
  correlationFilter,
  onCorrelationFilterChange,
}: ActivityFiltersProps) {
  const toggleServer = (name: string) => {
    if (serverFilter.includes(name)) {
      onServerFilterChange(serverFilter.filter((s) => s !== name));
    } else {
      onServerFilterChange([...serverFilter, name]);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
      {/* "Only show things that matter" toggle */}
      <label className="flex items-center gap-1.5 text-xs cursor-pointer select-none">
        <input
          type="checkbox"
          checked={onlyNotable}
          onChange={(e) => onOnlyNotableChange(e.target.checked)}
          className="rounded"
        />
        <span
          className={
            onlyNotable
              ? "text-[var(--color-accent)] font-medium"
              : "text-[var(--color-text-secondary)]"
          }
        >
          Only show things that matter
        </span>
        {onlyNotable && hiddenCount > 0 && (
          <span className="text-[var(--color-text-muted)] ml-1">
            (hiding {hiddenCount} routine events)
          </span>
        )}
      </label>

      {/* Separator */}
      <div className="w-px h-5 bg-[var(--color-border)] mx-1" />

      {/* Search */}
      <input
        type="text"
        placeholder="Search events..."
        aria-label="Search events"
        value={searchText}
        onChange={(e) => onSearchChange(e.target.value)}
        className="flex-1 min-w-[180px] max-w-xs bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
      />

      {/* Server multi-select dropdown */}
      <div className="relative group">
        <button
          className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] hover:border-[var(--color-text-secondary)] transition-colors"
          aria-label="Filter by server"
        >
          {serverFilter.length === 0
            ? "All Servers"
            : `${serverFilter.length} server${serverFilter.length > 1 ? "s" : ""}`}
        </button>
        <div className="absolute top-full left-0 mt-1 min-w-[180px] bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg shadow-[var(--shadow-dropdown)] z-[var(--z-dropdown)] hidden group-focus-within:block group-hover:block">
          <div className="py-1 max-h-48 overflow-y-auto">
            {serverFilter.length > 0 && (
              <button
                onClick={() => onServerFilterChange([])}
                className="w-full text-left px-3 py-1.5 text-xs text-[var(--color-accent)] hover:bg-[var(--color-bg-tertiary)]"
              >
                Clear all
              </button>
            )}
            {serverNames.map((name) => (
              <label
                key={name}
                className="flex items-center gap-2 px-3 py-1.5 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={serverFilter.includes(name)}
                  onChange={() => toggleServer(name)}
                  className="rounded"
                />
                {name}
              </label>
            ))}
            {serverNames.length === 0 && (
              <p className="px-3 py-1.5 text-xs text-[var(--color-text-muted)]">
                No servers
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Action filter */}
      <select
        value={statusFilter}
        onChange={(e) => onStatusFilterChange(e.target.value)}
        aria-label="Filter by action"
        className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
      >
        <option value="">All Actions</option>
        <option value="Allowed">Allowed</option>
        <option value="Blocked">Blocked</option>
        <option value="Prompted">Prompted</option>
        <option value="AutoBlocked">Auto-blocked</option>
      </select>

      {/* Risk filter */}
      <select
        value={riskFilter}
        onChange={(e) => onRiskFilterChange(e.target.value)}
        aria-label="Filter by risk level"
        className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
      >
        <option value="">All Risk</option>
        <option value="dangerous">Dangerous</option>
        <option value="suspicious">Suspicious</option>
        <option value="unusual">Unusual</option>
        <option value="normal">Normal</option>
      </select>

      {/* Correlation filter */}
      {onCorrelationFilterChange && (
        <select
          value={correlationFilter ?? ""}
          onChange={(e) => onCorrelationFilterChange(e.target.value)}
          aria-label="Filter by correlation"
          className="bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
        >
          <option value="">All Correlation</option>
          <option value="correlated">Correlated only</option>
          <option value="uncorrelated">Uncorrelated only</option>
        </select>
      )}

      {/* Time range quick buttons */}
      <div className="flex items-center gap-1" role="group" aria-label="Time range">
        {[
          { value: "", label: "All" },
          { value: "1h", label: "Last hour" },
          { value: "today", label: "Today" },
          { value: "yesterday", label: "Yesterday" },
          { value: "week", label: "This week" },
        ].map((opt) => (
          <button
            key={opt.value}
            onClick={() => onTimeRangeChange(opt.value)}
            aria-pressed={timeRange === opt.value}
            className={`text-xs px-2.5 py-1 rounded-full border transition-colors focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[var(--color-accent)] ${
              timeRange === opt.value
                ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-text-secondary)]"
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}
