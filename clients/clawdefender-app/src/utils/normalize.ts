/** Normalize backend decision values to canonical form: "allowed", "blocked", "prompted". */
export function normalizeDecision(d: string): string {
  const lower = d.toLowerCase();
  if (lower === "allowed" || lower === "allow") return "allowed";
  if (lower === "blocked" || lower === "block" || lower === "denied" || lower === "deny")
    return "blocked";
  if (lower === "prompted" || lower === "prompt") return "prompted";
  return lower;
}

/** Normalize backend risk_level to one of: "low", "medium", "high", "critical". */
export function normalizeRiskLevel(r: string): string {
  const lower = r.toLowerCase();
  if (lower === "info") return "low";
  if (lower === "block" || lower === "review") return "medium";
  if (lower === "low" || lower === "medium" || lower === "high" || lower === "critical")
    return lower;
  return "low";
}
