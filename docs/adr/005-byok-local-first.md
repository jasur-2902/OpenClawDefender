# ADR-005: BYOK and Local-First

**Status:** Accepted

## Context

Many security and AI tools operate as cloud services: they proxy traffic through their servers, require accounts, and charge subscription fees. We needed to decide whether ClawDefender should follow this model or operate entirely locally.

## Decision

ClawDefender is **local-first** and **BYOK (Bring Your Own Key)**.

- ClawDefender runs entirely on the user's machine. No data leaves the machine through ClawDefender.
- ClawDefender does not require an account, API key, or internet connection.
- If AI features are added in the future (e.g., intelligent policy suggestions), users supply their own API key and data goes directly to their chosen provider. ClawDefender never acts as an intermediary for AI API calls.

### Rationale

**Eliminates privacy concerns.** ClawDefender sits in the middle of every MCP tool call. These calls may contain source code, credentials, personal data, and proprietary information. Sending this data to a third-party service — even for "analysis" — is a non-starter for security-conscious users.

**No cloud costs.** ClawDefender can be maintained without infrastructure costs. No servers to run, no databases to manage, no SLAs to maintain. This makes the project sustainable as an open-source effort.

**No single point of failure.** A cloud service going down would disable security for all users. A local tool works even if the maintainers disappear.

**BYOK preserves user choice.** If we add AI-powered features, users choose their provider (OpenAI, Anthropic, local models) and pay them directly. ClawDefender doesn't lock users into a provider or take a margin on API calls.

**Trust model is simpler.** Users only need to trust the open-source code they can audit, not a service they can't inspect.

### Trade-off: no aggregate intelligence

A cloud service could aggregate anonymized data across users to detect novel attack patterns, build shared threat intelligence, and improve detection over time. By going local-first, we forgo this entirely. Each installation is an island.

We accept this trade-off. The privacy and trust benefits outweigh the detection benefits, especially at this stage. Aggregate intelligence can be added later as an opt-in feature if there's demand.

## Consequences

- No telemetry, no analytics, no usage data collection. Ever.
- Updates are distributed as binary releases, not pushed from a server.
- Documentation and community are the primary support channels — no dashboard, no admin console.
- Future AI features must work with user-supplied credentials, which means supporting multiple providers and handling key management carefully.
