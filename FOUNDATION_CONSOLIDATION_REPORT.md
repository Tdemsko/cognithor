# Thomas AI Foundation Consolidation Report

## Status

Date: 2026-07-27

Branch: `homelab-hardening`

Vendor baseline: `78212af5396fd42cb7103b9edfe9b2e57909aac5`

`main` remains the pristine upstream-derived branch. Nothing in this report
authorizes a merge to `main` or deployment to the home lab.

Five coherent hardening candidates have completed the mandatory three-round
release policy. Each exceeded 99.0/100 and had zero unresolved Critical or High
findings in its accepted scope.

## Accepted candidate ledger

| Candidate | Accepted branch commit | Scope | Score |
|---|---|---|---:|
| 1 | `f6804bbf` | Fail-closed home-lab policy, sandbox, safe mode, self-modification defaults, audit startup | 99.6 |
| 2 | `9800c19a` | Exact-payload, one-shot, expiring, session/risk-bound approvals | 99.625 |
| 3 | `a36cba52` | Secret storage/injection/redaction and required runtime-hook integrity | 99.625 |
| 4 | `f31bdb30` | Project-scoped memory, provenance, untrusted evidence, controlled reflection | 99.625 |
| 5 | This report's branch commit | Generic HTTP, redirect, browser, WebSocket, and v17 mutation boundary | 99.625 |

The detailed commands, rejected runs, repairs, counts, installed-artifact
probes, and residual risks are authoritative in `TEST_EVIDENCE.md`.

## Consolidated security foundation

The branch now establishes these deterministic invariants:

1. The planner/model proposes; deterministic code classifies, authorizes, and
   executes.
2. R0-R5 risk floors cannot be lowered by model estimates, tool metadata, or
   local policy.
3. Host shell, raw Docker/remote execution, sudo, destructive/security,
   credential, firmware, financial, and self-modification capabilities are
   never ordinary automatic actions.
4. Project writes are bounded to a resolved workspace; broader writes require
   explicit authorization.
5. Generated code defaults to a fail-closed namespace/container sandbox with
   no network and no process/bare fallback.
6. Required security initialization, runtime hooks, audit integrity, approval
   recording, secret lookup, and provenance checks fail closed.
7. Safe mode is an explicit read-only allowlist; break glass is local,
   short-lived, reasoned, and not model-facing.
8. Exact approvals bind action, canonical payload hash, target, risk, session,
   expiry, and single use. Material mutation invalidates approval.
9. Credential storage has no plaintext fallback. Scoped injection occurs
   below the model, and sensitive values are recursively redacted from model
   input and audit records.
10. Named projects have independent memory namespaces. Retrieved web, file,
    tool, and memory content is untrusted evidence with provenance and cannot
    silently become durable authority.
11. Automatic evolution, prompt mutation, community/generated skills, and
    self-repair are disabled in home-lab mode. Improvements remain proposals.
12. Generic public HTTP validates DNS and every redirect, rejects private and
    metadata destinations, bounds responses, prevents cross-origin secret/body
    replay, and redacts security logs.
13. Playwright contexts block service workers and intercept all HTTP and
    WebSocket destinations before the first page. Missing interception
    support disables browser startup.
14. Browser mutations are explicit R4 actions and remain denied in safe mode.
15. Accepted code and policy changes have reproducible three-round evidence,
    installed-wheel validation, and a tested prior-artifact rollback path.

## Upstream-maintainability assessment

The fork continues to use Cognithor's planner, Gatekeeper, executor, sandbox,
memory, workflow, browser, MCP, model, audit, and tool infrastructure. The
changes are concentrated in deterministic policy, security adapters,
provenance boundaries, and regression contracts rather than a replacement
control plane.

Relative to the frozen vendor baseline, the branch currently changes about
118 files. Most of the footprint is tests and evidence; the new network
boundary is centralized in `cognithor.security.network_guard`, and Thomas-
specific risk logic remains centralized in `cognithor.security.home_lab`.

This structure is suitable for future upstream reconciliation:

- keep `main` as the vendor mirror;
- merge upstream into a temporary reconciliation branch;
- rerun every accepted security contract before updating
  `homelab-hardening`;
- reject an upstream update that weakens an invariant, even when upstream
  tests pass.

## Target-topology mapping

| System | Permanent trust role |
|---|---|
| DGX Spark | Primary Qwen inference/model provider; no durable control state and no routine untrusted execution |
| `control01` on SER5 Proxmox | Cognithor controller, policy, approvals, projects, workflows, audit, model routing, and durable control state |
| SER5 worker VM | Primary disposable Linux execution zone, separated from `control01` |
| `worker01` on `pve1` | Existing bounded Linux QA/overflow worker; preserve the Ruff/mypy/pytest runner during migration |
| Windows laptop | Windows/WSL specialist worker and cross-platform validation |
| `apps01` | Open WebUI and infrastructure frontend; not source of truth |
| Synology | Durable backups, artifacts, approved data, and restore source |

Open WebUI remains replaceable. Direct-to-Spark chat remains a degraded
fallback when `control01` is unavailable.

## Requirement coverage after Candidate 5

| Requirement | State after Candidate 5 |
|---|---|
| Deterministic planner/gatekeeper/executor authority | Foundation accepted |
| Dangerous-tool reclassification and safe mode | Foundation accepted |
| Fail-closed sandbox/no bare fallback | Foundation accepted; live Ubuntu proof still gates deployment |
| Exact approvals and break glass | Foundation accepted |
| Secrets broker/storage/redaction | Core accepted; remaining connector-by-connector migration pending |
| Project memory/provenance/prompt-injection boundary | Foundation accepted |
| Generic web/browser private-network boundary | Application boundary accepted; VM firewall/live Chromium gate pending |
| Append-only authoritative audit | Core accepted; cross-system run reconstruction still pending |
| Worker leases/retry/idempotency | Existing Cognithor behavior regression-tested; Thomas worker protocol integration pending |
| Git-native coding lifecycle | Policy pieces exist; end-to-end branch/worktree/reviewer/approval flow pending |
| Qwen/Ollama model/tool conformance | Pending a live DGX Spark test fixture and endpoint access |
| OpenAI-compatible frontend plus REST/OpenAPI/MCP | Existing pieces require one verified, nonduplicated control-plane interface |
| Durable workflows/automation/notifications | Existing Cognithor modules require topology integration and recovery tests |
| Synology artifact/backup service | Pending named integration and restore drill |
| Windows/WSL worker | Pending worker registration and cross-platform release tests |
| Live production deployment | Not started; blocked on target isolation, backup, firewall, and restore gates |

## Prioritized next candidates

### Candidate 6 — Worker capability and job boundary

- preserve the existing `worker01` Python QA runner as a bounded adapter;
- audit Cognithor's native distributed-worker registration, capability
  advertisement, heartbeat, leases, cancellation, retry, and result handling;
- remove any model-facing arbitrary SSH, sudo, raw shell, or Docker socket;
- version job schemas and make side-effecting jobs idempotent;
- produce append-only job/artifact provenance;
- prove duplicate delivery cannot double-apply a side effect.

### Candidate 7 — Git-native coding and independent review

- isolated branch/worktree per task;
- deterministic lint/type/unit/integration stages;
- bounded repair loop;
- independent tester/reviewer role;
- exact-diff approval before merge or deployment;
- rollback and artifact retention.

### Candidate 8 — DGX Spark model/tool conformance

- Qwen3.5 122B Q6 through Ollama/OpenAI-compatible endpoint;
- schema-valid tool calls, malformed-call behavior, retry ceilings, timeout,
  partial stream, model outage, and fallback behavior;
- no real credentials or production mutation during conformance;
- preserve direct-to-Spark degraded chat.

### Candidate 9 — Control-plane interfaces and topology deployment

- one business-logic layer exposed through OpenAI-compatible chat, REST/
  OpenAPI, and MCP adapters;
- Open WebUI as client only;
- `control01`/worker trust-zone separation;
- Synology backup/artifact integration;
- restore, firewall, live browser, and reboot/reconnection tests.

### Candidate 10 — Durable automation and operations

- long-running resumable workflows;
- schedules/events and approval waits;
- notifications;
- observability and audit reconstruction;
- evaluation gates before model/tool/upstream upgrades;
- operator runbooks and recovery drills.

## Deployment blockers

No accepted candidate should be deployed unattended until all of these pass on
the target topology:

1. live Ubuntu namespace/container escape tests;
2. VM/container firewall denial of RFC1918, link-local, metadata, NAS,
   Proxmox, router, and control-plane management networks for generic egress;
3. live Chromium HTTP, redirect, service-worker, WebSocket, and DNS-rebinding
   probes;
4. `control01` backup plus destructive restore drill in a disposable VM;
5. worker lease/cancellation/idempotency tests across restart and packet loss;
6. DGX Spark Qwen model/tool conformance;
7. exact approval and audit reconstruction across frontend, controller,
   worker, and artifact store.

## Consolidation decision

Cognithor remains the correct foundation. The accepted branch has materially
reduced the highest-risk home-lab gaps without replacing upstream subsystems
or introducing Kubernetes, Kafka, a service mesh, or other unjustified
single-operator complexity.

The security foundation is ready for the next reviewable candidate. The
complete Thomas AI end-state is not yet finished, merged, or deployed.
