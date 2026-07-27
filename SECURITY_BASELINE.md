# Thomas AI Home-Lab Security Baseline

## Frozen upstream baseline

- Repository: `Tdemsko/cognithor`
- Upstream-derived branch: `main`
- Development branch: `homelab-hardening`
- Frozen commit: `78212af5396fd42cb7103b9edfe9b2e57909aac5`
- Frozen on: 2026-07-26
- Baseline branch comparison: `main` and `homelab-hardening` were identical
  (`ahead_by=0`, `behind_by=0`) before this release candidate began.

`main` is vendor/upstream baseline material. Thomas-specific changes must
remain on `homelab-hardening` or a feature branch based on it.

## Operator and topology assumptions

This profile is for one operator in a home network:

- DGX Spark provides primary model inference.
- `control01` is the durable controller and must not execute generated code.
- `worker01`, the future SER5 worker VM, and the Windows/WSL worker execute
  bounded disposable jobs.
- Open WebUI is a replaceable frontend, not the policy or state authority.
- Synology holds durable backups and approved artifacts.

## Non-negotiable invariants

1. Planner/model output is a proposal. Deterministic code authorizes actions.
2. Host shell, unrestricted Python, sudo, raw Docker, remote execution, and
   broad host writes never auto-execute.
3. Tool metadata cannot lower a home-lab risk floor.
4. Project writes may run automatically only inside the resolved project
   workspace. Broader writes require approval.
5. Unreviewed self-modification and community-skill installation are blocked.
6. Generated code never silently falls back to unsandboxed execution.
7. A required security-control failure blocks startup or the affected action.
8. Generated-code network access is disabled until a private-network-denying
   egress control is implemented and verified.
9. Global safe mode permits only an explicit read-only tool allowlist.
10. Break glass is a local administrator mechanism, never a model-facing tool.
11. Security-relevant defaults are closed: evolution, prompt mutation,
    community marketplaces, and automatic skill repair are disabled.
12. No release is accepted without all three evidence rounds, a weighted score
    above 99.0, zero unresolved Critical/High findings, and proven rollback.
13. Audit-chain integrity is verified at startup; an invalid chain or required
    audit initialization failure prevents the controller from starting.
14. A disabled improvement gate blocks proposals. Turning governance off must
    never convert into an allow-all self-modification path.
15. Dependencies with a known unresolved vulnerability are not accepted merely
    because they are optional. The identity extra currently pins ChromaDB to
    the audited pre-1.0 line while the affected 1.x line has no fixed release.
16. Human approval is one-shot, short-lived, session-bound, risk-bound, and
    bound to the canonical SHA-256 of the exact executable tool payload.
17. Planner, channel, or callback mutation after an approval intent is issued
    invalidates authorization. Execution uses a private deep snapshot, never
    the mutable plan or presentation object.
18. An approval timeout is absence of authorization and always fails closed.
19. Unknown/new tools default to R3/approval until added to the deterministic
    home-lab classifier and covered by a security-contract test.
20. An approved action is recorded in the authoritative append-only audit
    chain before execution. If the required audit trail is absent or its write
    fails, the approved action is converted to BLOCK and never reaches the
    executor.
21. Required pre-execution hooks are an integrity-checked security boundary.
    A missing runner, incomplete required hook set, or hook exception blocks
    the tool call before the MCP client is invoked.
22. The credential store has no plaintext/obfuscation fallback. Missing key
    material, malformed storage, or failed ciphertext authentication is a
    hard error and must never be interpreted as an empty store.
23. Credential injection is deterministic and strict by default. Malformed or
    unresolved mappings fail closed, and agent/capability-scoped injection
    cannot silently fall back to a global credential.
24. Known API credentials and private keys are removed before model input in
    home-lab mode. Sensitive-key values and recognized secret patterns are
    redacted from both authoritative and operational audit records.
25. Every named project has an independent memory namespace. Named projects
    never inherit legacy global memory, even when a caller omits a project
    filter or a historical database row predates project scoping.
26. Retrieved web, file, tool, and memory content is untrusted evidence, never
    authority. Model-visible evidence is provenance-checked, structurally
    delimited, and explicitly prohibited from overriding policy or system
    instructions.
27. External evidence cannot silently become durable memory. Home-lab
    reflection may store only project-scoped `agent_inference` evidence;
    procedure learning remains a reviewable proposal.
28. Public-ingestion HTTP validates every resolved address and every redirect,
    rejects private/link-local/loopback/metadata destinations, bounds response
    size, and redacts query/credential material from logs.
29. Community and generated skills are disabled at registry construction in
    home-lab mode. Configuration reload cannot silently re-enable them.
30. Persisted memory without valid source, project, trust, authority, and
    integrity metadata is quarantined before retrieval or model rendering.
31. Generic web and browser egress validates every destination and redirect,
    including WebSockets. Browser service workers are blocked, cross-origin
    credentials and request bodies are not replayed, HTTPS is not downgraded,
    and missing interception support disables the browser rather than
    weakening the boundary.
32. Browser interactions that can mutate external state, submit content, run
    page JavaScript, or trigger workflows are explicit R4 actions and remain
    denied by global safe mode.

## Risk policy

| Class | Meaning | Default |
|---|---|---|
| R0 | Explicitly classified read-only operation | Automatic |
| R1 | Named fail-closed disposable-sandbox execution | Automatic + inform |
| R2 | Deterministically project-scoped branch/workspace write | Automatic + inform |
| R3 | Staging, durable-memory, integration, or unknown capability | Approval |
| R4 | Production/external send, publish, device, UI, or broad write | Explicit approval |
| R5 | Host shell, raw Docker/remote execution, self-modification, destructive, security, credential, firmware, or financial action | Block |

The R0-R5 class is an authorization class independent of model estimates,
registry metadata, or local YAML policy. Cognithor's existing GREEN/YELLOW/
ORANGE/RED decision is raised to at least the deterministic class floor. R5 is
not made executable by ordinary approval.

## First release-candidate scope

The Home-Lab Security Baseline release candidate covers:

- deterministic home-lab risk floors;
- global safe mode and local break glass;
- fail-closed Gatekeeper and Executor security initialization;
- fail-closed sandbox selection and binary-loss behavior;
- generated-code network disabled by default;
- autonomous evolution/marketplace/self-repair defaults disabled;
- disabled improvement governance blocks rather than permits proposals;
- audit-chain HMAC comparison and startup integrity verification;
- runtime SQLite/SQLCipher error compatibility for idempotent migrations;
- a temporary ChromaDB `<1` constraint while the 1.x vulnerability remains
  without a fixed upstream release;
- security-contract regression tests for these invariants.

Exact-payload approvals, secret brokering, retrieval provenance, durable worker
leases/idempotency, and append-only cross-system run provenance remain required
follow-up release candidates. They must not be represented as complete here.

## Second release-candidate scope

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

The Exact-Action Authorization release candidate adds:

- deterministic R0-R5 action classification with approval-by-default for
  unknown tools;
- canonical tool-and-parameter hashing for exact-payload approvals;
- session, risk-class, expiration, target/payload, and one-shot replay binding;
- separate deep copies for the planner action, approval presentation, and
  executable approved snapshot;
- fail-closed handling for prompt-time mutation, UI/channel mutation,
  expiration, transport failure, rejection, and replay;
- bounded local break-glass requiring an exact acknowledgement, reason, and
  near-term expiry;
- permanent rejection of legacy timeout auto-approval;
- approval receipt fields in Gate decisions and append-only audit events;
- HMAC-capable authoritative approval-resolution recording before execution,
  with fail-closed behavior for missing or failed required audit storage.

All three rounds in `TEST_EVIDENCE.md` passed on 2026-07-26.

- Round 1 final regression: 18,894 passed, 39 skipped, zero failed.
- Round 2 adversarial/integration/failure testing: 3,957 passed, 7 skipped,
  zero failed.
- Round 3 installed-wheel, rollback/restore, voice-WebSocket, and final
  regression: 19,128 passed, 39 skipped, zero failed across the recorded
  non-overlapping commands.
- Weighted release score: 99.625/100.
- Unresolved Critical findings: zero.
- Unresolved High findings: zero.

The macOS release host proved fail-closed refusal when no secure isolation
backend is available. A live Ubuntu bubblewrap/container escape and private
network-isolation run remains a mandatory deployment gate, as it was for the
first baseline release.

## Third release-candidate scope

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

The Secret and Runtime Execution Boundary release candidate adds:

- fail-closed runtime behavior for exceptions in required pre-execution
  security hooks;
- integrity checks that the required secret-redaction and security-extension
  hooks are still registered before every tool execution;
- mandatory encrypted credential storage with explicit integrity and
  availability errors;
- strict credential mappings that reject malformed/unresolved references;
- scoped credential injection that denies implicit global-secret fallback;
- home-lab model-input stripping for known API keys and private keys, even
  when optional personal-data redaction is disabled;
- recursive sensitive-key and secret-pattern redaction in authoritative and
  operational audit parameters, results, reasons, and errors;
- security-contract tests covering missing/crashed runtime controls,
  credential corruption, scope broadening, and nested audit leaks.

All three rounds in `TEST_EVIDENCE.md` passed on 2026-07-26.

- Round 1 final regression: 18,910 passed, 39 skipped, zero failed.
- Round 2 adversarial/integration/failure testing: 3,971 passed, 7 skipped,
  zero failed.
- Round 3 release, installed-wheel, rollback/restore, voice-WebSocket, and
  final regression gates all passed.
- Weighted release score: 99.625/100.
- Unresolved Critical findings: zero.
- Unresolved High findings: zero.

This release establishes the credential-store and execution-hook foundation.
It does not yet represent every external connector as migrated to a single
per-capability secret broker. That integration work remains a follow-up and
must pass its own three-round acceptance cycle.

## Fourth release-candidate scope

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

The Project Memory, Provenance, and Untrusted-Evidence Boundary release
candidate adds:

- request-scoped project identity propagated through gateway, planner,
  reflector, retrieval, MCP memory, vault, and persistence paths;
- idempotent schema migration and fail-closed filtering for project-scoped
  chunks, entities, relations, search results, caches, and graph traversal;
- source/trust/authority/content-hash provenance created at ingestion and
  verified both at index write and immediately before model rendering;
- quarantine of forged, missing, or database-tampered provenance;
- explicit untrusted-evidence envelopes for retrieved memory, web, and tool
  output, including delimiter-breakout neutralization;
- prevention of silent project switching after a session contains messages;
- home-lab reflection limited to audited, project-scoped
  `agent_inference` evidence and review-only procedure proposals;
- disabled automatic learning and advanced self-improvement services in
  home-lab mode;
- construction-time prohibition of community and generated skill loading;
- fail-closed public-ingestion networking with DNS/address/redirect checks,
  private and metadata destination denial, bounded bodies, and redacted logs;
- append-only events for project reflection evidence and procedure proposals.

All three rounds in `TEST_EVIDENCE.md` passed on 2026-07-27.

- Round 1 final regression: 18,979 passed, 39 skipped, zero failed.
- Round 2 adversarial/integration/failure testing: 3,991 passed, 7 skipped,
  zero failed.
- Round 3 release-candidate, installed-wheel, recovery, isolation, and copied-
  source regression gates: 1,810 passed, zero failed across the recorded
  non-overlapping commands, plus all installed-artifact probes.
- Weighted release score: 99.625/100.
- Unresolved Critical findings in this candidate: zero.
- Unresolved High findings in this candidate: zero.

This candidate secures Cognithor's project-memory and knowledge-ingestion
paths. The generic MCP web client and interactive browser redirect paths are
not represented as covered by this acceptance; they remain disabled or
approval-constrained under the existing home-lab policy until a separate
network-boundary candidate passes the same three-round process.

## Fifth release-candidate scope

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

The Generic Web and Browser Egress Boundary release candidate adds:

- one bounded public HTTP request primitive for generic fetch, arbitrary HTTP
  requests, and Jina Reader access;
- validation of every DNS answer and redirect target, with private, loopback,
  link-local, CGNAT, reserved, multicast, local-name, and metadata denial;
- explicit domain allow/block policy on every hop;
- response-size enforcement on declared and streamed content;
- rejection of virtual-host override, proxy, forwarding, request-smuggling,
  CONNECT, and TRACE inputs;
- cross-origin stripping of authorization and cookies;
- refusal to replay request bodies or side-effecting methods to another
  origin, and refusal of HTTPS-to-HTTP redirect downgrade;
- Playwright interception for every HTTP request and WebSocket, with service
  workers blocked and initialization failing closed when interception is not
  supported;
- fail-closed direct browser DNS resolution, URL-log origin-only redaction,
  and no page-title logging;
- explicit R4 classification for v17 browser mutations and safe-mode denial;
- compatibility preservation for the existing v14 and v17 browser tool
  registrations.

All three rounds in `TEST_EVIDENCE.md` passed on 2026-07-27.

- Round 1 full regression: 19,023 passed, 39 skipped, zero failed.
- Round 2 adversarial/integration/failure testing: 4,066 passed, 7 skipped,
  zero failed.
- Round 3 release, rollback, WebSocket, copied-source regression, installed-
  wheel egress, sandbox-refusal, and prior-artifact restore gates: 1,077
  pytest cases passed, zero failed, plus every installed-artifact probe.
- Live dependency audit: no known vulnerabilities.
- Weighted release score: 99.625/100.
- Unresolved Critical findings in this candidate: zero.
- Unresolved High findings in this candidate: zero.

This acceptance is a branch-quality decision, not permission to deploy. The
application boundary is deliberately paired with a mandatory deployment
firewall/proxy gate because DNS validation and a later browser/HTTP connect
cannot be made atomic from this macOS test host.

## Accepted evidence for the first release candidate

The three required rounds completed on 2026-07-26. The detailed command and
result record is in `TEST_EVIDENCE.md`.

- Round 1 full regression: 18,860 passed, 39 skipped, zero failed.
- Round 2 security/adversarial/integration/failure testing: 3,877 passed,
  7 skipped, zero failed.
- Round 3 installed-wheel, fail-closed sandbox, rollback/restore, and final
  regression: 19,094 passed, 39 skipped, zero failed across the recorded
  non-overlapping commands.
- Separately excluded upstream voice-WebSocket file: 16 passed, zero failed.
- Live dependency audit: no known vulnerabilities.
- Weighted release score: 99.6/100.
- Unresolved Critical findings: zero.
- Unresolved High findings: zero.

The score applies only to this coherent security-baseline change set. It does
not claim that the complete Thomas AI end-state architecture is finished.

## Residual risks

1. **Medium — target Linux isolation proof remains a deployment gate.**
   The macOS validation host has neither bubblewrap, Firejail, nor Docker.
   The installed wheel was therefore tested for the required fail-closed
   behavior: an unavailable namespace sandbox refused execution and created
   no marker file. Before deployment on `control01` or a worker, the same
   release must also pass a real bubblewrap/container escape and network
   isolation test in the disposable Ubuntu VM.
2. **Low — ChromaDB compatibility debt.** The audited pre-1.0 line emits
   Pydantic deprecation warnings. Migrate to a fixed maintained release or a
   replacement backend when one is available and passes the same three rounds.
3. **Low — unrelated upstream lint debt.** A whole-repository Ruff run reports
   pre-existing issues in untouched `contrib/` and `scripts/` files. Every
   Python file in this patch set passes Ruff and formatting checks.
4. **Medium — DNS validation and connect are not atomic on this macOS test
   host.** Application-level checks reject every resolved private address and
   redirect. Deployment must additionally enforce worker/control-plane egress
   at the container/VM firewall so DNS rebinding cannot cross the boundary.
5. **Medium — live target-browser proof remains a deployment gate.**
   Browser HTTP/WebSocket interception and fail-closed startup passed with
   deterministic Playwright-compatible fakes and the installed wheel. Before
   unattended use, the exact wheel must also pass a live Chromium run inside
   the disposable Ubuntu trust zone with the VM firewall denying management
   networks.
6. **Low — legacy default-project compatibility remains intentionally
   readable.** It exists only for unscoped historical installations. Named
   projects cannot retrieve or promote that legacy global memory.
