# Thomas AI Test Evidence

No release has been accepted, merged, or deployed.

## Frozen baseline

- Commit: `78212af5396fd42cb7103b9edfe9b2e57909aac5`
- Branch state before edits: `main...homelab-hardening` identical
- Python runtime selected for testing: CPython 3.12.13

### Pre-change targeted baseline

Command:

```text
.venv/bin/python -m pytest tests/security_contracts \
  tests/test_security/test_gatekeeper_python.py \
  tests/test_mcp/test_shell.py tests/test_mcp/test_shell_coverage.py -q
```

Result: `295 passed in 4.02s`.

This is a compatibility baseline, not a release round.

## Release candidate: Home-Lab Security Baseline

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

### Round 1 — static, unit, security contracts, dependencies/config

Status: **PASS**

#### Static and configuration gates

Commands:

```text
git diff --check

git diff --name-only --diff-filter=ACM -- '*.py' |
  xargs .venv/bin/ruff check
.venv/bin/ruff check \
  src/cognithor/security/home_lab.py \
  tests/security_contracts/test_home_lab_security_baseline.py

git diff --name-only --diff-filter=ACM -- '*.py' |
  xargs .venv/bin/ruff format --check
.venv/bin/ruff format --check \
  src/cognithor/security/home_lab.py \
  tests/security_contracts/test_home_lab_security_baseline.py

.venv/bin/python -m mypy --strict \
  src/cognithor/config.py \
  src/cognithor/core/executor.py \
  src/cognithor/core/gatekeeper.py \
  src/cognithor/core/sandbox.py \
  src/cognithor/gateway/phases/security.py \
  src/cognithor/governance/improvement_gate.py \
  src/cognithor/mcp/code_tools.py \
  src/cognithor/mcp/database_tools.py \
  src/cognithor/mcp/shell.py \
  src/cognithor/mcp/tool_registry_db.py \
  src/cognithor/models.py \
  src/cognithor/security/audit.py \
  src/cognithor/security/sandbox.py \
  src/cognithor/security/home_lab.py

.venv/bin/python -m pip check
.venv/bin/python -m pip_audit
```

Results:

- diff whitespace/error check: pass;
- Ruff lint on every changed/new Python file: pass;
- Ruff formatting on 41 changed/new Python files: pass;
- strict mypy: `Success: no issues found in 14 source files`;
- dependency consistency: `No broken requirements found`;
- live vulnerability audit: `No known vulnerabilities found`.

The whole repository contains unrelated pre-existing Ruff failures in untouched
`contrib/` and `scripts/` files. They were not hidden or auto-fixed as part of
this security patch. Patch-scope lint is the release gate.

#### Full regression

Command:

```text
.venv/bin/python -m pytest tests/ -q --tb=short \
  --ignore=tests/test_channels/test_voice_ws_bridge.py
```

Final result after repair:

```text
18860 passed, 39 skipped, 3547 warnings in 782.54s (0:13:02)
```

The separately selected voice-WebSocket test file later passed 16/16 in Round
3. The warnings are deprecation notices, dominated by the temporary ChromaDB
pre-1.0 compatibility pin; no test warning represented a failed assertion.

#### Failures found and fixed

1. The first full run found seven remaining legacy-policy/platform failures:
   - self-improvement expected enabled by default;
   - `run_python`, durable memory writes, and chained memory writes expected
     execution without an approval channel;
   - direct `create_skill` expected model execution;
   - a Bash arithmetic/`errexit` demonstration assumed Bash 4+ behavior.
2. Fixes:
   - preserved the disabled self-improvement default;
   - positive E2E execution tests now install an explicit approval channel;
   - direct skill self-modification now asserts that no tool call occurs;
   - the explanatory arithmetic test skips only on Apple Bash 3.2, while the
     actual source scanner prohibiting `((errors++))` remains active.
3. Targeted confirmation: `6 passed, 1 skipped`.
4. The clean full rerun then passed with the count above.

### Round 2 — integration, adversarial, bypass, failure injection

Status: **PASS**

#### Security, adversarial, and permission-bypass group

Command:

```text
.venv/bin/python -m pytest \
  tests/security_contracts tests/adversarial tests/test_security \
  -q --tb=short
```

Result:

```text
2146 passed, 5 skipped, 2 warnings in 27.41s
```

This group includes policy/registry downgrade attempts, prompt-injection
corpus cases, path/symlink escapes, AST guard bypasses, credential masking,
safe-mode spoofing, memory-poisoning promotion attempts, audit tampering, and
required-control failure behavior.

#### Integration and E2E group

Command:

```text
.venv/bin/python -m pytest \
  tests/test_integration tests/integration tests/test_e2e_scenarios.py \
  -q --tb=short
```

Result:

```text
1421 passed, 2 skipped, 1 warning in 41.49s
```

#### Failure injection, worker retry, locking, and idempotency group

The first selection failed before collection because two guessed paths did not
exist (`tests/test_gateway/test_executor.py` and
`tests/test_gateway/test_retry.py`). This was recorded as a test-process
failure. The actual upstream paths were discovered and the corrected command
was run:

```text
.venv/bin/python -m pytest \
  tests/chaos \
  tests/test_core/test_worker.py \
  tests/test_core/test_distributed_lock.py \
  tests/test_core/test_distributed_lock_coverage.py \
  tests/test_crew/test_idempotent_kickoff.py \
  tests/test_cron/test_engine.py \
  tests/test_core/test_workflow.py \
  tests/test_core/test_executor.py \
  tests/test_core/test_executor_coverage.py \
  tests/test_core/test_llm_retry.py \
  tests/test_db/test_sqlite_retry.py \
  -q --tb=short
```

Result:

```text
310 passed in 27.73s
```

Round 2 aggregate:

```text
3877 passed, 7 skipped, 0 failed
```

### Round 3 — isolated RC, sandbox isolation, rollback, regression

Status: **PASS**

#### Release build

Command:

```text
.venv/bin/python -m pytest tests/release -q --tb=short
```

The first sandboxed attempt could not resolve PyPI while creating the isolated
PEP 517 build environment. No product assertion failed. The same command was
rerun with approved network access:

```text
4 passed in 1.12s
```

#### Disposable installed-wheel test

Commands:

```text
.venv/bin/python -m build --wheel \
  --outdir /private/tmp/cognithor-rc-round3.02n1YT/dist

.venv/bin/python -m venv --system-site-packages \
  /private/tmp/cognithor-rc-round3.02n1YT/venv-system

/private/tmp/cognithor-rc-round3.02n1YT/venv-system/bin/python \
  -m pip install --no-deps \
  /private/tmp/cognithor-rc-round3.02n1YT/dist/\
cognithor-0.99.0-py3-none-any.whl
```

Results:

- wheel built successfully;
- wheel installed outside the source tree;
- installed package reported `0.99.0`;
- installed `cognithor.security.home_lab` resolved from the disposable venv,
  not the repository source.

An earlier `--no-deps` import attempt failed on missing Pydantic as expected
and was replaced by the disposable environment above. This was retained as
evidence that the test did not accidentally import the source checkout.

#### Installed-artifact policy and sandbox checks

From `/private/tmp`, using the installed wheel:

- requested `NAMESPACE` execution on a host without bubblewrap/nsjail;
- command attempted to create a marker file;
- result returned exit code `-1`, `isolation_degraded=True`;
- marker file did not exist;
- a model-supplied GREEN estimate for `exec_command` remained ORANGE/APPROVE.

Result:

```text
fail_closed_sandbox=PASS
risk_floor=PASS
```

#### Rollback/restore

Command:

```text
.venv/bin/python -m pytest \
  tests/test_governance/test_policy_patcher.py \
  tests/test_governance/test_policy_patcher_ext.py \
  tests/test_packs/test_installer.py \
  tests/test_system/test_hardware_aware_runtime.py \
  tests/test_core/test_checkpoint.py \
  tests/test_integration/test_v18_graph_orchestrator.py \
  tests/security_contracts/test_inv5_audit_chain_integrity.py \
  tests/test_evolution_orchestrator.py \
  -q --tb=short
```

Result:

```text
214 passed in 0.84s
```

The remote `main`, local HEAD, and frozen baseline all resolved to:

```text
78212af5396fd42cb7103b9edfe9b2e57909aac5
```

Ahead/behind before committing: `0 / 0`. The patch therefore had not modified,
merged into, or deployed from `main`.

#### Final regression

Command:

```text
.venv/bin/python -m pytest tests/ -q --tb=short \
  --ignore=tests/test_channels/test_voice_ws_bridge.py
```

Result:

```text
18860 passed, 39 skipped, 3547 warnings in 797.65s (0:13:17)
```

Separately:

```text
.venv/bin/python -m pytest \
  tests/test_channels/test_voice_ws_bridge.py -q --tb=short

16 passed in 0.13s
```

Test-generated sample-skill rewrites and twelve stray MagicMock-named SQLite
files were detected after the regression, restored/moved out of the repository,
and excluded from the patch. The final patch-scope static checks passed after
that cleanup.

### Acceptance score

All hard gates passed. Zero unresolved Critical or High findings.

| Dimension | Weight | Result | Weighted |
|---|---:|---:|---:|
| Deterministic policy and fail-closed controls | 40 | 100.0 | 40.000 |
| Regression and compatibility | 20 | 100.0 | 20.000 |
| Adversarial, bypass, integration, failure behavior | 20 | 100.0 | 20.000 |
| Packaging, isolation, rollback, recovery | 15 | 97.5 | 14.625 |
| Evidence, maintainability, upstream discipline | 5 | 100.0 | 5.000 |
| **Total** | **100** |  | **99.625 / 100** |

Reported release score: **99.6/100 — PASS**

The packaging/isolation category is reduced because this macOS host has no
Docker, bubblewrap, or Firejail. The release proved fail-closed refusal rather
than a live Linux namespace escape test. A real Ubuntu bubblewrap/container
test remains a mandatory pre-deployment gate and is documented as a Medium
residual risk, not hidden by the score.

This score is a deterministic engineering acceptance rubric for this patch
scope. It is not a statistical claim of 99.6% reliability and it does not
assert that later Thomas AI architecture patch sets are already complete.

## Release candidate: Exact-Action Authorization

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

Scope:

- R0-R5 deterministic authorization classes;
- exact-payload, one-time, expiring approvals;
- immutable approval/execution snapshots;
- bounded local break-glass;
- fail-closed approval timeout behavior;
- approval provenance fields and events.

### Pre-round engineering checks

The first combined targeted selection exposed seven pre-existing expectations
that conflicted with the stricter default-deny R3 floor. The affected
capabilities were unscoped artifact generation, desktop screenshots,
synthesis, database connection, and an unclassified custom tool. The product
policy was not weakened. The compatibility tests were split so the genuinely
R0/R2 cases retain their original assertions, while new security-contract
tests assert that unscoped/sensitive and unknown tools require approval.

A review of nested model mutability also found that a frozen `PlannedAction`
still contains mutable dictionaries. The implementation was repaired to use
three separate objects: the live planner action, a presentation copy, and a
private deep execution snapshot. Tests now mutate both the planner action and
the channel presentation object and verify fail-closed behavior.

Current targeted command:

```text
.venv/bin/python -m pytest -q \
  tests/test_gateway/test_pge_loop_deep.py \
  tests/test_gateway/test_gateway.py \
  tests/test_gateway/test_gateway_coverage.py \
  tests/test_core/test_gatekeeper.py \
  tests/test_core/test_models.py \
  tests/test_core/test_executor.py \
  tests/test_hitl_manager.py \
  tests/test_integration/test_v20_hitl.py \
  tests/security_contracts
```

Current result:

```text
697 passed, 0 failed, 1 deprecation warning in 3.94s
```

This targeted result is pre-round evidence only. It is not a substitute for
the required three release rounds below.

### Round 1 — static, unit, security contracts, dependencies/config

Status: **PASS**

Static gates passed before the first full run:

- `git diff --check`: pass;
- Ruff lint: pass;
- Ruff format: pass;
- strict mypy: `Success: no issues found in 7 source files`;
- dependency consistency: `No broken requirements found`;
- live dependency audit: `No known vulnerabilities found`.

The first full regression was rejected:

```text
18875 passed, 39 skipped, 15 failed in 781.63s
```

Failure analysis found:

1. Ten legacy assertions expected model/registry metadata to downgrade raw
   shell, remote shell, host screenshots, durable identity/goals, or unknown
   pack tools. Their expected values were replaced with stricter security
   assertions; product controls were not relaxed.
2. Five document-creation E2E cases identified a real classification/
   implementation mismatch. `document_export` was intended as a confined
   project write but used a hard-coded home directory and was classified as
   unscoped R3. The implementation now uses the configured media workspace,
   sanitizes the filename, and the deterministic classifier recognizes only
   this named confined capability as R2.
3. The first targeted media retest then caught a `config=None` compatibility
   defect in the new workspace wiring. It was repaired with the original
   default-workspace fallback.

Targeted confirmation after repair:

```text
135 passed, 0 failed, 2 deprecation warnings in 3.90s
```

A clean full Round 1 rerun is required before PASS.

The initial clean rerun passed:

```text
18891 passed, 39 skipped, 3547 warnings in 760.21s (0:12:40)
```

During final review, the approval receipt was found to be present in the
returned result and run recorder but not guaranteed to be committed to the
authoritative tamper-evident `AuditTrail` before execution. Acceptance was
withdrawn and all three rounds were restarted after adding that hard gate.

The first restarted static attempt was rejected because Ruff formatting found
two files. They were formatted and every static gate was rerun. The first
restarted full regression then found four failures:

```text
18890 passed, 39 skipped, 4 failed, 3547 warnings in 742.34s
```

All four were E2E fixtures that simulated explicit approval while constructing
a partial Gateway without its required audit trail. Product execution failed
closed as designed. The fixtures were repaired to use a real HMAC-backed
append-only `AuditTrail`; the four scenarios then passed without relaxing the
product control.

The final clean Round 1 rerun passed:

```text
18894 passed, 39 skipped, 3547 warnings in 757.71s (0:12:37)
```

Round 1 final result: PASS.

### Round 2 — integration, adversarial, bypass, failure injection

Status: **PASS**

Commands:

```text
.venv/bin/python -m pytest \
  tests/security_contracts tests/adversarial tests/test_security \
  tests/test_gateway/test_pge_loop_deep.py \
  -q --tb=short

.venv/bin/python -m pytest \
  tests/test_integration tests/integration tests/test_e2e_scenarios.py \
  -q --tb=short

.venv/bin/python -m pytest \
  tests/chaos \
  tests/test_core/test_worker.py \
  tests/test_core/test_distributed_lock.py \
  tests/test_core/test_distributed_lock_coverage.py \
  tests/test_crew/test_idempotent_kickoff.py \
  tests/test_cron/test_engine.py \
  tests/test_core/test_workflow.py \
  tests/test_core/test_executor.py \
  tests/test_core/test_executor_coverage.py \
  tests/test_core/test_llm_retry.py \
  tests/test_db/test_sqlite_retry.py \
  -q --tb=short
```

Results:

- security/adversarial/bypass: `2226 passed, 5 skipped`;
- integration/E2E: `1421 passed, 2 skipped`;
- failure/retry/idempotency: `310 passed`;
- aggregate: `3957 passed, 7 skipped, 0 failed`.

The initial parallel orchestration returned the integration subprocess at 96%
without a terminal status. It was not counted. The integration command was
rerun directly and produced the complete passing result above.

### Round 3 — isolated RC, sandbox isolation, rollback, regression

Status: **PASS**

Release suite:

```text
.venv/bin/python -m pytest tests/release -q --tb=short
4 passed
```

An isolated wheel was built:

```text
.venv/bin/python -m build --wheel --outdir <disposable>/dist
Successfully built cognithor-0.99.0-py3-none-any.whl
```

The first disposable-venv probe stopped before product import because that
venv did not contain PyYAML. The wheel was then installed into an isolated
target directory and executed from `/private/tmp` with the already-audited
project dependencies. The probe asserted that `cognithor.__file__` resolved
from `wheel-target`, not the source checkout. Its first audit-chain assertion
used `None` instead of the API's documented intact-chain sentinel `-1`; the
probe was corrected and rerun. No product code changed for either probe setup
failure.

Installed-wheel results:

```text
exact_payload_mutation=PASS
risk_floors=PASS
document_workspace_confinement=PASS
approval_audit_chain=PASS
sandbox_level=bare
sandbox_fail_closed=PASS
```

The sandbox probe attempted to create a marker file. With no bwrap, Firejail,
or Windows Job Object available on the macOS release host, execution returned
the expected refusal and no marker was created.

Rollback/restore:

```text
.venv/bin/python -m pytest \
  tests/test_governance/test_policy_patcher.py \
  tests/test_governance/test_policy_patcher_ext.py \
  tests/test_packs/test_installer.py \
  tests/test_system/test_hardware_aware_runtime.py \
  tests/test_core/test_checkpoint.py \
  tests/test_integration/test_v18_graph_orchestrator.py \
  tests/security_contracts/test_inv5_audit_chain_integrity.py \
  tests/test_evolution_orchestrator.py \
  -q --tb=short

214 passed
```

Separately isolated voice-WebSocket suite:

```text
16 passed
```

Final independent regression:

```text
18894 passed, 39 skipped, 3547 warnings in 745.31s (0:12:25)
```

The full suite rewrote upstream sample-skill fixtures and created six
MagicMock-named SQLite artifacts over the three full regressions in this
candidate's complete history (two per run). Each was identified as
test-generated, restored/removed, and excluded from the release diff before
final static validation.

### Acceptance score

All hard gates passed. Zero unresolved Critical or High findings.

| Dimension | Weight | Result | Weighted |
|---|---:|---:|---:|
| Deterministic R0-R5 and exact-action authorization | 40 | 100.0 | 40.000 |
| Regression and compatibility | 20 | 100.0 | 20.000 |
| Adversarial, bypass, integration, failure behavior | 20 | 100.0 | 20.000 |
| Packaging, isolation, rollback, recovery | 15 | 97.5 | 14.625 |
| Evidence, maintainability, upstream discipline | 5 | 100.0 | 5.000 |
| **Total** | **100** |  | **99.625 / 100** |

Reported release score: **99.625/100 — PASS**

The 2.5-point deduction inside the packaging/isolation category reflects the
absence of a Linux namespace/container runtime on this macOS validation host.
The installed wheel proved fail-closed refusal. A real Ubuntu isolation and
private-network-egress test remains a mandatory deployment gate and is not
represented as complete.

## Release candidate: Secret and Runtime Execution Boundary

Status: **ACCEPTED FOR A REVIEWABLE BRANCH COMMIT — NOT MERGED OR DEPLOYED**

### Pre-change focused baseline

Command:

```text
.venv/bin/python -m pytest \
  tests/test_core/test_tool_hooks.py \
  tests/test_core/test_model_router.py \
  tests/test_security/test_credentials.py \
  tests/security_contracts/test_inv8_credential_masking.py \
  tests/test_integration/test_agent_separation.py \
  -q --tb=short
```

Result:

```text
123 passed in 3.27s
```

The code-level audit then confirmed:

- pre-tool security-hook exceptions were logged and ignored;
- the Executor also swallowed unexpected pre-hook failures;
- the credential store treated malformed storage as an empty store and
  authentication/decryption failure as a missing credential;
- strict scoped injection did not exist;
- known-secret model-input redaction was optional;
- the operational audit did not mask tool results and only sanitized exact
  top-level credential key names.

### Round 1 — static, unit, security contracts, dependencies/config

Status: **PASS AFTER A REJECTED FULL RUN AND REPAIR**

Static/configuration commands:

```text
git diff --check

.venv/bin/ruff check <all changed Python files>
.venv/bin/ruff format --check <all changed Python files>

.venv/bin/python -m mypy --strict \
  src/cognithor/audit/__init__.py \
  src/cognithor/core/executor.py \
  src/cognithor/core/model_router.py \
  src/cognithor/core/tool_hooks.py \
  src/cognithor/security/audit.py \
  src/cognithor/security/credentials.py \
  tests/security_contracts/test_secret_execution_boundary.py

.venv/bin/python -m pip check
.venv/bin/python -m pip_audit
```

Results:

- diff whitespace/error check: pass;
- Ruff lint: pass;
- Ruff format: all 14 selected Python files formatted;
- strict mypy: `Success: no issues found in 7 source files`;
- dependency consistency: `No broken requirements found`;
- live dependency audit: `No known vulnerabilities found`.

The first dependency-audit attempt was rejected because the local execution
sandbox could not resolve PyPI. The exact audit was rerun with approved
network access and passed.

Focused compatibility/security confirmation after implementation:

```text
294 passed, 0 failed
```

The first full regression was rejected:

```text
18908 passed, 39 skipped, 2 failed, 3547 warnings in 733.84s
```

Both failures were legacy audit tests:

1. a sensitive `api_key` field expected partial masking rather than full
   field redaction;
2. a sensitive `tokens` container expected a non-secret-looking sibling to
   remain visible.

The security rule was not weakened. Sensitive container shape is now
preserved for consumers, while every leaf beneath an explicitly sensitive
field is fully redacted. The stale tests were strengthened. Targeted audit
and security-contract repair confirmation:

```text
61 passed, 0 failed
```

The clean full Round 1 rerun passed:

```text
18910 passed, 39 skipped, 3547 warnings in 740.67s (0:12:20)
```

### Round 2 — integration, adversarial, bypass, failure injection

Status: **PASS**

Commands:

```text
.venv/bin/python -m pytest \
  tests/security_contracts tests/adversarial tests/test_security \
  tests/test_gateway/test_pge_loop_deep.py \
  -q --tb=short

.venv/bin/python -m pytest \
  tests/test_integration tests/integration tests/test_e2e_scenarios.py \
  -q --tb=short

.venv/bin/python -m pytest \
  tests/chaos \
  tests/test_core/test_worker.py \
  tests/test_core/test_distributed_lock.py \
  tests/test_core/test_distributed_lock_coverage.py \
  tests/test_crew/test_idempotent_kickoff.py \
  tests/test_cron/test_engine.py \
  tests/test_core/test_workflow.py \
  tests/test_core/test_executor.py \
  tests/test_core/test_executor_coverage.py \
  tests/test_core/test_llm_retry.py \
  tests/test_db/test_sqlite_retry.py \
  -q --tb=short
```

Results:

- security/adversarial/bypass: `2237 passed, 5 skipped`;
- integration/E2E: `1421 passed, 2 skipped`;
- failure/retry/idempotency: `313 passed`;
- aggregate: `3971 passed, 7 skipped, 0 failed`.

The new adversarial contracts prove that:

- deleting or crashing required pre-execution controls cannot reach the tool
  client;
- malformed/unresolved mappings cannot preserve a model-supplied credential
  value;
- scoped injection cannot silently consume a global credential;
- corrupted encrypted storage never becomes an apparently empty store;
- nested sensitive-key values and tool results cannot survive audit
  serialization.

### Round 3 — isolated RC, sandbox isolation, rollback, regression

Status: **PASS**

Release, rollback/restore, and voice suites:

```text
.venv/bin/python -m pytest tests/release -q --tb=short
4 passed

.venv/bin/python -m pytest \
  tests/test_governance/test_policy_patcher.py \
  tests/test_governance/test_policy_patcher_ext.py \
  tests/test_packs/test_installer.py \
  tests/test_system/test_hardware_aware_runtime.py \
  tests/test_core/test_checkpoint.py \
  tests/test_integration/test_v18_graph_orchestrator.py \
  tests/security_contracts/test_inv5_audit_chain_integrity.py \
  tests/test_evolution_orchestrator.py \
  -q --tb=short
214 passed

.venv/bin/python -m pytest \
  tests/test_channels/test_voice_ws_bridge.py -q --tb=short
16 passed
```

An isolated wheel was built and installed outside the source tree:

```text
Successfully built cognithor-0.99.0-py3-none-any.whl
Successfully installed cognithor-0.99.0
```

The first install command used a repository-relative `.venv/bin/python` while
its working directory was `/private/tmp`; it stopped before installation with
`no such file or directory`. The corrected command used the exact absolute
interpreter path. No product code or test assertion was changed.

The installed-wheel probe asserted that `cognithor.__file__` resolved from the
disposable `wheel-target` and returned:

```text
installed_import=PASS
credential_integrity=PASS
credential_scope=PASS
audit_redaction=PASS
model_secret_redaction=PASS
runtime_hook_fail_closed=PASS
sandbox_fail_closed=PASS
```

The sandbox probe attempted to create a marker file. The macOS validation host
had no bubblewrap, Firejail, or Windows Job Object, so execution failed closed
and the marker was not created.

Final independent regression:

```text
18910 passed, 39 skipped, 3547 warnings in 728.13s (0:12:08)
```

The three full runs in this candidate's history rewrote upstream sample-skill
fixtures and created six MagicMock-named SQLite artifacts (two per run). Each
artifact was positively identified as test-generated, restored/removed, and
excluded from the release diff before final validation.

### Acceptance score

All hard gates passed. Zero unresolved Critical or High findings.

| Dimension | Weight | Result | Weighted |
|---|---:|---:|---:|
| Secret boundary and required runtime-control correctness | 40 | 100.0 | 40.000 |
| Regression and compatibility | 20 | 100.0 | 20.000 |
| Adversarial, bypass, integration, failure behavior | 20 | 100.0 | 20.000 |
| Packaging, isolation, rollback, recovery | 15 | 97.5 | 14.625 |
| Evidence, maintainability, upstream discipline | 5 | 100.0 | 5.000 |
| **Total** | **100** |  | **99.625 / 100** |

Reported release score: **99.625/100 — PASS**

The packaging/isolation deduction reflects the absence of a live Linux
namespace/container runtime on the macOS validation host. The installed wheel
proved fail-closed refusal. A real Ubuntu isolation and private-network-egress
test remains a mandatory deployment gate and is not represented as complete.

Residual Medium work, outside this accepted patch set:

- migrate every external connector to the deterministic per-capability secret
  broker rather than a mix of environment/keyring lookup paths;
- make durable project-scoped retrieval provenance authoritative and
  fail-closed for untrusted memory promotion;
- prove network-denying sandbox behavior on the target disposable Ubuntu VM.
