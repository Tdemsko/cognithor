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
