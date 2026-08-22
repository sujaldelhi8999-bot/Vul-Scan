# Strix → PhantomScan Feature Mapping

Companion to `docs/STRIX_REFERENCE.md`. Maps every meaningful Strix (OSS) capability to PhantomScan's existing modules, identifies gaps, and proposes concrete adoption ideas.

**Methodology:** Strix features were extracted from the analyzed commit (`usestrix/strix @ 657aa5c`) — code + `docs/` + skills. PhantomScan references point to files under `backend/app/` unless noted. "—" = no equivalent.

---

## 1. Agent Architecture & Orchestration

| Strix | PhantomScan equivalent | Notes / Gap |
|---|---|---|
| `AgentCoordinator` agent-tree + statuses (`strix/core/agents.py`) | `agents/orchestrator.py` — `OrchestratorAgent.run()`, `gather_agents()` (parallel execution), `set_progress()`, `publish()` (WS events) | Strix: dynamic LLM-spawned tree with per-agent status/mailbox. PS: fixed in-process agent pipeline with phase progress. No per-agent graph state in PS. |
| Dynamic subagent spawning (`create_agent`) | `agents/orchestrator.py:566 run_agent()` (fixed registry of agents); `security_assessment.py` (9 sub-agents suite) | PS agent set is static/configured per scan; Strix root agent decides specialists at runtime from recon results. |
| `send_message_to_agent` / `wait_for_agents` mailboxes | `websockets.py` scan telemetry (one-way server→UI events); no inter-agent mailboxes | Strix: bidirectional peer messaging with interrupts. PS: agent-to-agent data flows through the orchestrator's gather/persist steps only. |
| `view_agent_graph` (live tree) | `routers/agents.py` (`/api/agents/status` — flat status list) | PS lacks a tree/status-per-agent snapshot; Strix shows parent/child + status + wait reason. |
| Crash recovery / nudge caps (`recovery_counts`, `idle_resume_counts`) | `agents/__init__.py` agent error handling; `self_audit.py` | No per-agent turn-recovery budget in PS (PS agents are deterministic functions, less failure-prone). |
| Snapshot + resume (`agents.json`, `agents.db`, `--resume`) | `database.py` scan rows with `status`/`progress`; no scan resume | PS scans are restartable only as new scans; Strix resumes mid-graph with conversation history. |
| Budget hooks ($USD + max-turns, `budget_paused`) | `config.py` — `MAX_SCAN_DURATION`, `MAX_TOTAL_REQUESTS`, `MAX_CONCURRENT_SCANS`, rate limits | PS enforces request/request-rate/credential budgets; Strix enforces LLM-cost budgets. Complementary. |
| Root agent = orchestrator; children = specialists | `orchestrator.py` does both orchestration and module execution | PS's PentestAgent (all `_test_*` methods) is exactly the kind of "single agent, many vuln types" Strix's deep-mode skill warns against. |
| Iteration limits (300 default) | `MAX_SCAN_DURATION` + request caps | Same intent, different currency. |

## 2. Skill / Knowledge System

| Strix | PhantomScan equivalent | Notes / Gap |
|---|---|---|
| 59 markdown skills in 10 categories (`strix/skills/`) | — | **Biggest structural gap.** PS knowledge lives in Python: `agents/exploitation/*.py` (21 exploit checkers), `pentest.py` `_test_*` methods, `cve_matcher.py`. No LLM-injectable knowledge packages. |
| Skills injected into system prompt (Jinja) | `services/openrouter_client.py` (prompt assembly for explainer/analyst/fixer) | PS prompts are hand-written per agent; a skills layer could feed the AI analyst/fixer context. |
| `load_skill` runtime tool (max 5) | — | No runtime knowledge loading in PS. |
| `skill_search_dirs()` / `register_skill_dir()` extensibility | — | Strix supports user-contributed skill dirs; PS has no equivalent plugin mechanism. |
| `tooling/*` playbooks (nmap, nuclei, sqlmap…) | `agents/scanner.py` (nmap/naabu-style port scan), `exploitation/sqli.py` (sqlmap-style checks) | Strix hands CLI tools to the LLM; PS reimplements checks in Python. Skills document *how* to run tools; PS has no docs-to-LLM bridge. |
| `scan_modes/{quick, standard, deep}` skills | `models.py` scan `mode` field; `routers/scan.py` | PS mode picks module set; Strix mode changes methodology/context + reasoning effort. |
| `coordination/source_aware_whitebox`, `custom/source_aware_sast` | `exploitation/dependency_security.py`, `security_assessment.py` ThreatIntelligence sub-agent | PS has SAST-ish/dependency checks but no white-box orchestration playbook. |

## 3. Multi-Agent Orchestration Pattern

| Strix | PhantomScan equivalent | Notes / Gap |
|---|---|---|
| Root delegates, children report via `agent_finish` completion reports | `orchestrator.py` `persist_findings()` collects from fixed agents; `gather_agents()` runs them in parallel | PS: coordinator-collected. Strix: parent-inbox reports with summary/findings/recommendations fields. |
| Shared notes + todos persisted per run | `database.py` findings/scan tables; `notifier.py`; no notes/todos concept | PS persists findings, not working notes/task state. |
| Shared Caido proxy history (`list_requests`, `view_sitemap`…) | `agents/browser_security.py` + `services/browser_observation.py` (Playwright capture); no request store | Strix: one shared intercepted-traffic store all agents read. PS: per-agent capture, no central replayable store. |
| Parallel swarm decomposition (component → feature → vuln level) | `security_assessment.py` suite + orchestrator phase parallelism | PS parallelism is fixed; Strix scales with target decomposition. |
| White-box: source repo targets | `pentest.py` `_fingerprint_db`, `scanner.py`; scan accepts URL mainly | PS supports codebases via scanner/TLS/etc.; no source-aware triage pipeline. |

## 4. Target Complexity Index (TCI) & ScanPlanner

**Strix status:** proposal only — GitHub issue #46 (unimplemented). See `STRIX_REFERENCE.md` §5.

| Strix (proposed) | PhantomScan equivalent | Notes |
|---|---|---|
| TCI 0–100 from target fingerprint | `services/active_security.py` — `AttackSurfaceMapper` (attack surface map: surfaces, tech, ports, parameters) + `score_findings()` (severity×confidence score) + `active.py:96 passive_plan_score()` | PS already computes surface-derived scores; a TCI value is a small extension over these. |
| ScanPlanner: TCI → prioritized plan (steps, modules, safe_mode, quotas) | `services/active_security.py:357 SecurityTestPlanner.create_plan()` (module selection from surfaces + `module_hints`), `create_verification_plan()` (evidence-weighted, planner v2.0) | **PhantomScan is ahead of Strix here** — implemented and v2 (browser/network evidence notes, authorization context, tech). |
| `strix/modules/registry.py` module priority metadata | `active_security.py` `CANONICAL_MODULES`, `normalize_modules()`, `active_limits()` | Module gating exists in PS (`services/active_gate.py`, `policy.py`); per-module priority tiers could be added. |
| Payload: `{target, fingerprint, tci, plan[]}` | `routers/active.py` `/api/active/map` + `/api/active/score` + `/api/active/run` | PS API already returns plan + score + limits to the client. |

## 5. Auto-Fix & PR Generation

| Strix | PhantomScan equivalent | Notes / Gap |
|---|---|---|
| `create_vulnerability_report` (CVSS vector/score, CWE, code locations, remediation) | `models.py` Finding (severity, confidence, `cvss_score`, CWE, `verification` PoC steps, `remediation_status`, `verification_status`) | Near-parity on the finding schema (Strix: CWE validation; PS: verification workflow). |
| Fix loop: `apply_patch` tool + re-run + re-verify | `agents/fixer.py` (prioritized markdown remediation checklist), `routers/findings.py` `POST /api/findings/{id}/verify` | **Gap:** PS generates *instructions*, not *patches*. `verify` endpoint exists but fix-verification re-test loop is manual. |
| `create_dependency_report` (advisory CVEs) | `exploitation/dependency_security.py` + `agents/cve_matcher.py` (NVD) | Parity on dependency CVE detection; Strix files into central report store. |
| PR generation (platform-only) | — | Neither OSS Strix nor PS creates PRs. PS's `fixer.py` + findings API is the natural hook for an autofix-PR feature. |
| SARIF export (`strix/report/sarif.py`) | — | PS exports markdown reports (`_write_report_files`); no SARIF. |

## 6. Agent Tools

| Strix tool | PhantomScan equivalent | Notes / Gap |
|---|---|---|
| Caido proxy tools (repeat_request, sitemap) | `browser_security.py` + `services/browser_observation.py` | PS observes via Playwright; no intercepting proxy / request replay. |
| `agent_browser` (Playwright) | `browser_security.py` (Playwright) | Parity. |
| `web_search` | `shadow_recon.py` (OSINT: wayback, dorks), `services/intelligence_service.py` | Parity in intent. |
| `exec_command` sandbox shell | `agents/sandbox_manager.py` (subprocess w/ resource limits), `dos.py` workers | PS runs Python checks in-process w/ limits; Strix runs LLM-driven shell in Docker. |
| `think` / notes / todos | — | No agent-side working memory layer in PS. |
| `respond_to_user` (interactive steering) | `routers/scan.py` stop endpoint; `websockets.py` | No mid-scan steering in PS (UI→scan), Strix has full duplex steering. |

## 7. Reporting, Viewer, CI/CD

| Strix | PhantomScan equivalent | Notes / Gap |
|---|---|---|
| Run artifacts dir + `strix view` local dashboard | Frontend dashboard + `features/reports`, `features/findings` pages | Parity. PS adds WebSocket live telemetry which Strix only partially matches. |
| Live agent graph UI | `frontend/src/components/layout/AppShell.tsx` agent status; no graph | Gap: no live agent-tree visualization. |
| Headless `-n` mode, non-zero exit on findings | `routers/scan.py` + `workers/active_worker.py` | PS has equivalent automation surface via API. |
| CI/CD GitHub Actions quick scans, diff-scope | `docker/docker-compose.yml` + API | No GitHub Actions workflow/PR-diff scoping in PS. |
| Scan modes quick/standard/deep | `models.py` `mode` + DoS intensity tiers (`dos.py`) | PS modes are broader; no reasoning-effort control (PS LLM calls are prompt-level only). |

## 8. Gap Summary (priority-ordered)

| # | Gap | Severity | Effort |
|---|---|---|---|
| 1 | **No skill/knowledge-package layer** for LLM context | High | Medium |
| 2 | **Fixer produces instructions, not patches** (no apply-patch-style autofix loop) | High | Medium |
| 3 | No dynamic agent spawning (fixed pipeline vs LLM-decided specialists) | Medium | High |
| 4 | No TCI value (planner exists; a complexity index is a thin add) | Low | Low |
| 5 | No inter-agent messaging / notes-todos working memory | Low | Medium |
| 6 | No live agent-graph UI | Low | Medium |
| 7 | No SARIF export | Low | Low |
| 8 | No GitHub Actions integration / diff-scope | Low | Low |

## 9. Adoption Recommendations (for PhantomScan)

1. **Build a `backend/app/skills/` knowledge layer.** Port Strix's `vulnerabilities/` markdown as structured prompt-context packages consumed by `ai_security_analyst.py`, `ai_explainer.py`, and `fixer.py`. Start with 8–10 vuln classes where PS modules already exist (SQLi, XSS, SSRF, SSRF→XXE, JWT, IDOR, file upload, race conditions), each containing: attack surface notes, payload primitives, and *false-positive validation steps*. This converts PS's LLM agents from generic to expert-tuned with zero changes to the exploitation engines.
2. **Add a TCI-style complexity score to the active-testing flow.** In `services/active_security.py`, compute `tci ∈ [0,100]` from the mapped attack surface (surface count, API/auth surfaces present, tech stack size, ports) and feed it into `SecurityTestPlanner.create_plan()` + `active_limits()` to tier module priority and quota (`safe_mode` for sensitive modules). This completes what Strix only proposed (issue #46) with already-built plumbing.
3. **Extend the Fixer into a patch + verify loop.** Generate per-finding code patches (Strix `apply_patch` pattern) and wire `POST /api/findings/{id}/verify` into an automated re-test that re-runs the matching `exploitation/` module against the patched source/lab endpoint, auto-transitioning `verification_status` to `FIX_VERIFIED`/`ISSUE_STILL_PRESENT`. This is the direct path to PS's own "autofix PR" story.
4. **Add agent-level completion reports to the orchestrator.** Mirror Strix's `agent_finish` pattern: each of the 20+ PS agents returns a structured `{status, summary, findings, recommendations}` object that `orchestrator.persist_findings()` aggregates — improving the AI analyst's root-cause grouping (`services/ai_analyst.py`) with per-agent context it currently lacks.
5. **Surface a live agent-graph view.** Add an `agents` tree endpoint (parent/child + status + current phase from `orchestrator.publish()` events) and render it in the frontend dashboard — the highest-visibility parity win with Strix's viewer, built on telemetry PS already emits.

---

## Appendix A: PhantomScan Module Index (referenced above)

- **Agents** — `agents/orchestrator.py`, `scanner.py`, `shadow_recon.py`, `analyzer.py`, `cve_matcher.py`, `browser_security.py`, `security_assessment.py` (9 sub-agents), `pentest.py`, `exploitation/` (21 checkers), `ai_security_analyst.py`, `ai_explainer.py`, `hindi_explainer.py`, `fixer.py`, `notifier.py`, `dos.py`, `self_audit.py`, `sandbox_manager.py`
- **Services** — `active_security.py` (AttackSurfaceMapper, SecurityTestPlanner, score_findings), `ai_analyst.py` (RemediationPlanner), `authorized_runner.py`, `active_gate.py`, `openrouter_client.py`, `browser_observation.py`, `intelligence_service.py`
- **Routers** — `scan.py`, `findings.py`, `active.py`, `ai.py`, `dos.py`, `intelligence.py`, `execution.py`, `agents.py`, `authorization.py`, `websockets.py`
- **Models/DB** — `models.py` (Finding: severity/confidence/CVSS/CWE/verification/remediation), `database.py`
