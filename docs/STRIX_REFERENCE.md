# Strix Codebase Reference

Reference document for the open-source Strix AI penetration testing tool, produced for PhantomScan feature-mapping purposes.

| | |
|---|---|
| **Repository** | https://github.com/usestrix/strix |
| **Analyzed commit** | `657aa5cbe687485135d1049450e36f296edb106d` (2026-08-04) |
| **License** | Apache-2.0 |
| **Language** | Python (CLI), TypeScript/React (local web viewer) |
| **Docs** | https://docs.strix.ai |
| **Companion doc** | `docs/STRIX_MAPPING.md` (Strix → PhantomScan mapping) |

> **TL;DR** — Strix is an LLM-driven pentest orchestration framework. A *root agent* decomposes a scan target and dynamically spawns specialized *subagents* (each a sandboxed LLM session with a curated toolset and skill knowledge packages) that work in parallel, share findings, and report back. All state lives in a single `AgentCoordinator` (agent tree, statuses, mailboxes, resume snapshots). "Strix" the scanner = root agent + subagents + skills + tools running inside a Docker sandbox.

---

## 1. Repository Layout

```
strix/
├── agents/            # Agent construction: factory, system-prompt renderer (Jinja)
│   └── prompts/system_prompt.jinja
├── config/            # Settings, LLM provider config, scan modes
├── core/              # Orchestration engine
│   ├── agents.py      #   AgentCoordinator — graph state, mailboxes, snapshots
│   ├── runner.py      #   run_strix_scan() — scan lifecycle (start/resume/teardown)
│   ├── execution.py   #   Agent run loops, child spawning, respawn on resume
│   ├── hooks.py       #   Usage/budget hooks (max turns, $ budget)
│   ├── inputs.py      #   Root task + scope context construction
│   ├── sessions.py    #   Per-agent SQLite SDK sessions
│   └── paths.py       #   Run directory layout
├── interface/         # TUI (Bubble Tea) + local web viewer (React, "strix view")
├── llm/               # LLM provider plumbing
├── report/            # Vulnerability report state, SARIF export
├── runtime/           # Sandbox session manager, status sink
├── skills/            # 59 markdown knowledge packages in 10 categories
├── tools/             # 16+ agent tool implementations
└── utils/             # Resource paths, output truncation helpers
```

Supporting directories: `containers/` (sandbox Docker images), `benchmarks/`, `tests/`, `scripts/`.

---

## 2. Agent Architecture (Graph-Based Workflow)

Strix is built on the OpenAI **Agents SDK** (`agents` package) with a custom orchestration layer. Agents are not static classes — they are constructed at runtime with per-agent tools, skills, and prompts.

### 2.1 `AgentCoordinator` (`strix/core/agents.py`)

The single owner of all multi-agent graph state. It is an in-memory registry + message bus with crash-safe JSON snapshots.

**Agent tree state:**
- `parent_of: agent_id → parent_id` — the graph is a **tree** rooted at the root agent (`parent=None`). Every agent has exactly one parent.
- `statuses: agent_id → Status` where `Status = running | waiting | completed | stopped | crashed | failed | budget_paused`
- `names`, `metadata` (task string, assigned skills), `errors`, `recovery_counts`

**Messaging (mailboxes):**
- Each agent has an `AgentRuntime` with a `mailbox` (list of messages) and an `asyncio.Event` wake signal.
- `send(target, message)` queues a message, wakes the target, and can **interrupt an in-flight turn** (`stream.cancel(mode="immediate")`) so the next run cycle sees it.
- `wait_for_message()` / `consume_pending()` drain mailboxes into the agent's SDK session.
- Incoming messages are persisted to the recipient's session as `[Message from <name> | type=... | priority=...]` user-context items.

**Wait semantics:** `WaitKind = user | agents | stalled` records *why* an agent parked, so the driver knows whether a parked agent will resume on its own (waiting on agents is re-checked on a timer) or needs user input.

**Fault tolerance:**
- `recovery_counts` — a turn that ends without a lifecycle tool call is a "recovery"; repeated nudges are capped so a stuck agent cannot burn unlimited turns.
- `idle_resume_counts` — caps auto-resume loops for agents that park again after every resume.
- `claim_parent_notice()` — a child owes its parent exactly one completion notice; whichever of `agent_finish`/terminal notice arrives first wins.

**Persistence / resume:**
- `snapshot()` serializes the full graph (statuses, tree, mailboxes, errors, budget flags) to `runtime/agents.json` on every mutation (atomic temp-file replace).
- `restore()` reconstructs it; per-agent conversation history lives in a separate SQLite DB (`agents.db`) via `open_agent_session()`. `strix --resume <scan-id>` replays both.
- New instructions on resume are injected as a fresh high-priority user message to the root session.

**Budget control:** scan-wide USD budget + max-turns enforcement via `ReportUsageHooks` (`strix/core/hooks.py`). States: `budget_stopped` (hard stop, wakes all parked agents to exit), `reserve_stopped`, `budget_paused` (interactive; user can extend). `pause_for_budget()`/`resume_from_budget_pause()` park/resume the whole tree.

### 2.2 Agent construction (`strix/agents/factory.py`)

`build_strix_agent()` builds a `SandboxAgent` (SDK agent bound to a Docker sandbox session):

| Aspect | Root agent | Child (sub)agent |
|---|---|---|
| Lifecycle tool | `finish_scan` (ends whole scan) | `agent_finish` (reports to parent, ends itself) |
| Interactive tool | `respond_to_user` (+ `wait_for_agents` parking) | same |
| Base toolset | full base set | full base set |
| Prompt | orchestration directive (`is_root=True`) | hands-on specialist directive |
| Skills | caller-specified + `coordination/root_agent` | caller-specified (max 5 via `create_agent`) |

Tools are shared module-level `FunctionTool`/`CustomTool` objects; each agent gets a bound copy wrapped for:
- **Output bounding** — tool results truncated to configured line/byte caps, spilled to the sandbox workspace when oversized (`strix/tools/output_store.py`).
- **Argument coercion** — JSON ↔ string schema coercion, custom tools (`apply_patch` etc.) exposed as raw-string "input" payloads for chat-completions backends.
- **Error-as-result** — tool exceptions are returned to the model as tool results (recoverable), except lifecycle errors.

Every agent has `Filesystem` + `Shell` capabilities (sandbox `exec_command`, file reads/writes, `apply_patch`).

### 2.3 System prompt rendering (`strix/agents/prompt.py` + `system_prompt.jinja`)

Prompt is a Jinja template composed at build time:
1. **Scope block** — system-verified authorized targets injected from `system_prompt_context` (authoritative; instructions cannot expand scope).
2. **Role block** — root agents get a hard "orchestrate, don't hands-on test" directive; children get the specialist methodology.
3. **Skills** — resolved skill markdown bodies are injected as template variables (`get_skill` global, each skill also a top-level variable).
4. **Communication rules** — interactive vs autonomous behavior contracts (e.g., autonomous mode: *almost every turn MUST be a tool call*; text-only turns never end a run).

### 2.4 Run loop (`strix/core/runner.py`, `strix/core/execution.py`)

`run_strix_scan()` lifecycle: create/reuse sandbox session → build root agent → register in coordinator → `run_agent_loop()` → teardown. Child agents are spawned mid-run by the root agent via the `create_agent` tool, which calls `spawn_child_agent()` (runner-supplied closure) → `execution.spawn_child_agent()`: opens a fresh SDK session, attaches runtime, launches an `asyncio.Task` running its own loop. Children run **concurrently** with the parent. On resume, `respawn_subagents()` recreates every surviving child's runtime and re-attaches sessions.

---

## 3. Skill System

### 3.1 Structure (`strix/skills/`)

59 markdown files organized as `<category>/<name>.md`, loaded via a YAML-frontmatter parser:

```markdown
---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, and ORM bypass techniques
---
# SQL Injection
## Attack Surface ... ## Detection Channels ... ## DBMS Primitives ...
```

| Category | Purpose | Examples |
|---|---|---|
| `vulnerabilities/` | Per-vuln-class testing playbooks | `sql_injection`, `xss`, `ssrf`, `idor`, `race_conditions`, `rce`, `xxe`, `ssti`, `jwt`, `http_request_smuggling`, `prototype_pollution`, `business_logic`, … (25 skills) |
| `frameworks/` | Framework-specific methods | `django`, `fastapi`, `nestjs`, `nextjs` |
| `technologies/` | Third-party services | `active_directory`, `auth0`, `firebase_firestore`, `supabase`, `grafana_prometheus` |
| `protocols/` | Protocol patterns | `graphql`, `oauth` |
| `tooling/` | Sandbox CLI playbooks | `nmap`, `nuclei`, `httpx`, `ffuf`, `katana`, `naabu`, `subfinder`, `sqlmap`, `semgrep`, `python`, `agent_browser` |
| `cloud/` | Cloud provider testing | `aws`, `gcp`, `kubernetes` |
| `reconnaissance/` | OSINT/enumeration | `asset_discovery` |
| `custom/` | Community skills, SAST/SCA | `source_aware_sast`, `dependency_cve_scanning`, `api_spec_testing` |
| `coordination/` (internal) | Orchestration playbooks | `root_agent`, `source_aware_whitebox` |
| `scan_modes/` (internal) | Per-mode methodology | `quick`, `standard`, `deep` |

### 3.2 Loading & injection

- **Static (prompt-time):** `prompt._resolve_skills()` computes the ordered skill list — caller-requested skills, then always `scan_modes/<mode>`, `tooling/agent_browser`, `tooling/python`, plus `coordination/root_agent` (root only) and white-box skills when source is available. Bodies are inlined into the rendered system prompt (see 2.3).
- **Dynamic (runtime):** the `load_skill` tool fetches skill markdown inline as a tool result — reference material without a permanent prompt change.
- **Cap:** max 5 skills per agent (validated by `validate_requested_skills`), recommended 1–3.
- **Extensibility:** `register_skill_dir()` mounts custom skill roots; user directories shadow built-ins.
- Internal categories (`scan_modes`, `coordination`) are not user-selectable.

A typical skill body contains: attack surface enumeration, detection channels (error/boolean/time/OAST-based), payload primitives per technology, validation steps to avoid false positives, and chaining guidance.

---

## 4. Multi-Agent Orchestration Pattern

Strix's pattern: **root agent = planner/coordinator; subagents = parallel specialists**. The root is explicitly forbidden from hands-on testing — everything is delegated.

### 4.1 Graph tools (`strix/tools/agents_graph/tools.py`)

| Tool | Function |
|---|---|
| `create_agent(name, task, inherit_context=True, skills=[...])` | Spawn a specialist child (max 5 skills; child runs in its own `asyncio.Task`/SDK session). `inherit_context=True` seeds the child with the parent's turn history as background. |
| `view_agent_graph()` | Print the whole agent tree with statuses (used to avoid duplicate specialists). |
| `send_message_to_agent(target, message, type, priority)` | Inter-agent messaging; wakes target, can interrupt its turn. `type: query/instruction/information`, `priority: low→urgent`. |
| `wait_for_agents(reason, timeout)` | Park until a message arrives (parent typically uses it after spawning, to collect completion reports). |
| `agent_finish(result_summary, findings, success, report_to_parent)` | Child termination: marks `completed`, posts a structured completion report to the parent's inbox (findings must already be filed via reporting tools). |
| `stop_agent(target, cascade=True)` | Graceful stop (current turn finishes first); cascades leaves-first. |
| `finish_scan(...)` | Root termination; writes the executive report, marks `scan_completed`. |

### 4.2 Coordination mechanics

- **Shared sandbox workspace** — all agents share one Docker sandbox + Caido proxy history (recon artifacts, captured requests, notes files).
- **Shared notes & todos** (`strix/tools/notes/`, `strix/tools/todo/`) — persisted to disk (`runtime/notes.json`, `runtime/todos.json`), hydrated on resume, usable by every agent.
- **Vulnerability reporting** — findings are filed centrally via `create_vulnerability_report` / `create_dependency_report` (see §7), not kept in agent memory.
- **Completion reports** — `agent_finish` renders a structured text report (status/summary/findings/recommendations) delivered to the parent's inbox; the parent aggregates them.
- **Parent-child context inheritance** — children get parent turn history as background (one-way; siblings don't see each other).

### 4.3 Deep-mode decomposition strategy (from `skills/scan_modes/deep.md`)

After recon, decompose hierarchically: component level (auth, payments, admin) → feature level (login, password reset) → vulnerability level (SQLi agent, XSS agent). "Do NOT overload a single agent with multiple vulnerability types… creates a massive parallel swarm." This is the canonical guidance that drives spawn behavior.

### 4.4 White-box (source-aware) orchestration

When a target is a local code repo (`is_whitebox=True`): the coordination skill `source_aware_whitebox` + `custom/source_aware_sast` steer agents to run `semgrep`/AST structural search/`gitleaks`/`trivy fs` triage first, store artifacts, then validate top candidates dynamically. Skills gate the exact tool calls.

---

## 5. Target Complexity Index (TCI) & ScanPlanner

**Status: NOT IMPLEMENTED in the OSS repo.** TCI and ScanPlanner exist only as an open enhancement proposal: **GitHub issue #46** — *"feat(agent): add Target Complexity Index (TCI) + adaptive ScanPlanner for dynamic vulnerability scanning"* (open, 0 comments, Oct 2025).

### 5.1 Proposal summary

- **Goal:** replace static checklist execution with tactical, prioritized scanning driven by target fingerprinting — reduce wasted tests, token cost, and false positives.
- **TCI (0..100)** — computed from a target fingerprint: open ports, protocols, auth patterns, API surface size, front-end technologies, WAF/CDN presence, data sensitivity, patch posture.
- **ScanPlanner** — maps TCI → structured scan plan: priority tiers, ordered steps, module selection, `safe_mode` flags, timeouts, quotas.
- **Proposed component boundaries:**
  - `strix/core/tci.py` — TCI calculation, configurable weights
  - `strix/agents/planner.py` — plan generation from TCI
  - `strix/modules/registry.py` — modules accept priority metadata, quotas, `safe_mode` hints
- **Payload example:**

```json
{
  "target": "https://api.example.local",
  "fingerprint": { "...": "metadata" },
  "tci": 78.3,
  "plan": [
    {"step": 1, "module": "auth-enum", "priority": "high", "safe_mode": true},
    {"step": 2, "module": "id_or", "priority": "high", "safe_mode": true},
    {"step": 3, "module": "sqli-fuzz", "priority": "medium", "safe_mode": true}
  ]
}
```

### 5.2 What exists today instead

- Scan modes (`quick`/`standard`/`deep`) select the *methodology skill* injected into prompts — a coarse, static form of planning.
- The root agent's prompt itself instructs it to "read scope/config, decompose the target… track todos/notes/coverage, decide next steps" — i.e., planning is delegated to the LLM at runtime rather than computed.

> **Note for PhantomScan:** PhantomScan already implements a working equivalent of this proposal — see `docs/STRIX_MAPPING.md` §3 (`AttackSurfaceMapper` + `SecurityTestPlanner` + `passive_plan_score`).

---

## 6. Auto-Fix & PR Generation Flow

### 6.1 In the OSS repo

1. **Finding filing** — agents call `create_vulnerability_report` (fields: title, severity, CVSS vector/score via `_calculate_cvss`, CWE, code locations with file/line, description, remediation) or `create_dependency_report` (advisory CVEs). Reports are validated, deduped, and written to report state (`strix/report/`), exportable as SARIF.
2. **Fix loop** — the fixing agent edits code in the sandbox using the `apply_patch` tool (SDK `ApplyPatchTool`, surfaced to the model as `patch`) plus `exec_command` (tests) and the filesystem tools; re-runs validation; updates findings via `create_vulnerability_report` metadata.
3. **Reporting tools** — `list_reports` / `get_report` let any agent (esp. the root) query the central finding store for aggregation into the final report.

### 6.2 PR generation — platform-only

The actual "one-click autofix → ready-to-merge **pull request**" flow is a **Strix Platform (cloud)** feature (`app.strix.ai`): AI-generated security patches presented as PRs against connected repos (GitHub/GitLab/Bitbucket). The OSS CLI stops at: patched files in the sandbox + reports on disk. CI/CD usage is supported via `--scan-mode quick` and `--scope-mode diff` (PR-diff-scoped scans), but PR creation itself is not in the OSS code.

---

## 7. Agent Tool Registry

| Tool | Purpose |
|---|---|
| `think` | Private reasoning notes (kept out of report) |
| `load_skill` | Inline skill reference material (max 5) |
| `create_todo/list_todos/update_todo/mark_todo_done/mark_todo_pending/delete_todo` | Shared task tracking |
| `create_note/list_notes/get_note/update_note/delete_note` | Shared persistent notes |
| `web_search` | OSINT during recon |
| `create_vulnerability_report` | File a validated finding (CVSS, CWE, locations, remediation) |
| `create_dependency_report` | File a known-CVE dependency finding |
| `list_reports` / `get_report` | Query central finding store |
| `list_requests/view_request/repeat_request/list_sitemap/view_sitemap_entry/scope_rules` | Caido proxy interrogation (shared proxy history) |
| `view_agent_graph` / `send_message_to_agent` / `wait_for_agents` / `create_agent` / `stop_agent` | Multi-agent graph control |
| `agent_finish` / `finish_scan` | Lifecycle termination (child / root) |
| `respond_to_user` | Interactive mode: deliver message + park |
| `exec_command`, `write_stdin`, filesystem ops, `patch` (apply_patch) | Sandbox shell/filesystem (SDK capabilities) |
| `view_image` | Screenshot review from the agent browser |

Extensibility: `register_agent_tools()` adds tools to every subsequently built agent (root + children).

---

## 8. Scan Modes

| Mode | Duration | Purpose | Prompt effect |
|---|---|---|---|
| `quick` | ~5–15 min | CI/CD, PR validation | `skills/scan_modes/quick.md` — surface checks, common patterns |
| `standard` | 30–60 min | Routine reviews | `standard.md` — balanced coverage |
| `deep` (default) | 1–4 h | Pre-release, bug bounty | `deep.md` — exhaustive recon → logic deep-dive → full attack surface → **vulnerability chaining** → persistent testing |

Mode selection also influences `STRIX_REASONING_EFFORT` (medium for quick, high otherwise). White-box targets switch `is_whitebox` on, which adds source-aware skills. `--scope-mode diff` scopes quick scans to a PR diff against a base branch.

---

## 9. Run Artifacts & Viewer

- Every run writes to `strix_runs/<run-name>/`: `runtime/agents.json` (coordinator snapshot), `runtime/agents.db` (per-agent SDK sessions), `runtime/notes.json`, `runtime/todos.json`, reports, logs.
- `strix view [run-name]` starts a local web viewer (React, bound to `127.0.0.1`, tokened link): overview + severity breakdown, vulnerability list with reproduction steps, **live agent graph**, steering (send instructions to a live scan from the browser), run history, shareable reports.
- Headless mode (`-n`): prints real-time findings + final report, exits non-zero when vulnerabilities are found (CI-friendly).

---

## 10. Source File Index (key files)

| File | Role |
|---|---|
| `strix/core/agents.py` | `AgentCoordinator` — graph state, mailboxes, snapshots |
| `strix/core/runner.py` | `run_strix_scan()` lifecycle |
| `strix/core/execution.py` | `run_agent_loop`, `spawn_child_agent`, `respawn_subagents` |
| `strix/core/hooks.py` | Budget/turns enforcement |
| `strix/core/inputs.py` | Root task + scope context |
| `strix/agents/factory.py` | `build_strix_agent`, tool wrapping, child factory |
| `strix/agents/prompt.py` | Jinja prompt renderer + skill resolution |
| `strix/agents/prompts/system_prompt.jinja` | Base system prompt template |
| `strix/tools/agents_graph/tools.py` | Multi-agent graph tools |
| `strix/tools/reporting/tool.py` | Finding/report tools (CVSS, CWE, dedupe) |
| `strix/tools/load_skill/tool.py` | Dynamic skill loading |
| `strix/skills/__init__.py` | Skill discovery, parsing, validation |
| `docs/usage/scan-modes.mdx` | Scan mode docs |
| `strix/interface/viewer/` | Local web viewer (React) |
