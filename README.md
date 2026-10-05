# Scanner Detection Rules - Claude Cowork and Claude Code

Scanner detection rules for the OpenTelemetry logs emitted by Claude Cowork
and Claude Code, plus three rules for the Claude Compliance API activity feed.

The pack has two purposes:

1. **Everyday alerts you can use on their own.** Each rule catches one specific
   risky behavior: an unapproved MCP server, credential file access, a push to
   an unexpected git remote, and so on.
2. **A composite "would have caught it" alert.** It chains many weak signals
   into one critical alert, modeled on the July 2026 Hugging Face autonomous
   agent intrusion. Scanner's detection engine runs many rules in parallel
   without a performance penalty, so you can afford to watch for signals that
   aren't alarming on their own but, together, point to a swarm event. This
   composite is an example meant to inspire your own.

All rules ship with `enabled: Staging`. Watch them in `_detections` for a few
days, tune thresholds and fill in your own values, then switch them to
`Active`. Read [Before you enable](#before-you-enable-what-fails-out-of-the-box)
first: several rules match everything, or never fire, until they are
configured.

---

## Claude Cowork and Claude Code

Claude Cowork and Claude Code emit the same OpenTelemetry event structure
(`tool_decision`, `tool_result`, `api_request`, `plugin_loaded` and so on), so
**most rules work on both products unchanged**. A few rules read fields that
only one product records.

Every rule carries the tag `source.claude` and one or both product tags:

| Tag | Meaning | Rules |
|---|---|---|
| `product.claude_cowork` + `product.claude_code` | Works on both products | 32 |
| `product.claude_cowork` only | Reads Cowork-only fields, or the Claude Compliance API feed | 7 |
| `product.claude_code` only | Reads Claude Code-only fields (git branch and repository, file paths, MCP server names, the Bash sandbox flag) | 6 |

The product each rule applies to is also shown in the [All rules](#all-rules)
table. If you only run one product, you can disable the rules tagged only for
the other.

The rules do not filter by product. If you want to scope a rule to one
product, or tell the two apart while triaging, use
`resource.attributes.service.name`: it is `cowork` for Claude Cowork and
`claude-code` for Claude Code.

### Claude Code telemetry settings

Claude Code leaves some telemetry detail off by default. Set these for the
rules that need them:

| Setting | Needed by |
|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY=1` | Every rule (turns on OpenTelemetry export) |
| `OTEL_LOG_TOOL_DETAILS=1` | Any rule that reads commands or file paths (`tool_parameters`, `tool_input`), `Claude - Agent Committed to Protected Branch` (the branch is logged only with tool details), and MCP server names |
| `OTEL_METRICS_INCLUDE_REPOSITORY=true` | `Claude - Session in Unapproved Repository` (adds `vcs.owner.name` and `vcs.repository.name`) |

The git branch and repository fields need Claude Code v2.1.269 or later.
Without `OTEL_LOG_TOOL_DETAILS=1`, rules that match commands or file paths
cannot fire. The easiest way to set these for everyone is the `env` block of
Claude Code's managed settings.

---

## Alerts, signals and correlations

This pack has three kinds of rules. Knowing which is which is the key to using
it.

### Alerts

An **alert** is a normal detection rule. It has Medium, High or Critical
severity and an `event_sink_keys` entry, so when it fires someone gets
notified. It describes a behavior worth looking at on its own.

### Signals

A **signal** is a detection rule that never notifies anyone. It has
`Informational` severity, **no `event_sink_keys`**, the tag `signal`, and
`(Signal)` at the end of its name. When it fires, the result is written to
Scanner's built-in `_detections` index and nothing else happens.

Signals capture activity that is **usually innocent on its own**:

* a session that ran 50 tool calls in an hour,
* a user with three different sessions within an hour,
* a human reviewer who approved every command they saw,
* a shell command that used `curl`.

Paging on any one of these would bury your team in false positives. They
become interesting only when **several different ones pile up on the same
person** in a short time. Signals exist to be counted by a correlation rule.

### Correlations

A **correlation** rule queries the `_detections` index instead of your raw
logs. It counts how many *different* rules fired for the same user and alerts
when that count crosses a threshold. It needs no join. Each contributing rule
opts in with a tag (`correlation.<label>`) and names its user column the same
way (`entity_user_id` or `entity_email`):

```
@index={ 00000000-0000-0000-0000-000000000000 | "_detections" }
tags[*]:correlation.composite_critical
| stats countdistinct(name) as rule_count by results_table.rows[0].entity_user_id
| where rule_count >= 5
```

### Why some behaviors have both an alert and a signal

Several behaviors appear twice: once as an alert with a strict threshold, and
once as a signal with a looser one. For example:

| Rule | Threshold | Notifies? | Feeds the composite? |
|---|---|---|---|
| `Claude - High Tool Call Volume in Session` | 100 tool calls/hour | Yes (Medium) | No |
| `Claude - High Tool Call Volume in Session (Signal)` | 50 tool calls/hour | No | Yes |

The pairing lets you keep the standalone alert, which is useful day to day,
and still give the composite a more sensitive version of the same behavior.
**Only the signal sibling carries the composite tag.** The correlation counts
distinct rule names, so if both versions were tagged, one behavior would count
twice. Because the signal's threshold is lower, it always fires whenever the
alert does, so the composite never misses it.

A few strong alerts (for example `Claude - Credential File or Cloud Metadata
Access`) have no signal sibling. They notify on their own **and** are tagged
directly into the composite.

---

## The composite: Multi-Stage Agent Compromise

`Claude - Multi-Stage Agent Compromise (Critical Correlation)` fires when
**5 or more different contributing rules** hit the same `user.id` within a
rolling 24 hours. It is checked hourly and pages at most once a day per user.

It is modeled on the Hugging Face incident, where an autonomous agent ran for
days with no human review. It performed reconnaissance, harvested cloud and
Kubernetes credentials, enrolled devices into a mesh VPN, spawned a
self-respawning pod fleet, minted tokens and pushed to repositories. No single
action was damning, but the combination was. Each contributor maps to a stage
of that attack:

| Contributing rule | Kind | Products | Attack stage |
|---|---|---|---|
| `Claude - High Auto-Accept Ratio on High-Risk Tools (Signal)` | Signal | Both | No human in the loop |
| `Claude - Human Reviewer Approving Everything (Signal)` | Signal | Both | Review exists but isn't really reviewing |
| `Claude - High Tool Call Volume in Session (Signal)` | Signal | Both | Sustained machine-speed activity |
| `Claude - User Active Across Many Sessions (Signal)` | Signal | Both | Parallel sessions / fan-out |
| `Claude - Risky Bash Command Proposed (Signal)` | Signal | Both | Reconnaissance and tooling download |
| `Claude - Repeated Tool Execution Failures (Signal)` | Signal | Both | Probing restricted resources |
| `Claude - Repeated API Auth Failures (401/403) (Signal)` | Signal | Both | Credential misuse |
| `Claude - Same Bash Command Repeated in Session (Signal)` | Signal | Both | Device enrollment / pod fleet fan-out |
| `Claude - Repeated Calls to Unapproved Domain (Signal)` | Signal | Both | Command and control over public services |
| `Claude - Tool Call from Unapproved MCP Server` | Alert | Cowork | Shadow tooling |
| `Claude - Credential File or Cloud Metadata Access` | Alert | Both | Credential access |
| `Claude - Token Minting with Unapproved Git Push` | Alert | Both | Token minting and supply-chain compromise |
| `Claude - Repeated Escalation to bypassPermissions` | Alert | Cowork | Defense evasion |

**Adding your own rule to the composite.** Any rule can count toward this
alert if it does two things:

1. Include `correlation.composite_critical` in its `tags:` list. That tag is
   how the composite finds it.
2. End its query with `| rename(log.attributes.user.id as entity_user_id)`.
   The composite counts rules per user and expects the user in a column named
   `entity_user_id`.

The Claude Code rules already end with that `rename` line, so strong ones such
as `Claude - Read Tool Opened Credential File` or `Claude - Write to Sensitive
or Persistence Path` only need the tag. Adding a rule makes the composite more
sensitive, so you may want to raise its threshold from 5.

### Other correlations in this pack

| Correlation | Fires when | Contributors |
|---|---|---|
| `Claude - Agent Off the Rails (Correlation)` | 2+ of these alerts on the same user within an hour | `Claude - High Auto-Accept Ratio on High-Risk Tools`, `Claude - Repeated Tool Execution Failures`, `Claude - Tool Call from Unapproved MCP Server`, `Claude - Repeated API Auth Failures (401/403)` |
| `Claude - Unapproved IP with Risky Tool Use (Correlation)` | both signals on the same email within an hour | `Claude - Compliance API Activity from Unapproved IP (Signal)`, `Claude - Accepted High-Risk Tool Calls (Signal)` |
| `Claude - Role Change with Risky Tool Use (Correlation)` | both signals on the same email within an hour | `Claude - Accepted High-Risk Tool Calls (Signal)`, `Claude - Role or Permission Change (Signal)` |

---

## Before you enable: what fails out of the box

Read this before switching any rule from `Staging` to `Active`. Each affected
rule also starts its description with a **"Before you enable"** section.

**Matches everything until you fill in its placeholders.** Left as shipped,
these alert on normal activity:

* `Claude - Unapproved Model Used` (every API request)
* `Claude - Tool Call from Unapproved MCP Server` (every MCP tool call; this
  High alert also feeds `Agent Off the Rails` and the composite, so left
  unfilled it inflates both correlations)
* `Claude - Unapproved MCP Server Connected` (every MCP connection)
* `Claude - Session in Unapproved Repository` (every repository)
* `Claude - Unapproved Plugin Loaded` (every plugin load)
* `Claude - Repeated Calls to Unapproved Domain` and its (Signal) (every
  domain counts as unapproved)
* `Claude - Compliance API Activity from Unapproved IP (Signal)` (all activity)
* `Claude - Compliance API Accessed by Unapproved Actor` (every access)

**Never fires until configured:**

* `Claude - SSRF or Injection Marker in Tool Arguments` (no default markers)
* All four correlation rules, until you set your `_detections` index ID. They
  also need their contributing rules enabled and configured.

**Claude Code: never fires without telemetry settings** (see
[Claude Code telemetry settings](#claude-code-telemetry-settings)):

* Without `OTEL_LOG_TOOL_DETAILS=1`: every rule that reads commands or file
  paths. That is the Risky Bash, Git Push, Token Minting, Credential File,
  Same Bash Command, Unapproved Domain, SSRF Marker, Sandbox Disabled, Write
  to Sensitive Path, Read Credential File and Protected Branch rules.
* Without `OTEL_METRICS_INCLUDE_REPOSITORY=true`: `Claude - Session in
  Unapproved Repository`.

**Never fires without the Claude Compliance API activity feed:** the two
Compliance API signals, `Claude - Compliance API Accessed by Unapproved Actor`
and the two correlations built on them.

**Affected by redaction:** if your pipeline redacts `user.email`, the two
Compliance API correlations cannot match people; if it redacts `to_mode`,
`Claude - Repeated Escalation to bypassPermissions` never fires; if it redacts
plugin or marketplace names, `Claude - Unapproved Plugin Loaded` cannot tell
plugins apart.

**Works as shipped, but review the defaults:** approved git remotes (`origin`,
`upstream`), protected branches (`main`, `master`), the risky command list, the
token-minting regex and the credential and persistence path regexes. With
other remote names, for example, legitimate pushes fire as High alerts.

**Inline tests:** the tests use the shipped placeholders and defaults. When you
change a value in a query, update that rule's test events too, or
`scanner-cli run-tests` fails.

---

## Values you should supply

Many rules check activity against **your** allowlists: approved models, MCP
servers, git remotes, domains and so on. There is no universal default for
these, so the queries ship with **placeholders in angle brackets**, such as
`<approved-model-1>`. **A rule with an unfilled placeholder will either match
everything or never match.** Fill these in before you set a rule to `Active`.

Each rule's description also has a **"Values you should supply"** section with
the exact instructions.

| Rule | Placeholder in query | What to put there |
|---|---|---|
| `Claude - Unapproved Model Used` | `<approved-model-1>`, `<approved-model-2>` | Your approved Claude model IDs |
| `Claude - Tool Call from Unapproved MCP Server` | `<approved-mcp-server-uuid-1>`, `<approved-mcp-server-uuid-2>` | Cowork: UUIDs (not display names) of approved MCP servers |
| `Claude - Unapproved MCP Server Connected` | `<approved-mcp-server-1>`, `<approved-mcp-server-2>` | Claude Code: approved MCP server names as they appear in `server_name` |
| `Claude - Session in Unapproved Repository` | `<approved-org-1>`, `<approved-org-2>` | Your GitHub/GitLab organization names (repository owners) |
| `Claude - SSRF or Injection Marker in Tool Arguments` | `<marker-1>`, `<marker-2>` | SSRF/injection strings to catch. No default; the rule is inert until filled |
| `Claude - Unapproved Plugin Loaded` | `<approved-plugin-N>` + `<approved-marketplace-N>` | Approved plugin/marketplace pairs, one `not (...)` line per plugin |
| `Claude - Repeated Calls to Unapproved Domain` | `<approved-domain-1>\|<approved-domain-2>` | Approved outbound domains as a regex (escape dots). Also in the (Signal) sibling |
| `Claude - Compliance API Activity from Unapproved IP (Signal)` | `<approved-ip-1>`, `<approved-ip-2>` | Office egress, VPN and cloud workstation IPs (literal IPs, no CIDR) |
| `Claude - Compliance API Accessed by Unapproved Actor` | `<approved-compliance-user-1>`, `<approved-compliance-user-2>` | Emails of people and automation allowed to use the Compliance API |
| `Claude - Git Push to Unapproved Remote` | `origin`, `upstream` (pre-filled) | Your approved git remote alias names |
| `Claude - Token Minting with Unapproved Git Push` | Minting regex + `^(origin\|upstream)$` (pre-filled) | Commands your agents use to mint tokens; approved remote aliases |
| `Claude - Agent Committed to Protected Branch` | `main`, `master` (pre-filled) | Your protected branch names |
| `Claude - Write to Sensitive or Persistence Path` | Path regex (pre-filled) | Optional: add more persistence or config paths |
| `Claude - Read Tool Opened Credential File` | Path regex (pre-filled) | Optional: add credential paths, or drop `.env` if reading it is routine (`.env.example` and similar templates are already excluded) |
| `Claude - High Auto-Accept Ratio on High-Risk Tools` | `Bash`, `Write`, `Edit`, `NotebookEdit` (pre-filled) | High-risk tool list; also used by the (Signal) sibling, Human Reviewer Approving Everything and Accepted High-Risk Tool Calls (Signal) |
| `Claude - Risky Bash Command Proposed` | `curl`, `wget`, `base64`, `chmod` (pre-filled) | Risky command names for your environment. Also in the (Signal) sibling |
| `Claude - Credential File or Cloud Metadata Access` | Path/IP regex (pre-filled) | Optional: add more credential paths |
| All four correlation rules | `00000000-0000-0000-0000-000000000000` in the `@index=` line | Your tenant's `_detections` index ID. Tab-complete `@index=_detections` in the Scanner search box to get it |

Rows marked *(pre-filled)* work as shipped, but the defaults are generic. Review them for your environment. The correlations also inherit the values of the rules that feed them.

These lists drift. New Claude models and tools ship, and your MCP and repo
inventory changes. Review them periodically, not just at setup.

---

## Requirements

### Log source and field names

The rules expect the Claude Cowork and Claude Code OpenTelemetry log events
after Scanner has flattened them into dot-path fields, for example
`log.attributes.event.name`, `log.attributes.session.id`,
`log.attributes.tool_parameters`. If your ingestion pipeline flattens or
renames fields differently, adjust the queries to match.

The queries do not restrict themselves to one index. They select events by
`log.attributes.event.name`, which is selective enough. For lower query cost,
add `@index=<your index>` as the first line of each query.

Two signal rules and one alert read the **Claude Compliance API activity
feed** (`type`, `actor.*` fields), a separate source. If you don't ingest it,
leave those three rules disabled; the two correlations that depend on them will
simply never fire.

### Redacted fields

Some fields might be redacted for privacy reasons. Make sure your detections
don't rely on fields that are redacted in your environment.

### Thresholds are starting points

Every count and ratio threshold is an initial value, not tuned on production
data. Expect to adjust them after watching `_detections` in Staging.

---

## All rules

45 rules: 29 alerts, 12 signals, 4 correlations. Products: *Both* = Claude Cowork and Claude Code, *Cowork* = Claude Cowork only, *Code* = Claude Code only.

| Name | Kind | Severity | Products | Window / frequency | File |
|---|---|---|---|---|---|
| Claude - API Rate Limit Storm (429) | Alert | Medium | Both | 1h / 1h | [`api_rate_limit_storm.yml`](rules/api_rate_limit_storm.yml) |
| Claude - Agent Committed to Protected Branch | Alert | Medium | Code | 1h / 15m | [`agent_committed_to_protected_branch.yml`](rules/agent_committed_to_protected_branch.yml) |
| Claude - Auto-Accepted File Overwrite Tools | Alert | Medium | Both | 1h / 1h | [`auto_accepted_file_overwrite_tools.yml`](rules/auto_accepted_file_overwrite_tools.yml) |
| Claude - Bash Run with Sandbox Disabled | Alert | Medium | Code | 1h / 15m | [`bash_run_with_sandbox_disabled.yml`](rules/bash_run_with_sandbox_disabled.yml) |
| Claude - Compliance API Accessed by Unapproved Actor | Alert | High | Cowork | 1h / 1h | [`compliance_api_accessed_by_unapproved_actor.yml`](rules/compliance_api_accessed_by_unapproved_actor.yml) |
| Claude - Credential File or Cloud Metadata Access | Alert | High | Both | 1h / 15m | [`credential_file_or_cloud_metadata_access.yml`](rules/credential_file_or_cloud_metadata_access.yml) |
| Claude - Elevated Tool Rejection Rate | Alert | Medium | Both | 1h / 1h | [`elevated_tool_rejection_rate.yml`](rules/elevated_tool_rejection_rate.yml) |
| Claude - Git Push to Unapproved Remote | Alert | High | Both | 1h / 15m | [`git_push_to_unapproved_remote.yml`](rules/git_push_to_unapproved_remote.yml) |
| Claude - High Auto-Accept Ratio on High-Risk Tools | Alert | Medium | Both | 1h / 1h | [`high_auto_accept_ratio_on_high_risk_tools.yml`](rules/high_auto_accept_ratio_on_high_risk_tools.yml) |
| Claude - High Tool Call Volume in Session | Alert | Medium | Both | 1h / 1h | [`high_tool_call_volume_in_session.yml`](rules/high_tool_call_volume_in_session.yml) |
| Claude - Human Reviewer Approving Everything | Alert | Medium | Both | 1h / 1h | [`human_reviewer_approving_everything.yml`](rules/human_reviewer_approving_everything.yml) |
| Claude - Low-Activity User Running Risky Tools | Alert | Medium | Both | 1h / 1h | [`low_activity_user_running_risky_tools.yml`](rules/low_activity_user_running_risky_tools.yml) |
| Claude - Read Tool Opened Credential File | Alert | High | Code | 1h / 15m | [`read_tool_opened_credential_file.yml`](rules/read_tool_opened_credential_file.yml) |
| Claude - Repeated API Auth Failures (401/403) | Alert | Medium | Both | 1h / 1h | [`repeated_api_auth_failures.yml`](rules/repeated_api_auth_failures.yml) |
| Claude - Repeated Calls to Unapproved Domain | Alert | Medium | Both | 1h / 15m | [`repeated_calls_to_unapproved_domain.yml`](rules/repeated_calls_to_unapproved_domain.yml) |
| Claude - Repeated Deny-Rule Hits | Alert | Medium | Both | 1h / 15m | [`repeated_deny_rule_hits.yml`](rules/repeated_deny_rule_hits.yml) |
| Claude - Repeated Escalation to bypassPermissions | Alert | High | Cowork | 1h / 15m | [`repeated_escalation_to_bypass_permissions.yml`](rules/repeated_escalation_to_bypass_permissions.yml) |
| Claude - Repeated Tool Execution Failures | Alert | Medium | Both | 1h / 1h | [`repeated_tool_execution_failures.yml`](rules/repeated_tool_execution_failures.yml) |
| Claude - Risky Bash Command Proposed | Alert | Medium | Both | 1h / 15m | [`risky_bash_command_proposed.yml`](rules/risky_bash_command_proposed.yml) |
| Claude - SSRF or Injection Marker in Tool Arguments | Alert | High | Both | 1h / 15m | [`ssrf_or_injection_marker_in_tool_arguments.yml`](rules/ssrf_or_injection_marker_in_tool_arguments.yml) |
| Claude - Same Bash Command Repeated in Session | Alert | Medium | Both | 1h / 15m | [`same_bash_command_repeated_in_session.yml`](rules/same_bash_command_repeated_in_session.yml) |
| Claude - Session in Unapproved Repository | Alert | Medium | Code | 1h / 1h | [`session_in_unapproved_repository.yml`](rules/session_in_unapproved_repository.yml) |
| Claude - Token Minting with Unapproved Git Push | Alert | High | Both | 1h / 15m | [`token_minting_with_unapproved_git_push.yml`](rules/token_minting_with_unapproved_git_push.yml) |
| Claude - Tool Call from Unapproved MCP Server | Alert | High | Cowork | 1h / 15m | [`tool_call_from_unapproved_mcp_server.yml`](rules/tool_call_from_unapproved_mcp_server.yml) |
| Claude - Unapproved MCP Server Connected | Alert | Medium | Code | 1h / 15m | [`unapproved_mcp_server_connected.yml`](rules/unapproved_mcp_server_connected.yml) |
| Claude - Unapproved Model Used | Alert | Medium | Both | 5m / 5m | [`unapproved_model_used.yml`](rules/unapproved_model_used.yml) |
| Claude - Unapproved Plugin Loaded | Alert | Medium | Both | 1h / 1h | [`unapproved_plugin_loaded.yml`](rules/unapproved_plugin_loaded.yml) |
| Claude - User Active Across Many Sessions | Alert | Medium | Both | 1h / 1h | [`user_active_across_many_sessions.yml`](rules/user_active_across_many_sessions.yml) |
| Claude - Write to Sensitive or Persistence Path | Alert | High | Code | 1h / 15m | [`write_to_sensitive_or_persistence_path.yml`](rules/write_to_sensitive_or_persistence_path.yml) |
| Claude - Accepted High-Risk Tool Calls (Signal) | Signal | Informational | Both | 1h / 1h | [`accepted_high_risk_tool_calls_signal.yml`](rules/accepted_high_risk_tool_calls_signal.yml) |
| Claude - Compliance API Activity from Unapproved IP (Signal) | Signal | Informational | Cowork | 1h / 1h | [`compliance_api_activity_from_unapproved_ip_signal.yml`](rules/compliance_api_activity_from_unapproved_ip_signal.yml) |
| Claude - High Auto-Accept Ratio on High-Risk Tools (Signal) | Signal | Informational | Both | 1h / 1h | [`high_auto_accept_ratio_on_high_risk_tools_signal.yml`](rules/high_auto_accept_ratio_on_high_risk_tools_signal.yml) |
| Claude - High Tool Call Volume in Session (Signal) | Signal | Informational | Both | 1h / 1h | [`high_tool_call_volume_in_session_signal.yml`](rules/high_tool_call_volume_in_session_signal.yml) |
| Claude - Human Reviewer Approving Everything (Signal) | Signal | Informational | Both | 1h / 1h | [`human_reviewer_approving_everything_signal.yml`](rules/human_reviewer_approving_everything_signal.yml) |
| Claude - Repeated API Auth Failures (401/403) (Signal) | Signal | Informational | Both | 1h / 1h | [`repeated_api_auth_failures_signal.yml`](rules/repeated_api_auth_failures_signal.yml) |
| Claude - Repeated Calls to Unapproved Domain (Signal) | Signal | Informational | Both | 1h / 15m | [`repeated_calls_to_unapproved_domain_signal.yml`](rules/repeated_calls_to_unapproved_domain_signal.yml) |
| Claude - Repeated Tool Execution Failures (Signal) | Signal | Informational | Both | 1h / 1h | [`repeated_tool_execution_failures_signal.yml`](rules/repeated_tool_execution_failures_signal.yml) |
| Claude - Risky Bash Command Proposed (Signal) | Signal | Informational | Both | 1h / 15m | [`risky_bash_command_proposed_signal.yml`](rules/risky_bash_command_proposed_signal.yml) |
| Claude - Role or Permission Change (Signal) | Signal | Informational | Cowork | 1h / 1h | [`role_or_permission_change_signal.yml`](rules/role_or_permission_change_signal.yml) |
| Claude - Same Bash Command Repeated in Session (Signal) | Signal | Informational | Both | 1h / 15m | [`same_bash_command_repeated_in_session_signal.yml`](rules/same_bash_command_repeated_in_session_signal.yml) |
| Claude - User Active Across Many Sessions (Signal) | Signal | Informational | Both | 1h / 1h | [`user_active_across_many_sessions_signal.yml`](rules/user_active_across_many_sessions_signal.yml) |
| Claude - Agent Off the Rails (Correlation) | Correlation | High | Both | 1h / 1h | [`agent_off_the_rails_correlation.yml`](rules/agent_off_the_rails_correlation.yml) |
| Claude - Multi-Stage Agent Compromise (Critical Correlation) | Correlation | Critical | Both | 24h / 1h | [`multi_stage_agent_compromise_critical_correlation.yml`](rules/multi_stage_agent_compromise_critical_correlation.yml) |
| Claude - Role Change with Risky Tool Use (Correlation) | Correlation | High | Cowork | 1h / 1h | [`role_change_with_risky_tool_use_correlation.yml`](rules/role_change_with_risky_tool_use_correlation.yml) |
| Claude - Unapproved IP with Risky Tool Use (Correlation) | Correlation | High | Cowork | 1h / 1h | [`unapproved_ip_with_risky_tool_use_correlation.yml`](rules/unapproved_ip_with_risky_tool_use_correlation.yml) |

---

## Deployment

Follow **Detection Rules as Code** in the [Scanner documentation](https://docs.scanner.dev):
connect this repository with the Scanner GitHub app, which validates rules on
every push to `main` and syncs them to your Scanner instance.

The included GitHub Actions workflow (`.github/workflows/validate-rules.yml`)
validates rules on pull requests. It needs the `SCANNER_RULE_VALIDATION_API_URL`
and `SCANNER_RULE_VALIDATION_API_KEY` repository secrets.

To validate and test locally:

```
pip install scanner-cli
export SCANNER_API_URL=... SCANNER_API_KEY=...
scanner-cli validate -d rules -r
scanner-cli run-tests -d rules -r
```

Every rule has inline `tests:` with events that should fire and events that
should not. The tests use the shipped placeholder and default values (for
example `<approved-model-1>`, or `origin` and `upstream` as approved git
remotes). When you replace those values in a query, update the matching test
events too, or `run-tests` will fail.

### Event sinks

Alerts are routed by severity to these event sink keys:
`medium_severity_alerts`, `high_severity_alerts`, `critical_severity_alerts`.
Signals have no event sink by design.
