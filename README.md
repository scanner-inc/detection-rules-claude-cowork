# Scanner Detection Rules - Claude Cowork

Scanner detection rules for the OpenTelemetry logs emitted by Claude Cowork,
plus three rules for the Claude Compliance API activity feed.

Claude Code emits similarly named events, but these rules have not been
validated against Claude Code logs.

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
`Active`.

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
@index=_detections
tags[*]:correlation.composite_critical
| stats countdistinct(name) as rule_count by results_table.rows[0].entity_user_id
| where rule_count >= 5
```

### Why some behaviors have both an alert and a signal

Several behaviors appear twice: once as an alert with a strict threshold, and
once as a signal with a looser one. For example:

| Rule | Threshold | Notifies? | Feeds the composite? |
|---|---|---|---|
| `Claude Cowork - High Tool Call Volume in Session` | 100 tool calls/hour | Yes (Medium) | No |
| `Claude Cowork - High Tool Call Volume in Session (Signal)` | 50 tool calls/hour | No | Yes |

The pairing lets you keep the standalone alert, which is useful day to day,
and still give the composite a more sensitive version of the same behavior.
**Only the signal sibling carries the composite tag.** The correlation counts
distinct rule names, so if both versions were tagged, one behavior would count
twice. Because the signal's threshold is lower, it always fires whenever the
alert does, so the composite never misses it.

A few strong alerts (for example `Claude Cowork - Credential File or Cloud
Metadata Access`) have no signal sibling. They notify on their own **and** are
tagged directly into the composite.

---

## The composite: Multi-Stage Agent Compromise

`Claude Cowork - Multi-Stage Agent Compromise (Critical Correlation)` fires
when **5 or more different contributing rules** hit the same `user.id` within a
rolling 24 hours. It is checked hourly and pages at most once a day per user.

It is modeled on the Hugging Face incident, where an autonomous agent ran for
days with no human review. It performed reconnaissance, harvested cloud and
Kubernetes credentials, enrolled devices into a mesh VPN, spawned a
self-respawning pod fleet, minted tokens and pushed to repositories. No single
action was damning, but the combination was. Each contributor maps to a stage
of that attack:

| Contributing rule | Kind | Attack stage |
|---|---|---|
| `Claude Cowork - High Auto-Accept Ratio on High-Risk Tools (Signal)` | Signal | No human in the loop |
| `Claude Cowork - Human Reviewer Approving Everything (Signal)` | Signal | Review exists but isn't really reviewing |
| `Claude Cowork - High Tool Call Volume in Session (Signal)` | Signal | Sustained machine-speed activity |
| `Claude Cowork - User Active Across Many Sessions (Signal)` | Signal | Parallel sessions / fan-out |
| `Claude Cowork - Risky Bash Command Proposed (Signal)` | Signal | Reconnaissance and tooling download |
| `Claude Cowork - Repeated Tool Execution Failures (Signal)` | Signal | Probing restricted resources |
| `Claude Cowork - Repeated API Auth Failures (401/403) (Signal)` | Signal | Credential misuse |
| `Claude Cowork - Same Bash Command Repeated in Session (Signal)` | Signal | Device enrollment / pod fleet fan-out |
| `Claude Cowork - Repeated Calls to Unapproved Domain (Signal)` | Signal | Command and control over public services |
| `Claude Cowork - Tool Call from Unapproved MCP Server` | Alert | Shadow tooling |
| `Claude Cowork - Credential File or Cloud Metadata Access` | Alert | Credential access |
| `Claude Cowork - Token Minting with Unapproved Git Push` | Alert | Token minting and supply-chain compromise |
| `Claude Cowork - Repeated Escalation to bypassPermissions` | Alert | Defense evasion |

**Adding your own rule to the composite.** Any rule can count toward this
alert if it does two things:

1. Include `correlation.composite_critical` in its `tags:` list. That tag is
   how the composite finds it.
2. End its query with `| rename(log.attributes.user.id as entity_user_id)`.
   The composite counts rules per user and expects the user in a column named
   `entity_user_id`.

Adding a rule this way makes the composite more sensitive, so you may want to
raise its threshold from 5.

### Other correlations in this pack

| Correlation | Fires when | Contributors |
|---|---|---|
| `Claude Cowork - Agent Off the Rails (Correlation)` | 2+ of these alerts on the same user within an hour | `Claude Cowork - High Auto-Accept Ratio on High-Risk Tools`, `Claude Cowork - Repeated Tool Execution Failures`, `Claude Cowork - Tool Call from Unapproved MCP Server`, `Claude Cowork - Repeated API Auth Failures (401/403)` |
| `Claude Cowork - Unapproved IP with Risky Tool Use (Correlation)` | both signals on the same email within an hour | `Claude Cowork - Compliance API Activity from Unapproved IP (Signal)`, `Claude Cowork - Accepted High-Risk Tool Calls (Signal)` |
| `Claude Cowork - Role Change with Risky Tool Use (Correlation)` | both signals on the same email within an hour | `Claude Cowork - Accepted High-Risk Tool Calls (Signal)`, `Claude Cowork - Role or Permission Change (Signal)` |

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
| `Claude Cowork - Unapproved Model Used` | `<approved-model-1>`, `<approved-model-2>` | Your approved Claude model IDs |
| `Claude Cowork - Tool Call from Unapproved MCP Server` | `<approved-mcp-server-uuid-1>`, `<approved-mcp-server-uuid-2>` | UUIDs (not display names) of approved MCP servers |
| `Claude Cowork - SSRF or Injection Marker in Tool Arguments` | `<marker-1>`, `<marker-2>` | SSRF/injection strings to catch. No default; the rule is inert until filled |
| `Claude Cowork - Unapproved Plugin Loaded` | `<approved-plugin-N>` + `<approved-marketplace-N>` | Approved plugin/marketplace pairs, one `not (...)` line per plugin |
| `Claude Cowork - Repeated Calls to Unapproved Domain` | `<approved-domain-1>\|<approved-domain-2>` | Approved outbound domains as a regex (escape dots). Also in the (Signal) sibling |
| `Claude Cowork - Compliance API Activity from Unapproved IP (Signal)` | `<approved-ip-1>`, `<approved-ip-2>` | Office egress, VPN and cloud workstation IPs (literal IPs, no CIDR) |
| `Claude Cowork - Compliance API Accessed by Unapproved Actor` | `<approved-compliance-user-1>`, `<approved-compliance-user-2>` | Emails of people and automation allowed to use the Compliance API |
| `Claude Cowork - Git Push to Unapproved Remote` | `origin`, `upstream` (pre-filled) | Your approved git remote alias names |
| `Claude Cowork - Token Minting with Unapproved Git Push` | Minting regex + `origin\|upstream` (pre-filled) | Commands your agents use to mint tokens; approved remote aliases |
| `Claude Cowork - High Auto-Accept Ratio on High-Risk Tools` | `Bash`, `Write`, `Edit`, `NotebookEdit` (pre-filled) | High-risk tool list; also used by the (Signal) sibling, Human Reviewer Approving Everything and Accepted High-Risk Tool Calls (Signal) |
| `Claude Cowork - Risky Bash Command Proposed` | `curl`, `wget`, `base64`, `chmod` (pre-filled) | Risky command names for your environment. Also in the (Signal) sibling |
| `Claude Cowork - Credential File or Cloud Metadata Access` | Path/IP list (pre-filled) | Optional: add more credential paths |

Rows marked *(pre-filled)* work as shipped, but the defaults are generic. Review them for your environment. The three correlations and the composite inherit the values of the rules that feed them.

These lists drift. New Claude models and tools ship, and your MCP and repo
inventory changes. Review them periodically, not just at setup.

---

## Requirements

### Log source and field names

The Cowork rules expect the OpenTelemetry log events after Scanner
has flattened them into dot-path fields, for example
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

38 rules: 22 alerts, 12 signals, 4 correlations.

| Name | Kind | Severity | Window / frequency | File |
|---|---|---|---|---|
| Claude Cowork - API Rate Limit Storm (429) | Alert | Medium | 1h / 1h | [`api_rate_limit_storm.yml`](rules/api_rate_limit_storm.yml) |
| Claude Cowork - Auto-Accepted File Overwrite Tools | Alert | Medium | 1h / 1h | [`auto_accepted_file_overwrite_tools.yml`](rules/auto_accepted_file_overwrite_tools.yml) |
| Claude Cowork - Compliance API Accessed by Unapproved Actor | Alert | High | 1h / 1h | [`compliance_api_accessed_by_unapproved_actor.yml`](rules/compliance_api_accessed_by_unapproved_actor.yml) |
| Claude Cowork - Credential File or Cloud Metadata Access | Alert | High | 1h / 15m | [`credential_file_or_cloud_metadata_access.yml`](rules/credential_file_or_cloud_metadata_access.yml) |
| Claude Cowork - Elevated Tool Rejection Rate | Alert | Medium | 1h / 1h | [`elevated_tool_rejection_rate.yml`](rules/elevated_tool_rejection_rate.yml) |
| Claude Cowork - Git Push to Unapproved Remote | Alert | High | 1h / 15m | [`git_push_to_unapproved_remote.yml`](rules/git_push_to_unapproved_remote.yml) |
| Claude Cowork - High Auto-Accept Ratio on High-Risk Tools | Alert | Medium | 1h / 1h | [`high_auto_accept_ratio_on_high_risk_tools.yml`](rules/high_auto_accept_ratio_on_high_risk_tools.yml) |
| Claude Cowork - High Tool Call Volume in Session | Alert | Medium | 1h / 1h | [`high_tool_call_volume_in_session.yml`](rules/high_tool_call_volume_in_session.yml) |
| Claude Cowork - Human Reviewer Approving Everything | Alert | Medium | 1h / 1h | [`human_reviewer_approving_everything.yml`](rules/human_reviewer_approving_everything.yml) |
| Claude Cowork - Low-Activity User Running Risky Tools | Alert | Medium | 1h / 1h | [`low_activity_user_running_risky_tools.yml`](rules/low_activity_user_running_risky_tools.yml) |
| Claude Cowork - Repeated API Auth Failures (401/403) | Alert | Medium | 1h / 1h | [`repeated_api_auth_failures.yml`](rules/repeated_api_auth_failures.yml) |
| Claude Cowork - Repeated Calls to Unapproved Domain | Alert | Medium | 1h / 15m | [`repeated_calls_to_unapproved_domain.yml`](rules/repeated_calls_to_unapproved_domain.yml) |
| Claude Cowork - Repeated Escalation to bypassPermissions | Alert | High | 1h / 15m | [`repeated_escalation_to_bypass_permissions.yml`](rules/repeated_escalation_to_bypass_permissions.yml) |
| Claude Cowork - Repeated Tool Execution Failures | Alert | Medium | 1h / 1h | [`repeated_tool_execution_failures.yml`](rules/repeated_tool_execution_failures.yml) |
| Claude Cowork - Risky Bash Command Proposed | Alert | Medium | 1h / 15m | [`risky_bash_command_proposed.yml`](rules/risky_bash_command_proposed.yml) |
| Claude Cowork - SSRF or Injection Marker in Tool Arguments | Alert | High | 1h / 15m | [`ssrf_or_injection_marker_in_tool_arguments.yml`](rules/ssrf_or_injection_marker_in_tool_arguments.yml) |
| Claude Cowork - Same Bash Command Repeated in Session | Alert | Medium | 1h / 15m | [`same_bash_command_repeated_in_session.yml`](rules/same_bash_command_repeated_in_session.yml) |
| Claude Cowork - Token Minting with Unapproved Git Push | Alert | High | 1h / 15m | [`token_minting_with_unapproved_git_push.yml`](rules/token_minting_with_unapproved_git_push.yml) |
| Claude Cowork - Tool Call from Unapproved MCP Server | Alert | High | 1h / 15m | [`tool_call_from_unapproved_mcp_server.yml`](rules/tool_call_from_unapproved_mcp_server.yml) |
| Claude Cowork - Unapproved Model Used | Alert | Medium | 5m / 5m | [`unapproved_model_used.yml`](rules/unapproved_model_used.yml) |
| Claude Cowork - Unapproved Plugin Loaded | Alert | Medium | 1h / 1h | [`unapproved_plugin_loaded.yml`](rules/unapproved_plugin_loaded.yml) |
| Claude Cowork - User Active Across Many Sessions | Alert | Medium | 1h / 1h | [`user_active_across_many_sessions.yml`](rules/user_active_across_many_sessions.yml) |
| Claude Cowork - Accepted High-Risk Tool Calls (Signal) | Signal | Informational | 1h / 1h | [`accepted_high_risk_tool_calls_signal.yml`](rules/accepted_high_risk_tool_calls_signal.yml) |
| Claude Cowork - Compliance API Activity from Unapproved IP (Signal) | Signal | Informational | 1h / 1h | [`compliance_api_activity_from_unapproved_ip_signal.yml`](rules/compliance_api_activity_from_unapproved_ip_signal.yml) |
| Claude Cowork - High Auto-Accept Ratio on High-Risk Tools (Signal) | Signal | Informational | 1h / 1h | [`high_auto_accept_ratio_on_high_risk_tools_signal.yml`](rules/high_auto_accept_ratio_on_high_risk_tools_signal.yml) |
| Claude Cowork - High Tool Call Volume in Session (Signal) | Signal | Informational | 1h / 1h | [`high_tool_call_volume_in_session_signal.yml`](rules/high_tool_call_volume_in_session_signal.yml) |
| Claude Cowork - Human Reviewer Approving Everything (Signal) | Signal | Informational | 1h / 1h | [`human_reviewer_approving_everything_signal.yml`](rules/human_reviewer_approving_everything_signal.yml) |
| Claude Cowork - Repeated API Auth Failures (401/403) (Signal) | Signal | Informational | 1h / 1h | [`repeated_api_auth_failures_signal.yml`](rules/repeated_api_auth_failures_signal.yml) |
| Claude Cowork - Repeated Calls to Unapproved Domain (Signal) | Signal | Informational | 1h / 15m | [`repeated_calls_to_unapproved_domain_signal.yml`](rules/repeated_calls_to_unapproved_domain_signal.yml) |
| Claude Cowork - Repeated Tool Execution Failures (Signal) | Signal | Informational | 1h / 1h | [`repeated_tool_execution_failures_signal.yml`](rules/repeated_tool_execution_failures_signal.yml) |
| Claude Cowork - Risky Bash Command Proposed (Signal) | Signal | Informational | 1h / 15m | [`risky_bash_command_proposed_signal.yml`](rules/risky_bash_command_proposed_signal.yml) |
| Claude Cowork - Role or Permission Change (Signal) | Signal | Informational | 1h / 1h | [`role_or_permission_change_signal.yml`](rules/role_or_permission_change_signal.yml) |
| Claude Cowork - Same Bash Command Repeated in Session (Signal) | Signal | Informational | 1h / 15m | [`same_bash_command_repeated_in_session_signal.yml`](rules/same_bash_command_repeated_in_session_signal.yml) |
| Claude Cowork - User Active Across Many Sessions (Signal) | Signal | Informational | 1h / 1h | [`user_active_across_many_sessions_signal.yml`](rules/user_active_across_many_sessions_signal.yml) |
| Claude Cowork - Agent Off the Rails (Correlation) | Correlation | High | 1h / 1h | [`agent_off_the_rails_correlation.yml`](rules/agent_off_the_rails_correlation.yml) |
| Claude Cowork - Multi-Stage Agent Compromise (Critical Correlation) | Correlation | Critical | 24h / 1h | [`multi_stage_agent_compromise_critical_correlation.yml`](rules/multi_stage_agent_compromise_critical_correlation.yml) |
| Claude Cowork - Role Change with Risky Tool Use (Correlation) | Correlation | High | 1h / 1h | [`role_change_with_risky_tool_use_correlation.yml`](rules/role_change_with_risky_tool_use_correlation.yml) |
| Claude Cowork - Unapproved IP with Risky Tool Use (Correlation) | Correlation | High | 1h / 1h | [`unapproved_ip_with_risky_tool_use_correlation.yml`](rules/unapproved_ip_with_risky_tool_use_correlation.yml) |

---

## Deployment

Follow **Detection Rules as Code** in the [Scanner documentation](https://docs.scanner.dev):
connect this repository with the Scanner GitHub app, which validates rules on
every push to `main` and syncs them to your Scanner instance.

The included GitHub Actions workflow (`.github/workflows/validate-rules.yml`)
validates rules on pull requests. It needs the `SCANNER_RULE_VALIDATION_API_URL`
and `SCANNER_RULE_VALIDATION_API_KEY` repository secrets.

To validate locally:

```
pip install scanner-cli
export SCANNER_API_URL=... SCANNER_API_KEY=...
for f in rules/*.yml; do scanner-cli validate -f "$f"; done
```

### Event sinks

Alerts are routed by severity to these event sink keys:
`medium_severity_alerts`, `high_severity_alerts`, `critical_severity_alerts`.
Signals have no event sink by design.
