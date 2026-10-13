# Offline pipeline acceptance

`tests/acceptance/test_pipeline.py` runs the full alert pipeline offline, in-process, with no network, no auth, and no GitHub writes.

## Scope

The flow runs through the real components at each boundary:

1. Ingress: `create_app` receives the alert over HTTP with a test token.
2. Queue: a normalized ServiceBus-style fake holds the message.
3. Worker: real `IncidentProcessor` and `IncidentRepository` on an in-memory `EntityStore`.
4. Investigation: real `CopilotInvestigator` with a fake `ModelBackend` and fake collector.
5. Publication: real `McpPublisher` with a fake GitHub MCP `SessionFactory`. Tool schemas come from the official `ToolResponse` and schema fixtures.

The report renderer and the reconciler run as part of this flow.

## Scenarios

| Test | What it checks |
| --- | --- |
| Fired, lost create response, reconcile, Resolved, lost recovery response, redelivery | One investigation, one issue create, one comment, never closed, fixed repo, secrets sanitized, trusted Sev with no model assignment. Issue headings, evidence markers, and body within the UTF-8 limit. |
| Resolved before Fired | The early Resolved is held, then handled as one incident. |
| Test sink | Investigation runs but never touches GitHub (`TEST_SINK_SUPPRESSED`). |
| Enqueue failure | Ingress returns 503 and leaves no state. |
| Unknown scope | Ingress returns 400 before anything is queued. |

## Running

```bash
.venv/bin/pytest tests/acceptance -q -p no:cacheprovider
```

## Limits

- Offline only. Nothing here contacts Azure, GitHub, or Copilot.
- The fake GitHub server and the model backend emulate the real interfaces. They do not prove live behavior.
- Live acceptance gates are separate and are not covered by this suite.
