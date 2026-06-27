# API Reference — SILENTCHAIN AI Community Edition

SILENTCHAIN Community is a Burp Suite extension — it does not expose a standalone HTTP API. All interaction happens through Burp Suite's interfaces.

---

## Burp Suite Java Interfaces

The extension implements these Burp Suite interfaces, accessible programmatically via Burp's Extender API:

### IBurpExtender

- `registerExtenderCallbacks(callbacks)` — Entry point. Registers all listeners, UI tabs, and context menus.

### IHttpListener

- `processHttpMessage(toolFlag, messageIsRequest, messageInfo)` — Intercepts HTTP traffic. Only processes responses (`messageIsRequest=False`) that are in scope and pass the static file filter.

### IScannerCheck

- `doPassiveScan(baseRequestResponse)` — Called by Burp's scanner. Returns `IScanIssue` list with AI-generated findings.
- `doActiveScan(baseRequestResponse, insertionPoint)` — Not implemented (Community is passive-only).

### ITab

- `getTabCaption()` — Returns `"SILENTCHAIN AI"`.
- `getUiComponent()` — Returns the main Swing panel with settings, findings table, and controls.

### IContextMenuFactory

- `createMenuItems(invocation)` — Adds right-click menu items: "Analyze with SILENTCHAIN AI", "Analyze Selected Text".

---

## AI Provider APIs

The extension communicates with one configured AI provider:

| Provider | Endpoint | Auth |
|----------|----------|------|
| Ollama | `POST {api_url}/api/generate` | None |
| OpenAI | `POST {api_url}/v1/chat/completions` | `Authorization: Bearer {key}` |
| Claude | `POST {api_url}/v1/messages` | `x-api-key: {key}` |
| Gemini | `POST {api_url}/v1beta/models/{model}:generateContent` | `?key={key}` |
| ClaudeCode | Local CLI: `claude -p` | None (uses local auth) |

All AI requests use the same structured prompt format requesting JSON output with OWASP classification, severity, confidence, and remediation details.

The **ClaudeCode** provider invokes the locally installed `claude` CLI via subprocess rather than making HTTP requests. No API key or URL configuration is needed — the CLI handles authentication independently.
