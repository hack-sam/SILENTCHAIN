# Architecture

## Overview

SILENTCHAIN AI Community Edition is a single-file Jython Burp Suite extension (~94KB). It implements several Burp interfaces to intercept HTTP traffic, analyze it with AI, and report findings as Burp Scanner Issues.

## Component Diagram

```
Burp Suite
  |
  v
BurpExtender (single .py file)
  |
  +-- IHttpListener ------> Intercepts proxy traffic
  +-- IScannerCheck -------> Passive scan integration
  +-- ITab ----------------> SILENTCHAIN UI tab
  +-- IContextMenuFactory -> Right-click "Analyze" menu
  |
  v
AI Analysis Thread Pool (background)
  |
  +-- DataSanitizer (redacts sensitive data before cloud AI calls)
  +-- Deduplication (SHA256 hash check)
  +-- AI Provider (urllib2 HTTP calls or local CLI)
  |     +-- Ollama API
  |     +-- OpenAI API
  |     +-- Claude API
  |     +-- Gemini API
  |     +-- Azure Foundry API
  |     +-- ClaudeCode (local `claude` CLI)
  +-- RAG Bridge (optional, urllib2 → localhost:8000/retrieve + /feedback)
  +-- Response Parser (structured finding extraction)
  |
  v
Finding Registration
  +-- IScanIssue (Burp Scanner Issue)
  +-- JTable model update (SILENTCHAIN tab)
  +-- Persistent vulnerability cache (JSON serialization)
```

## Data Flow

1. HTTP request/response passes through Burp's proxy.
2. `IHttpListener.processHttpMessage()` captures the traffic.
3. Deduplication check: SHA256(URL + parameters). Skip if already analyzed.
4. DataSanitizer redacts sensitive data (API keys, credentials, PII) from the prompt (if enabled).
5. Background thread sends request/response data to the configured AI provider.
6. AI returns structured analysis with vulnerability type, severity, confidence, and description.
7. DataSanitizer restores original values in the AI response (replaces `[REDACTED_*]` placeholders).
8. Finding is registered as a Burp Scanner Issue and added to the SILENTCHAIN tab.

## Key Design Decisions

- **Single file:** Burp's Jython extension loader requires a single .py file entry point. All code lives in one file to simplify loading.
- **No external packages:** Only Jython stdlib and Burp API imports are used. `urllib2` handles all HTTP communication.
- **Thread pool:** Configurable thread pool for parallel AI analysis requests. Keeps the Swing EDT responsive while processing multiple requests concurrently.
- **Java Swing UI:** All GUI components use `javax.swing` since that is what Burp's extension API provides.
- **Persistent cache:** Findings are serialized to JSON and survive extension reload / Burp restart. The cache is keyed by SHA256(URL + parameters) for deduplication.
- **CSV export:** Findings can be exported to CSV directly from the extension UI.
- **RAG integration:** Optional HTTP bridge to the RAG Security Knowledge Engine at `localhost:8000` via `urllib2`. Sends `/retrieve` queries for context enrichment during analysis and `/feedback` calls for verified findings.
