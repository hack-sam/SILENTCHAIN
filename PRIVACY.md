# SILENTCHAIN Community Privacy Notice

**Effective Date:** June 18, 2026
**Applies to:** SILENTCHAIN Community (Burp Suite extension)

For the full privacy policy, visit: https://silentchain.ai/privacy.html

---

## 1. Local-First Architecture

SILENTCHAIN Community runs entirely inside your local Burp Suite instance. Sn1perSecurity LLC does **not** receive, store, or have access to:

- Target URLs, domains, or IP addresses you scan
- HTTP requests, responses, or traffic content
- Vulnerability findings or scan results
- Any files on your system

The extension performs no telemetry, analytics, or "phone-home" of any kind. SILENTCHAIN Community is unlicensed and does not contact Sn1perSecurity servers.

---

## 2. AI Provider Data Transmission (Important)

**When you configure a cloud-based AI provider, portions of the HTTP traffic intercepted by Burp Suite are transmitted to that provider's API for analysis.** This is the primary data flow you should be aware of.

### What data is sent to AI providers

- HTTP request and response content (URLs, headers, parameters, body) for the in-scope traffic the extension analyzes
- Vulnerability finding metadata (severity, CWE, parameter names)

This data is sent to **whichever AI provider you select**. If you select a cloud provider, that traffic leaves your machine.

### AI providers and data residency

| Provider | Data Destination | Data Leaves Your Machine? |
|----------|-----------------|---------------------------|
| **Ollama** | Local machine | **No** - fully local processing |
| **OpenAI** | OpenAI API servers | **Yes** - subject to [OpenAI Privacy Policy](https://openai.com/policies/privacy-policy) |
| **Anthropic (Claude)** | Anthropic API servers | **Yes** - subject to [Anthropic Privacy Policy](https://www.anthropic.com/privacy) |
| **Google (Gemini)** | Google API servers | **Yes** - subject to [Google Gemini API Terms](https://ai.google.dev/gemini-api/terms) |
| **Azure Foundry** | Microsoft Azure servers | **Yes** - subject to [Microsoft Privacy Statement](https://www.microsoft.com/privacy/privacystatement) and your Azure agreement |

### Your responsibility

Sn1perSecurity does not control how third-party AI providers process, store, or retain data sent to their APIs, and the provider's own terms of service and data processing agreements apply to that data. **If your scan targets contain sensitive information** (PII, PHI, customer data, credentials, proprietary data), you must:

1. Evaluate whether transmitting that traffic to a third-party AI provider complies with your organization's data protection policies and applicable regulations (GDPR, CCPA, HIPAA, contractual obligations).
2. Review and accept the third-party AI provider's terms of service and data processing agreements, including any terms related to training on submitted data.
3. **Use Ollama as your AI provider if data must not leave your machine.**

### Data sanitization

SILENTCHAIN Community applies a `DataSanitizer` layer before transmitting data to cloud AI providers. It performs bidirectional redaction: sensitive values (e.g., authorization headers with bearer tokens, API keys, common secret patterns) are replaced with `[REDACTED_*]` placeholders before the request is sent, then restored in the response. Sanitization is skipped entirely for Ollama, since that data never leaves your machine.

This redaction is **best-effort**. It relies on pattern and heuristic matching and does **not** guarantee removal of all sensitive data from HTTP traffic. Treat any cloud AI provider as receiving the unredacted portions of the traffic you submit.

---

## 3. RAG Knowledge Engine (Optional)

If you enable the optional RAG Security Knowledge Engine bridge:

- The RAG engine runs locally within your infrastructure (typically as a Docker container at `localhost:8000`).
- Knowledge base data and any findings ingested for correlation remain local.
- **If RAG is configured to use a cloud AI provider for enrichment, the same data transmission disclosures in Section 2 apply.**

---

## 4. Your Rights

You may request access to, correction of, or deletion of any personal data held by Sn1perSecurity by contacting **privacy@silentchain.ai**. We respond within 30 days.

- **GDPR (EEA/UK):** Right to access, rectification, erasure, restriction, portability, objection, and withdrawal of consent.
- **CCPA (California):** Right to know, delete, opt out of sale (we do not sell personal information), and non-discrimination.

---

## 5. Contact

Sn1perSecurity LLC
Email: privacy@silentchain.ai
Website: https://silentchain.ai
Full Privacy Policy: https://silentchain.ai/privacy.html
