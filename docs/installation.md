# Installation

## Prerequisites

- **Burp Suite** Professional or Community Edition (2023.x or later recommended)
- **Jython** 2.7.x standalone JAR ([download](https://www.jython.org/download))
- **AI Provider** — at least one of:
  - Ollama running locally (default, no API key needed)
  - OpenAI API key
  - Anthropic (Claude) API key
  - Google (Gemini) API key
  - [Claude Code](https://claude.ai/code) CLI — requires:
    1. Install Claude Code: `npm install -g @anthropic-ai/claude-code`
    2. Run `claude` once to authenticate (opens browser for Anthropic login)
    3. Verify: `claude --version` should print a version number
    4. The `claude` binary must be on your system `PATH`

## Step 1: Configure Jython in Burp Suite

1. Download the Jython standalone JAR.
2. In Burp Suite: **Extender > Options > Python Environment**.
3. Set the path to the Jython JAR file.
4. Restart Burp Suite.

## Step 2: Load the Extension

1. In Burp Suite: **Extender > Extensions > Add**.
2. Set **Extension type** to **Python**.
3. Browse to `silentchain_ai_community.py` and click **Next**.
4. The extension loads and a **SILENTCHAIN** tab appears.

## Step 3: Configure AI Provider

1. Click the **SILENTCHAIN** tab.
2. Open **Settings** (gear icon or Settings button).
3. Select your AI provider (Ollama is default).
4. Set the API URL:
   - Ollama: `http://localhost:11434` (default)
   - OpenAI: `https://api.openai.com`
   - Claude: `https://api.anthropic.com`
   - Gemini: `https://generativelanguage.googleapis.com`
   - ClaudeCode: no URL needed (uses local `claude` CLI)
5. Enter your API key (not required for Ollama or ClaudeCode).
6. Select the model name.
7. Click **Save**.

## Updating

To update the extension:
1. Download the new version of `silentchain_ai_community.py`.
2. In Burp Suite: uncheck the extension to unload it.
3. Replace the file on disk.
4. Re-check the extension to reload.

## Troubleshooting

- **Extension fails to load:** Verify Jython JAR path is set correctly in Burp's Python Environment settings.
- **No findings generated:** Ensure your target is in Burp's scope and proxy traffic is flowing.
- **AI timeout errors:** Check that your AI provider is reachable (try `curl http://localhost:11434/api/tags` for Ollama).
