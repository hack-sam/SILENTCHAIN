# Troubleshooting

## Jython Not Found

**Symptom:** Burp Suite shows "Python environment not configured" or cannot load Python extensions.

**Solution:**
1. Download the Jython **standalone** JAR (not the installer)
2. Go to Extender > Options > Python Environment
3. Set the JAR path to the standalone file (e.g., `/opt/jython/jython-standalone-2.7.4.jar`)
4. Restart Burp Suite

## Extension Fails to Load

**Symptom:** Error output when adding the extension, extension does not appear in the Extensions list.

**Solution:**
- Check the Extender > Extensions > Errors tab for details
- Ensure you selected "Python" as the extension type (not Java or Ruby)
- Verify the `.py` file path is correct and readable
- Try reloading Burp Suite and loading the extension again

## AI Connection Errors

**Symptom:** "Connection refused" or timeout errors in the extension output.

**Solutions by provider:**

### Ollama
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if not running
ollama serve

# Verify the model is pulled
ollama list
```

### Cloud Providers (OpenAI, Claude, Gemini)
- Verify your API key is correct and not expired
- Check the API URL matches the provider's current endpoint
- Ensure your network allows outbound HTTPS connections
- Check for rate limiting (wait and retry)

## ClaudeCode Provider Not Working

**Symptom:** Selecting "ClaudeCode" as the provider results in errors or no analysis.

**Solutions:**
- Verify the `claude` CLI is installed: run `claude --version` in a terminal
- Ensure you have authenticated the CLI: run `claude` and complete the login flow
- Check that the `claude` binary is on the system PATH visible to Burp Suite's Java process
- If Burp was launched from a desktop shortcut, PATH may differ from your terminal — try launching Burp from the terminal instead

## No Findings Generated

**Symptom:** Traffic flows through Burp but no findings appear in the SILENTCHAIN tab.

**Solutions:**
- Verify the AI provider is connected (check for errors in the output tab)
- Lower the `confidence_threshold` to `Tentative` to see all findings
- Ensure `dedup` is not filtering out previously seen patterns
- Check that the target application returns meaningful HTTP responses (not just redirects)
- Try a different AI model -- smaller models may miss subtle vulnerabilities

## Slow Analysis

**Symptom:** Findings take a long time to appear, Burp Suite feels sluggish.

**Solutions:**
- Use a smaller, faster model (e.g., `llama3.1:8b` instead of larger models)
- For local Ollama, ensure your GPU is being utilized (`nvidia-smi`)
- Increase the `timeout` setting if the model needs more time
- Reduce the `max_tokens` setting to get shorter responses
## Memory Issues

**Symptom:** Burp Suite runs out of memory or becomes unresponsive during extended scans.

**Solutions:**
- Increase Burp Suite's heap size: edit the startup script or use `-Xmx4g` flag
- Enable deduplication to reduce the number of AI calls
- Clear the findings list periodically during long sessions
- Restart Burp Suite if memory usage grows too high

