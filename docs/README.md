# SILENTCHAIN Community Documentation

SILENTCHAIN Community is a Jython-based Burp Suite extension that provides AI-powered security analysis of HTTP traffic. It passively analyzes proxied requests and responses, identifying OWASP Top 10 vulnerabilities using configurable AI providers.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Quick start guide for first-time setup |
| [Installation](installation.md) | Detailed prerequisites and installation steps |
| [Configuration](configuration.md) | Config file reference and settings |
| [Usage](usage.md) | Scanning workflow, findings, and export |
| [Architecture](architecture.md) | Internal design and code structure |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |

## Overview

- **Type:** Burp Suite Extension (passive scanner)
- **Language:** Python 2.7 (Jython)
- **AI Providers:** Ollama, OpenAI, Claude, Gemini, ClaudeCode (local CLI)
- **Coverage:** OWASP Top 10 vulnerability categories

## Quick Start

1. Install Jython 2.7.4 standalone JAR
2. Configure Jython in Burp > Extender > Options > Python Environment
3. Load `silentchain_ai_community.py` in Burp > Extender > Extensions
4. Configure your AI provider in the SILENTCHAIN tab
5. Proxy traffic through Burp and review findings
