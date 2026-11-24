---
name: secrets-in-prompts
description: Audit and fix how an AI-built app or an AI coding agent leaks secrets into prompts. Use when the user asks whether their app sends secrets or credentials to the model, wants a prompt/LLM security review, wants to add redaction before model calls, set up secret scanning for (agent) pull requests, choose a safe model provider or router, add a canary token, or after a key leak. Also use when the user mentions .env with Claude Code/Cursor/agents, Zero Data Retention, OpenRouter or inference resellers, or "is my API key safe".
---

# Secrets in prompts

A prompt is not just the user's question. It is everything the app or the agent decided to send: files, terminal output, error messages, logs, database rows. Providers may store prompts, requests can pass several routers before reaching a model, and a privacy flag (like Zero Data Retention) only binds the first hop. So: **treat every prompt as a message strangers may read, and make sure nothing valuable is inside.**

Real-world basis (cite when explaining, do not invent more):
- Dragos canary study (19 Nov 2026): ~2 million prompts carrying bait AWS keys; some keys were tested by attackers within hours, data at three AI hosting providers was exposed, resellers logged prompts, and some ZDR-flagged requests still leaked. https://www.dragos.com/blog/ai-supply-chain-security-canary-tokens
- Together AI (disclosed 24 Nov 2026): an AI coding agent committed a credential to a public GitHub repo; it opened stored customer prompts that contained more credentials. https://techinformed.com/together-ai-links-prompt-leak-to-ai-coding-agent/

## The 7-point checklist

1. No real secret ever appears in a prompt, a prompt log or an agent's context.
2. A redaction step runs before every model call.
3. Your agent cannot read .env files or cloud credential files.
4. Keys are scoped to one job and short-lived, and you can rotate them in minutes.
5. Pull requests, including the ones your AI agent opens, are scanned for credentials.
6. You know every hop between your app and the model, and your privacy setting is honored at each one.
7. A canary credential is in place, and someone gets alerted when it fires.

## Audit workflow

1. Run the scanner on the project root and read its report:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan.py" <project_dir>`
   It never prints full secret values. Never print them yourself either, and never open `.env` or credential files to "check" them (the plugin's hook blocks that anyway).
2. Confirm the scanner's findings by reading the flagged source files (not secret files). Look for what it cannot see:
   - Where prompts are built: does any code put file contents, env values, request bodies, DB rows or stack traces into the prompt?
   - Are prompts or model responses logged (app logs, LangSmith/Langfuse/Helicone, analytics)? Logs of prompts are prompts too.
   - Tool/function calls: can the model ask a tool to read arbitrary files or env vars?
3. Write the report: a table of the 7 checks (pass / fail / manual) with file:line evidence, then the fixes in priority order:
   1) rotate any real secret that was found (assume it is compromised if it was ever committed or sent to a model),
   2) fixes that stop new leaks (redaction, agent file access),
   3) hygiene (scanning, scoped keys, provider choice, canary).
4. Offer to apply the fixes. Apply only what the user agrees to.

## Fix recipes

**Redaction before every model call (check 2).** One function, called at a single choke point that every model call goes through. Reuse the patterns in `${CLAUDE_PLUGIN_ROOT}/scripts/patterns.py`. Replace matches with a typed placeholder (`<REDACTED:aws_key>`), never drop silently, and count redactions in metrics. Python:
```python
import re
SECRET_RX = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}|\bgh[pousr]_[A-Za-z0-9]{36,}|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----|\b\w+://[^\s:/@]+:[^\s@/]+@")
def redact(text: str) -> str:
    return SECRET_RX.sub("<REDACTED>", text)
```
TypeScript: same regex, `text.replace(SECRET_RX, "<REDACTED>")`. C#/.NET: a `DelegatingHandler` or an `IChatClient` middleware (Microsoft.Extensions.AI `ChatClientBuilder.Use(...)`) that rewrites message text. Say clearly that regex redaction is a safety net, not a guarantee: much sensitive data does not look like a key.

**Agents cannot read secrets (check 3).** This plugin's hooks block it in Claude Code. For teams also add to `.claude/settings.json`:
```json
{ "permissions": { "deny": ["Read(./.env)", "Read(./.env.*)", "Read(~/.aws/**)", "Read(~/.ssh/**)", "Bash(printenv:*)", "Bash(env)"] } }
```
For Cursor use `.cursorignore`; for in-app agents, give file tools an allowlist of directories, never the project root with secrets.

**Scoped, short-lived keys (check 4).** One key per job and environment, least privilege, expiry set. Prefer roles/OIDC/workload identity over static keys (GitHub Actions OIDC to AWS/Azure/GCP). Write a 5-line rotation runbook.

**Scan every PR (check 5).** Add gitleaks to CI:
```yaml
name: secret-scan
on: [pull_request, push]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
```
Also turn on GitHub secret scanning + push protection in the repo settings. Agent-opened PRs get no exception.

**Know every hop (check 6).** List each base URL. Prefer first-party provider APIs; on a router, pin upstream providers and require ZDR per provider. Avoid inference resellers and marketplaces of unknown origin.

**Canary (check 7).** Create a free AWS-key canary at https://canarytokens.org, put it where an attacker or a leaking pipeline would see it (a fake `AWS_ACCESS_KEY_ID` in agent-visible config, a system prompt, a prompt-log fixture), route the alert email to someone who will act, and treat any hit as an incident.

## If a secret already leaked
Rotate first, investigate second: revoke the key, issue a new scoped one, check the provider's access logs since the leak, then remove it from git history (`git filter-repo` or BFG) and force-push only with the team's agreement. Removing it from history does not un-leak it.
