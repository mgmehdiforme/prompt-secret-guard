# prompt-secret-guard

**Keep your secrets out of LLM prompts.** A Claude Code plugin that stops your AI coding agent from reading `.env` and credential files, blocks API keys pasted into prompts, refuses to hardcode keys in code, and audits your AI app against a 7-point checklist.

## Why

A prompt is not just your question. It is everything your app or agent decided to send: files, terminal output, error messages, logs. Providers can store prompts, requests can pass through several routers, and a "Zero Data Retention" flag only binds the first hop.

- **Dragos canary study (19 Nov 2026).** Dragos sent about 2 million prompts carrying bait AWS keys. Attackers tested some of the keys within hours. Data at three AI hosting providers was exposed, and some resellers logged prompts. [Source](https://www.dragos.com/blog/ai-supply-chain-security-canary-tokens)
- **Together AI (24 Nov 2026).** An AI coding agent pushed a credential to public GitHub. The credential opened stored customer prompts, and those prompts held more credentials. [Source](https://techinformed.com/together-ai-links-prompt-leak-to-ai-coding-agent/)

## What's inside

| Part | What it does |
|---|---|
| **Hooks** (on by default) | `UserPromptSubmit`: blocks a prompt that contains a real key. `PreToolUse`: stops the agent from reading `.env*`, SSH, AWS, GCP, Azure, Docker and Kube credentials, from running `printenv` / `echo $API_KEY` / `aws configure export-credentials`, and from writing a hardcoded key into code. `PostToolUse`: if a secret shows up in a tool result, tells the agent not to repeat, log or commit it. |
| **Agent** `prompt-leak-auditor` | A read-only security auditor. It traces what goes into every model call, checks prompt logging, git history and providers, and returns a 7-point report with file:line evidence. |
| **Skill** `secrets-in-prompts` | The checklist, the audit method, and fix recipes for redaction (Python, TS, .NET), deny rules, gitleaks CI, scoped keys, safe providers and canary tokens. |
| `/prompt-leak-check` | Scans the project and proposes fixes. |
| `/add-redaction` | Adds one redaction step in front of every model call, with a test. |
| `scripts/scan.py` | A standalone scanner using only the standard library. It masks values and exits with 1 on critical findings, so you can use it in CI. |

### The 7-point checklist
1. No real secret ever appears in a prompt, a prompt log or an agent's context.
2. A redaction step runs before every model call.
3. Your agent cannot read .env files or cloud credential files.
4. Keys are scoped to one job and short-lived, and you can rotate them in minutes.
5. Pull requests, including the ones your AI agent opens, are scanned for credentials.
6. You know every hop between your app and the model, and your privacy setting is honored at each one.
7. A canary credential is in place, and someone gets alerted when it fires.

## Install

In Claude Code:
```
/plugin marketplace add mgmehdiforme/prompt-secret-guard
/plugin install prompt-secret-guard@prompt-secret-guard
```
It needs `python3` (3.8 or later) and nothing else.

## Use
- The hooks work on their own as soon as the plugin is installed.
- Run `/prompt-leak-check` in any project, or ask "audit this app for secrets in prompts" and the auditor agent takes it.
- Scan without Claude, for example in CI: `python3 scripts/scan.py path/to/project`

## Settings
- `PROMPT_GUARD_MODE=block` (default) | `ask` (you approve each case) | `off`
- `.promptguardignore` in your project root: one glob per line for files the guard should allow, such as `fixtures/*.pem`.

## Limits
Regex catches known key formats only. Passwords, personal data and customer data often don't look like keys. This plugin is a safety net, not a guarantee. Rotate any key that was ever committed or sent to a model.

## Tests
```
python3 tests/test_guard.py
```

---
Built by **Mehdi Golzari**, from the *Vibe Code Rescue* series. I take AI-built apps from prototype to production. MIT licensed.
