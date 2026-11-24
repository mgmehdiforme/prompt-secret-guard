---
description: Add a secret-redaction step in front of every model call in this app
allowed-tools: Read, Grep, Glob, Edit, Write, Bash(python3:*)
---

Use the `secrets-in-prompts` skill, section "Redaction before every model call".

1. Find every place the app calls a model (OpenAI, Anthropic, Vercel AI SDK, LangChain, Semantic Kernel, Microsoft.Extensions.AI, Gemini...).
2. Propose ONE choke point all calls go through (a wrapper, middleware or DelegatingHandler) and show the plan before editing.
3. After the user agrees: add the redact function in the app's language, route all calls through it, and add a small unit test that proves an `AKIA…` key and a `sk-…` key are replaced.
4. Tell the user what regex redaction does not catch.
