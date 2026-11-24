---
description: Scan this project against the 7-point secrets-in-prompts checklist and propose fixes
argument-hint: "[project folder, default: current]"
allowed-tools: Bash(python3:*), Read, Grep, Glob
---

Use the `secrets-in-prompts` skill.

1. Run: `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan.py" ${ARGUMENTS:-.}`
2. Verify the findings by reading the flagged source files (never secret files, never print secret values).
3. Report the 7 checks as a table (status + file:line evidence), then the fixes in priority order: rotate real secrets, stop new leaks, hygiene.
4. Ask which fixes to apply. Do not change code before the user says which.
