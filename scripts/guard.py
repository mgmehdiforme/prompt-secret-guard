#!/usr/bin/env python3
"""prompt-secret-guard hook.

Usage (from hooks.json):  guard.py prompt | pre | post
Reads the hook event JSON on stdin.

  prompt : UserPromptSubmit  -> blocks a prompt that contains a real secret.
  pre    : PreToolUse        -> stops the agent reading secret files, dumping
                                the environment, or writing a hardcoded secret.
  post   : PostToolUse       -> if a secret showed up in a tool result, tells
                                the agent not to repeat, log or commit it.

Settings (environment variables):
  PROMPT_GUARD_MODE = block (default) | ask | off
  Project allowlist: .promptguardignore in the project root, one glob per line.
"""
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patterns import find_secrets, is_secret_path  # noqa: E402

MODE = os.environ.get("PROMPT_GUARD_MODE", "block").lower()
FOOTER = " (prompt-secret-guard; set PROMPT_GUARD_MODE=ask or add a glob to .promptguardignore to change this)"

SAFE_COMMANDS = {"ls", "touch", "chmod", "chown", "mkdir", "test", "[", "stat", "git", "rm", "mv"}
ENV_DUMP = [
    re.compile(r"^\s*(?:env|printenv)\s*(?:$|\||>|;|&)"),
    re.compile(r"^\s*(?:set|export\s+-p|declare\s+-x)\s*(?:$|\|)"),
    re.compile(r"\baws\s+configure\s+(?:get|export-credentials)\b"),
    re.compile(r"\baws\s+sts\s+get-session-token\b"),
    re.compile(r"\bgcloud\s+auth\s+(?:print-access-token|print-identity-token|application-default\s+print-access-token)\b"),
    re.compile(r"\baz\s+account\s+get-access-token\b"),
    re.compile(r"\bkubectl\s+get\s+secrets?\b.*-o\s*(?:yaml|json|jsonpath)"),
    re.compile(r"\bheroku\s+config\b(?!:set)"),
    re.compile(r"\bgh\s+auth\s+token\b"),
    re.compile(r"\becho\s+[^|;&]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)\w*\}?", re.I),
]


def load_allow():
    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    p = os.path.join(root, ".promptguardignore")
    try:
        with open(p, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def emit(obj):
    print(json.dumps(obj))
    sys.exit(0)


def pre_decision(reason):
    decision = "ask" if MODE == "ask" else "deny"
    emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason + FOOTER,
    }})


def describe(hits):
    kinds = sorted({k for k, _ in hits})
    return ", ".join(kinds)


def bash_problem(cmd, allow):
    for rx in ENV_DUMP:
        if rx.search(cmd):
            return "This command would print credentials or the whole environment into the conversation, which is sent to the model."
    for segment in re.split(r"&&|\|\||;|\|", cmd):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        if os.path.basename(tokens[0]) in SAFE_COMMANDS:
            continue
        for t in tokens[1:]:
            t = t.lstrip("<>@").split("=", 1)[-1]
            if is_secret_path(t, allow):
                return f"This command reads `{os.path.basename(t)}`, a secret file. Its contents would be sent to the model."
    return None


def handle_pre(ev):
    tool = ev.get("tool_name", "")
    ti = ev.get("tool_input", {}) or {}
    allow = load_allow()

    if tool in ("Read", "NotebookRead"):
        p = ti.get("file_path") or ti.get("notebook_path") or ""
        if is_secret_path(p, allow):
            pre_decision(f"`{os.path.basename(p)}` is a secret file. Reading it puts its values into the prompt. Ask the user which variable names exist instead, or read `.env.example`.")
    elif tool == "Grep":
        p = ti.get("path") or ""
        g = ti.get("glob") or ""
        if is_secret_path(p, allow) or (g and is_secret_path(g, allow)):
            pre_decision("Searching inside secret files puts their values into the prompt.")
    elif tool == "Bash":
        problem = bash_problem(ti.get("command", ""), allow)
        if problem:
            pre_decision(problem)
    elif tool in ("Write", "Edit", "MultiEdit"):
        p = ti.get("file_path", "")
        if is_secret_path(p, allow):
            sys.exit(0)  # writing into a secret file is where secrets belong
        text = ti.get("content") or ti.get("new_string") or ""
        for e in ti.get("edits", []) or []:
            text += "\n" + (e.get("new_string") or "")
        hits = find_secrets(text)
        if hits:
            pre_decision(f"This would hardcode a secret ({describe(hits)}) in `{os.path.basename(p)}`. Read it from an environment variable or a secret manager instead.")
    sys.exit(0)


def handle_prompt(ev):
    if MODE == "off":
        sys.exit(0)
    hits = find_secrets(ev.get("prompt", ""))
    if not hits:
        sys.exit(0)
    msg = (f"Your prompt contains what looks like a real secret ({describe(hits)}: "
           + "; ".join(v for _, v in hits[:3])
           + "). It was not sent. Replace it with a placeholder like <API_KEY>, and rotate the key if it was already shared anywhere.")
    if MODE == "ask":
        emit({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
              "additionalContext": "WARNING: the user's prompt contains a secret. Do not repeat it, write it to files, logs or commits."}})
    emit({"decision": "block", "reason": msg})


def handle_post(ev):
    if MODE == "off":
        sys.exit(0)
    out = json.dumps(ev.get("tool_response", ""))[:500000]
    hits = find_secrets(out)
    if hits:
        emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext":
              f"prompt-secret-guard: the last tool result contained a secret ({describe(hits)}). "
              "Do not repeat it in replies, do not write it to code, logs, docs or commits, and tell the user it should be rotated if it is real."}})
    sys.exit(0)


def main():
    if MODE == "off":
        sys.exit(0)
    kind = sys.argv[1] if len(sys.argv) > 1 else "pre"
    try:
        ev = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # never break the session on bad input
    {"prompt": handle_prompt, "pre": handle_pre, "post": handle_post}.get(kind, handle_pre)(ev)


if __name__ == "__main__":
    main()
