#!/usr/bin/env python3
"""Run: python3 tests/test_guard.py   (fake secrets are assembled at runtime so this repo contains none)"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(ROOT, "scripts", "guard.py")
SCAN = os.path.join(ROOT, "scripts", "scan.py")
AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
OAI = "sk-" + "proj-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def run(kind, ev, env=None):
    p = subprocess.run([sys.executable, GUARD, kind], input=json.dumps(ev), capture_output=True, text=True,
                       env={**os.environ, **(env or {})})
    return json.loads(p.stdout) if p.stdout.strip() else {}


def denied(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


cases = [
    ("prompt with key blocked", lambda: run("prompt", {"prompt": f"my key is {AWS} fix it"}).get("decision") == "block"),
    ("plain prompt allowed", lambda: run("prompt", {"prompt": "fix the login bug"}) == {}),
    ("read .env denied", lambda: denied(run("pre", {"tool_name": "Read", "tool_input": {"file_path": "/app/.env"}}))),
    ("read .env.local denied", lambda: denied(run("pre", {"tool_name": "Read", "tool_input": {"file_path": "/app/.env.local"}}))),
    ("read .env.example allowed", lambda: run("pre", {"tool_name": "Read", "tool_input": {"file_path": "/app/.env.example"}}) == {}),
    ("read ~/.aws/credentials denied", lambda: denied(run("pre", {"tool_name": "Read", "tool_input": {"file_path": "/home/u/.aws/credentials"}}))),
    ("read ssh key denied", lambda: denied(run("pre", {"tool_name": "Read", "tool_input": {"file_path": "/home/u/.ssh/id_ed25519"}}))),
    ("read source allowed", lambda: run("pre", {"tool_name": "Read", "tool_input": {"file_path": "/app/src/main.py"}}) == {}),
    ("cat .env denied", lambda: denied(run("pre", {"tool_name": "Bash", "tool_input": {"command": "cat .env | head"}}))),
    ("grep in .env denied", lambda: denied(run("pre", {"tool_name": "Bash", "tool_input": {"command": "grep KEY .env.production"}}))),
    ("printenv denied", lambda: denied(run("pre", {"tool_name": "Bash", "tool_input": {"command": "printenv"}}))),
    ("echo $API_KEY denied", lambda: denied(run("pre", {"tool_name": "Bash", "tool_input": {"command": "echo $OPENAI_API_KEY"}}))),
    ("aws export creds denied", lambda: denied(run("pre", {"tool_name": "Bash", "tool_input": {"command": "aws configure export-credentials"}}))),
    ("ls allowed", lambda: run("pre", {"tool_name": "Bash", "tool_input": {"command": "ls -la .env"}}) == {}),
    ("npm test allowed", lambda: run("pre", {"tool_name": "Bash", "tool_input": {"command": "npm test && git status"}}) == {}),
    ("hardcoded key in code denied", lambda: denied(run("pre", {"tool_name": "Write", "tool_input": {"file_path": "/app/x.py", "content": f"KEY='{OAI}'"}}))),
    ("key into .env allowed", lambda: run("pre", {"tool_name": "Write", "tool_input": {"file_path": "/app/.env", "content": f"KEY={OAI}"}}) == {}),
    ("ask mode asks", lambda: run("pre", {"tool_name": "Read", "tool_input": {"file_path": ".env"}}, {"PROMPT_GUARD_MODE": "ask"})["hookSpecificOutput"]["permissionDecision"] == "ask"),
    ("off mode silent", lambda: run("pre", {"tool_name": "Read", "tool_input": {"file_path": ".env"}}, {"PROMPT_GUARD_MODE": "off"}) == {}),
    ("post warns on leaked output", lambda: "secret" in run("post", {"tool_name": "Bash", "tool_response": {"stdout": AWS}})["hookSpecificOutput"]["additionalContext"]),
    ("bad json does not crash", lambda: subprocess.run([sys.executable, GUARD, "pre"], input="nope", capture_output=True, text=True).returncode == 0),
]


def scan_case():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "app.py"), "w").write(f"from openai import OpenAI\nkey='{AWS}'\n")
        p = subprocess.run([sys.executable, SCAN, d], capture_output=True, text=True)
        return p.returncode == 1 and AWS not in p.stdout and "AKIA" in p.stdout


cases.append(("scanner finds and masks key", scan_case))

fails = 0
for name, fn in cases:
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001
        ok, name = False, f"{name} ({e})"
    print(("PASS " if ok else "FAIL ") + name)
    fails += not ok
print(f"\n{len(cases) - fails}/{len(cases)} passed")
sys.exit(1 if fails else 0)
