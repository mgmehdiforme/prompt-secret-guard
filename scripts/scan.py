#!/usr/bin/env python3
"""Scan a project against the 7-point "secrets in prompts" checklist.

Usage: scan.py [project_dir] [--json]
Exit code: 1 if a critical finding exists (a real secret in the repo or a
tracked secret file), else 0, so it can run in CI.
Standard library only. Secret values are always masked in the output.
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patterns import find_secrets, is_secret_path  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next",
             "bin", "obj", "target", ".idea", ".vscode", "vendor", ".terraform", "coverage", ".cache"}
TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".cs", ".go", ".rb", ".php", ".java", ".kt",
            ".rs", ".swift", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".md", ".txt", ".log",
            ".sh", ".ps1", ".env", ".properties", ".xml", ".config", ".tf", ".sql", ".html", ".vue", ".svelte",
            ".ipynb", ".jsonl", ".prompt", ".j2", ".hbs"}
MAX_BYTES = 2_000_000

LLM_CALL = re.compile(r"(?:from\s+openai|import\s+openai|from\s+anthropic|import\s+anthropic|['\"]openai['\"]|"
                      r"['\"]@anthropic-ai/sdk['\"]|['\"]ai['\"]|@ai-sdk/|langchain|llamaindex|Azure\.AI\.OpenAI|"
                      r"Microsoft\.Extensions\.AI|Microsoft\.SemanticKernel|google\.generativeai|google-genai|"
                      r"chat\.completions\.create|messages\.create|generateText\(|streamText\()")
REDACT = re.compile(r"(?i)\b(?:redact\w*|scrub\w*|sanitiz\w*|mask_?secrets?|strip_?secrets?|presidio|detect_secrets)\b")
BASE_URL = re.compile(r"(?i)(?:base_?url|baseURL|api_base|endpoint)\s*[:=]\s*['\"]?(https?://[^\s'\"]+)")
ROUTERS = re.compile(r"(?i)openrouter\.ai|together\.(?:ai|xyz)|deepinfra|groq\.com|fireworks\.ai|novita|"
                     r"siliconflow|hyperbolic|aimlapi|api\.chatanywhere|one-api|new-api")
ENV_DUMP = re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|str\(\s*os\.environ\s*\)|"
                      r"json\.dumps\(\s*os\.environ|Environment\.GetEnvironmentVariables\(\)")
TRACE_TO_LLM = re.compile(r"(?i)(?:traceback\.format_exc|\.stack\b|e\.StackTrace|ex\.ToString\(\))")
SCANNERS = re.compile(r"(?i)gitleaks|trufflehog|detect-secrets|ggshield|secret[-_ ]scanning|talisman|noseyparker")
CANARY = re.compile(r"(?i)canarytoken|canary[_-]?(?:key|token|credential)")


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            p = os.path.join(d, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in TEXT_EXT or f.startswith(".env") or f in ("Dockerfile", ".npmrc", ".pypirc", ".netrc"):
                try:
                    if os.path.getsize(p) <= MAX_BYTES:
                        yield p
                except OSError:
                    pass


def read(p):
    try:
        with open(p, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def git(root, *args):
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return ""


def scan(root):
    root = os.path.abspath(root)
    rel = lambda p: os.path.relpath(p, root)  # noqa: E731
    tracked = set(git(root, "ls-files").splitlines())
    is_git = bool(tracked) or os.path.isdir(os.path.join(root, ".git"))

    secrets, weak, llm_files, redact_files, base_urls, routers = [], [], [], [], set(), set()
    env_dumps, trace_hits, canary, scanners = [], [], [], []
    secret_files = []

    for p in walk(root):
        r = rel(p)
        text = read(p)
        if is_secret_path(r):
            secret_files.append(r)
            continue  # values in .env are expected; the question is whether they leak
        for kind, val in find_secrets(text):
            secrets.append((r, kind, val))
        if not r.endswith((".md", ".txt")):
            for kind, val in find_secrets(text, weak=True)[len(find_secrets(text)):]:
                weak.append((r, kind, val))
        if LLM_CALL.search(text):
            llm_files.append(r)
            if TRACE_TO_LLM.search(text):
                trace_hits.append(r)
        if REDACT.search(text):
            redact_files.append(r)
        for m in BASE_URL.finditer(text):
            base_urls.add(m.group(1).rstrip("/,);"))
        for m in ROUTERS.finditer(text):
            routers.add(m.group(0).lower())
        if ENV_DUMP.search(text):
            env_dumps.append(r)
        if CANARY.search(text):
            canary.append(r)
        if (".github/workflows" in r.replace("\\", "/") or r.startswith(".pre-commit") or "gitlab-ci" in r) and SCANNERS.search(text):
            scanners.append(r)

    tracked_secret_files = [f for f in secret_files if f in tracked]
    gitignore = read(os.path.join(root, ".gitignore"))
    env_ignored = bool(re.search(r"(?m)^\s*/?\.env(\*|\.\*|\s*$)", gitignore))
    settings = read(os.path.join(root, ".claude", "settings.json")) + read(os.path.join(root, ".claude", "settings.local.json"))
    agent_blocked = bool(re.search(r"Read\([^)]*\.env", settings))

    checks = []

    def add(n, title, status, detail):
        checks.append({"n": n, "title": title, "status": status, "detail": detail})

    d1 = []
    if secrets:
        d1 += [f"{f}: {k} {v}" for f, k, v in secrets[:20]]
    if tracked_secret_files:
        d1 += [f"tracked by git: {f}" for f in tracked_secret_files]
    if env_dumps:
        d1 += [f"whole environment serialized in {f}" for f in env_dumps]
    add(1, "No real secret in code, prompts, logs or agent context",
        "FAIL" if (secrets or tracked_secret_files) else ("WARN" if env_dumps or weak else "PASS"),
        d1 + [f"weak signal {f}: {k} {v}" for f, k, v in weak[:10]] or ["no high-confidence secrets found"])

    if not llm_files:
        add(2, "A redaction step runs before every model call", "N/A", ["no model calls found"])
    else:
        st = "PASS" if redact_files else "FAIL"
        det = [f"model calls in: {', '.join(llm_files[:8])}"]
        det.append(f"redaction found in: {', '.join(redact_files[:5])}" if redact_files else "no redact/scrub/sanitize step found")
        if trace_hits:
            det.append(f"stack traces may be sent to the model from: {', '.join(trace_hits[:5])}")
            st = "FAIL" if st == "FAIL" else "WARN"
        add(2, "A redaction step runs before every model call", st, det)

    det3 = [".env in .gitignore" if env_ignored else ".env is NOT in .gitignore",
            "Claude settings deny reading .env" if agent_blocked else "no Read(.env) deny rule in .claude/settings.json (fine if prompt-secret-guard is installed)"]
    add(3, "Agents cannot read .env or credential files", "PASS" if env_ignored else "FAIL", det3)

    aws_keys = [s for s in secrets if s[1] == "AWS access key id" and "AKIA" in s[2]]
    add(4, "Keys are scoped, short-lived and rotatable", "WARN" if aws_keys else "MANUAL",
        (["long-lived AWS user keys (AKIA…) found in the repo: rotate them and switch to roles/SSO"] if aws_keys else [])
        + ["check by hand: one key per job, expiry set, rotation documented"])

    add(5, "Pull requests (including agent PRs) are scanned for credentials",
        "PASS" if scanners else ("FAIL" if is_git else "N/A"),
        [f"scanner configured in: {', '.join(scanners)}"] if scanners else ["no gitleaks/trufflehog/detect-secrets in CI or pre-commit"])

    det6 = [f"base URL: {u}" for u in sorted(base_urls)[:10]] + [f"router/reseller referenced: {r}" for r in sorted(routers)]
    add(6, "Every hop to the model is known", "WARN" if routers else ("MANUAL" if llm_files else "N/A"),
        det6 or ["no custom base URLs; calls go to the SDK default endpoint"])

    add(7, "A canary credential is in place and alerts", "PASS" if canary else "FAIL" if llm_files else "MANUAL",
        [f"canary referenced in: {', '.join(canary[:3])}"] if canary else ["no canary token found (see canarytokens.org)"])

    critical = bool(secrets or tracked_secret_files)
    return {"root": root, "checks": checks, "critical": critical}


def to_markdown(res):
    icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "MANUAL": "📝", "N/A": "—"}
    out = [f"# Secrets-in-prompts scan: {res['root']}", ""]
    score = sum(1 for c in res["checks"] if c["status"] == "PASS")
    out.append(f"**{score}/7 checks pass.**" + (" **Critical: real secrets found. Rotate them first.**" if res["critical"] else ""))
    out.append("")
    for c in res["checks"]:
        out.append(f"## {icon[c['status']]} {c['n']}. {c['title']} — {c['status']}")
        out += [f"- {d}" for d in c["detail"]]
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    res = scan(args[0] if args else ".")
    print(json.dumps(res, indent=2) if "--json" in sys.argv else to_markdown(res))
    sys.exit(1 if res["critical"] else 0)
