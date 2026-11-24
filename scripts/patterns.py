"""Shared secret patterns and secret-file rules for prompt-secret-guard.

Only high-confidence formats are in SECRET_PATTERNS, so blocking stays rare and
meaningful. Weaker signals (password=..., generic tokens) are in WEAK_PATTERNS
and are only reported by the scanner, never blocked.
"""
import fnmatch
import os
import re

SECRET_PATTERNS = [
    ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"),
    ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    ("Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ("Database URL with password", r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@]+:[^\s@/]{3,}@[^\s]+"),
    ("Azure storage key", r"AccountKey=[A-Za-z0-9+/=]{60,}"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
]

WEAK_PATTERNS = [
    ("Password assignment", r"(?i)\b(?:password|passwd|pwd|secret|api_?key|access_?token)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    ("Bearer token", r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]

SECRET_RE = [(n, re.compile(p)) for n, p in SECRET_PATTERNS]
WEAK_RE = [(n, re.compile(p)) for n, p in WEAK_PATTERNS]

# File names / globs whose contents should never reach a model.
SECRET_FILE_GLOBS = [
    ".env", ".env.*", "*.env", ".envrc",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".git-credentials",
    "credentials", "credentials.json", "service-account*.json",
    "application_default_credentials.json",
    "*.tfstate", "*.tfstate.backup", "secrets.yml", "secrets.yaml",
]
# Safe templates that look like secret files.
SAFE_FILE_GLOBS = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub"]
SECRET_DIR_PARTS = [".aws", ".ssh", ".gnupg", ".docker", ".kube", "gcloud", ".azure"]


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-2:] + f" ({len(value)} chars)"


def find_secrets(text: str, weak: bool = False):
    """Return a list of (kind, masked_value) found in text."""
    hits = []
    for name, rx in SECRET_RE + (WEAK_RE if weak else []):
        for m in rx.finditer(text or ""):
            hits.append((name, mask(m.group(0))))
    return hits


def is_secret_path(path: str, allow=()) -> bool:
    if not path:
        return False
    norm = path.replace("\\", "/")
    base = os.path.basename(norm.rstrip("/"))
    for g in allow:
        if fnmatch.fnmatch(norm, g) or fnmatch.fnmatch(base, g):
            return False
    if any(fnmatch.fnmatch(base, g) for g in SAFE_FILE_GLOBS):
        return False
    if any(fnmatch.fnmatch(base, g) for g in SECRET_FILE_GLOBS):
        return True
    parts = norm.split("/")
    for d in SECRET_DIR_PARTS:
        if d in parts[:-1]:
            # ~/.docker/config.json, ~/.kube/config, ~/.aws/credentials ...
            if base in ("config", "config.json", "credentials", "credentials.db", "access_tokens.db") or d in (".ssh", ".gnupg"):
                return True
    return False
