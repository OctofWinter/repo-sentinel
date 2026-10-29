"""Deterministic repository checks; source contents never enter reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Iterable


IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "__pycache__", ".pytest_cache", ".mypy_cache", "dist", "build",
})
MAX_FILE_BYTES = 1_048_576
MAX_FILES = 10_000
SENSITIVE_NAMES = frozenset({".env", ".env.local", ".env.production", "credentials.json"})
SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

# Deliberately specific formats: a random long string alone is not a secret.
SECRET_PATTERNS = (
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    path: str | None = None
    line: int | None = None


@dataclass
class AuditResult:
    root: str
    files_scanned: int
    files_skipped: int
    findings: list[Finding]

    @property
    def counts(self) -> dict[str, int]:
        return {level: sum(f.severity == level for f in self.findings)
                for level in SEVERITY_ORDER}

    def to_dict(self) -> dict:
        return {"schema_version": 1, "root": self.root,
                "files_scanned": self.files_scanned, "files_skipped": self.files_skipped,
                "counts": self.counts, "findings": [asdict(f) for f in self.findings]}

    def fails(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        return any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[threshold]
                   for f in self.findings)


def _walk(root: Path, excluded: frozenset[str]) -> Iterable[Path]:
    """Walk in stable order and never follow repository symlinks."""
    pending = [root]
    while pending:
        directory = pending.pop()
        children = sorted(directory.iterdir(), key=lambda p: p.name)
        subdirs = []
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name not in excluded:
                    subdirs.append(child)
            elif child.is_file():
                yield child
        pending.extend(reversed(subdirs))


def _readme_checks(root: Path) -> list[Finding]:
    findings = []
    entries = {p.name.lower(): p for p in root.iterdir() if not p.is_symlink()}
    readme = next((entries[name] for name in ("readme.md", "readme.rst", "readme.txt", "readme")
                   if name in entries and entries[name].is_file()), None)
    if readme is None:
        findings.append(Finding("missing_readme", "warning", "Add a README explaining installation and usage."))
    elif readme.stat().st_size <= MAX_FILE_BYTES:
        content = readme.read_bytes().decode("utf-8", errors="replace")
        if len(content.strip()) < 120:
            findings.append(Finding("short_readme", "warning", "Explain the problem, installation, and a working example.", readme.name))
        if not re.search(r"install|quick\s*start|getting started|安装|快速开始", content, re.I):
            findings.append(Finding("missing_install_docs", "info", "Document how to install or run the project.", readme.name))
        if not re.search(r"usage|example|用法|使用|示例", content, re.I):
            findings.append(Finding("missing_usage_docs", "info", "Include a copyable usage example.", readme.name))

    if not any(re.fullmatch(r"(?:licen[sc]e|copying)(?:\..+)?", name)
               and path.is_file() for name, path in entries.items()):
        findings.append(Finding("missing_license", "warning", "Add a license so others know how they can use the code."))
    if not any(name.startswith("contributing") and p.is_file() for name, p in entries.items()):
        findings.append(Finding("missing_contributing", "info", "Document how contributors can run checks and submit changes."))
    if not any(name.startswith("security") and p.is_file() for name, p in entries.items()):
        findings.append(Finding("missing_security_policy", "info", "Document a private vulnerability reporting route."))
    return findings


def scan(root: str | Path, *, exclude: Iterable[str] = (),
         max_files: int = MAX_FILES, max_file_bytes: int = MAX_FILE_BYTES) -> AuditResult:
    """Inspect a local directory without modifying it or using the network.

    Exclusions match directory base names at any depth. Findings include rule
    names and locations, never matched tokens or source lines. The root itself
    may be a symlink; symlinks inside the resolved tree are always ignored.
    """
    if max_files < 1 or max_file_bytes < 1:
        raise ValueError("scan limits must be positive")
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("repository path must be a directory")
    excluded = IGNORED_DIRS | frozenset(exclude)
    findings = _readme_checks(root)
    scanned = skipped = discovered = 0
    has_tests = has_ci = False
    for path in _walk(root, excluded):
        if discovered >= max_files:
            findings.append(Finding("file_limit", "warning", "File limit reached; the audit is incomplete."))
            break
        discovered += 1
        relative = path.relative_to(root).as_posix()
        parts = path.relative_to(root).parts
        name = path.name.lower()
        has_tests |= (
            "tests" in parts or "test" in parts or "__tests__" in parts
            or name.startswith("test_") or name.endswith(("_test.py", "_test.go", ".test.js", ".test.ts", ".spec.ts"))
        )
        has_ci |= (relative.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))) or relative == ".gitlab-ci.yml"
        if name in SENSITIVE_NAMES:
            findings.append(Finding("sensitive_file", "warning", "Verify this configuration file contains no credentials before publishing.", relative))
        try:
            # Bound the read even if a file grows after it was enumerated.
            with path.open("rb") as stream:
                data = stream.read(max_file_bytes + 1)
            if len(data) > max_file_bytes or b"\x00" in data:
                skipped += 1
                continue
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        except OSError:
            skipped += 1
            findings.append(Finding("unreadable_file", "warning", "File could not be read; the audit is incomplete.", relative))
            continue
        scanned += 1
        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding("secret_" + rule, "error", "Possible credential detected; review locally and rotate if real. Value redacted.", relative, line_no))
    if not has_tests:
        findings.append(Finding("missing_tests", "warning", "Add automated tests for the project's behavior."))
    if not has_ci:
        findings.append(Finding("missing_ci", "info", "Run automated checks in CI before merging."))
    if skipped:
        findings.append(Finding("skipped_files", "info", "Some binary, oversized, or unreadable files were not scanned; inspect them separately."))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path or "", f.line or 0, f.code))
    return AuditResult(str(root), scanned, skipped, findings)
