# repo-sentinel

An offline command-line check before you publish a source repository. Find missing release documentation, absent test and CI entry points, and a small set of recognizable credential formats without sending your code to a service.

Runtime dependencies: **Python 3.10+ and its standard library**. No GitHub token, Git installation, or network access is needed to scan a directory. Package installation uses setuptools as a build dependency.

## Installation

Clone or download this repository, then install from its root:

```sh
python -m pip install .
repo-sentinel --version
```

You can also run directly from source without installing dependencies:

```sh
# Linux / macOS, from the repository root
PYTHONPATH=src python -m repo_sentinel /path/to/project
```

PowerShell equivalent:

```powershell
$env:PYTHONPATH = "src"
python -m repo_sentinel C:\path\to\project
```

## Usage

```sh
repo-sentinel .
repo-sentinel ../my-project --format json
repo-sentinel . --fail-on warning
repo-sentinel . --exclude generated --exclude fixtures
repo-sentinel . --max-files 20000 --max-file-bytes 2097152
```

`--exclude` matches directory base names at any depth, not globs. It does not modify `.gitignore`. The scanner checks the working directory contents, including untracked files; it does not inspect Git history or use `.gitignore` rules. This deliberately helps catch a local `.env` before publication.

By default the process exits with `1` when a possible credential is found. Missing README, license, or tests produce warnings; absent CI and contribution/security instructions produce informational findings. `--fail-on warning` also fails on warnings, `--fail-on info` fails on any finding, and `--fail-on none` always allows findings. A path or traversal error exits with `2` regardless of policy.

Example for an empty directory (abbreviated):

```text
Repository: '/path/to/project'
Scanned 0 text files; skipped 0 files.
WARNING missing_license: Add a license so others know how they can use the code.
WARNING missing_readme: Add a README explaining installation and usage.
WARNING missing_tests: Add automated tests for the project's behavior.
```

## Checks and limitations

| Check | What it inspects |
| --- | --- |
| README | Root README, introductory text, installation and usage cues in English or Chinese |
| License | Root LICENSE, LICENCE, or COPYING file |
| Tests | Test directory or common Python, Go, JavaScript and TypeScript test filenames |
| CI | GitHub Actions workflow files or a root GitLab CI configuration |
| Contribution / security instructions | Root CONTRIBUTING and SECURITY files |
| Sensitive files | Common `.env` variants and `credentials.json` |
| Credential patterns | Selected GitHub tokens, AWS access-key IDs, Slack tokens and private-key headers |

These are presence and pattern checks. They do not prove that tests pass, workflows are valid, or a license permits your intended use. Known patterns can miss credentials; test fixtures can trigger false positives. Findings never include matched values or source lines, but reports contain your local root path and filenames, which may themselves be sensitive.

The scanner skips dependency/build directories, repository metadata, symlinks within the tree, binary files, non-UTF-8 files and files above 1 MiB. It reads at most 10,000 candidate files by default. Skipped-file counts and limit findings make incomplete coverage visible. Root README checks also run separately. A repository changing during traversal is outside the supported threat model; scan a stable checkout you control. A clean report is not a security guarantee.

## JSON API

`--format json` emits one object with a versioned envelope:

```json
{
  "schema_version": 1,
  "root": "/path/to/project",
  "files_scanned": 7,
  "files_skipped": 0,
  "counts": {"error": 0, "warning": 0, "info": 0},
  "findings": []
}
```

Every finding contains `code`, `severity`, `message`, `path`, and `line`; unavailable locations are `null`. Invalid paths produce `{"schema_version": 1, "error": "..."}` and exit `2`. Files and findings are ordered deterministically for a stable directory tree.

For Python integration:

```python
from repo_sentinel.audit import scan

result = scan(".", exclude=["generated"])
print(result.to_dict())
if result.fails("warning"):
    raise SystemExit(1)
```

## Development and tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m repo_sentinel . --fail-on warning
```

The suite covers credential redaction, supported patterns, exclusions, symlinks, incomplete coverage, deterministic output, exit codes and terminal control-character escaping. CI tests Python 3.10 through 3.13 and audits this repository.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting. MIT licensed.
