# Contributing

Please open a focused issue describing a reproducible problem or propose a pull request with a small, useful change. Explain the expected behavior and how you tested it.

Use Python 3.10 or newer. Install with `python -m pip install .`, then run:

```sh
python -m unittest discover -s tests -v
repo-sentinel . --fail-on warning
```

Without installing, prefix each command with `PYTHONPATH=src` and replace the executable with `python -m repo_sentinel`.

Keep runtime dependencies limited to the standard library. Add behavior tests for new rules, including a false-positive case and proof that reports do not reveal secret values. Construct synthetic credential strings from separate pieces so fixtures do not look like live credentials to scanners.

Changes to JSON output should preserve `schema_version: 1` compatibility or explicitly introduce a new schema version. Avoid scanning new locations or changing failure thresholds silently. Do not include real credentials, personal source code, or sensitive report paths in issues.
