"""Command-line interface and stable machine-readable output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .audit import MAX_FILE_BYTES, MAX_FILES, scan


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a local repository for release readiness, offline.")
    parser.add_argument("path", nargs="?", default=".", type=Path)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=("error", "warning", "info", "none"), default="error")
    parser.add_argument("--exclude", action="append", default=[], metavar="DIR", help="Ignore a directory base name; repeatable.")
    parser.add_argument("--max-files", type=positive_int, default=MAX_FILES)
    parser.add_argument("--max-file-bytes", type=positive_int, default=MAX_FILE_BYTES)
    args = parser.parse_args(argv)
    try:
        result = scan(args.path, exclude=args.exclude, max_files=args.max_files,
                      max_file_bytes=args.max_file_bytes)
    except (OSError, ValueError):
        # Do not echo potentially sensitive exception or user-supplied text.
        if args.format == "json":
            print(json.dumps({"schema_version": 1, "error": "Unable to audit the repository; verify its path and permissions."}))
        else:
            print("Unable to audit the repository; verify its path and permissions.", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=True))
    else:
        # Escape control characters in paths to prevent terminal escape injection.
        print("Repository:", ascii(result.root))
        print(f"Scanned {result.files_scanned} text files; skipped {result.files_skipped} files.")
        for finding in result.findings:
            location = "" if finding.path is None else " " + ascii(finding.path)
            if finding.line is not None:
                location += f":{finding.line}"
            print(f"{finding.severity.upper()} {finding.code}{location}: {finding.message}")
        counts = result.counts
        print(f"{counts['error']} errors, {counts['warning']} warnings, {counts['info']} informational findings.")
    return 1 if result.fails(args.fail_on) else 0
