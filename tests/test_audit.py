import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from repo_sentinel.audit import scan
from repo_sentinel.cli import main


class RepositoryFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def codes(self, result):
        return {finding.code for finding in result.findings}

    def complete_repository(self):
        self.write("README.md", "# A real tool\n\nInstallation and usage example.\n" + "Explains the supported behavior. " * 5)
        self.write("LICENSE", "MIT license text")
        self.write("CONTRIBUTING.md", "Run the test suite before proposing a change.")
        self.write("SECURITY.md", "Use a private security advisory.")
        self.write("tests/test_example.py", "assert 2 + 2 == 4\n")
        self.write(".github/workflows/ci.yml", "name: ci\n")
        self.write("src/main.py", "print('hello')\n")

    def test_empty_repository_has_actionable_findings(self):
        result = scan(self.root)
        self.assertTrue({"missing_readme", "missing_license", "missing_tests", "missing_ci"} <= self.codes(result))
        self.assertEqual(result.files_scanned, 0)
        self.assertTrue(result.fails("warning"))
        self.assertFalse(result.fails("error"))

    def test_complete_repository_has_no_findings(self):
        self.complete_repository()
        result = scan(self.root)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 7)

    def test_credentials_are_located_but_never_serialized(self):
        token = "gh" + "p_" + "a" * 36
        self.write("settings.py", "# configuration\nTOKEN = '" + token + "'\n")
        result = scan(self.root)
        matches = [f for f in result.findings if f.code == "secret_github_token"]
        self.assertEqual(len(matches), 1)
        self.assertEqual((matches[0].path, matches[0].line), ("settings.py", 2))
        self.assertNotIn(token, json.dumps(result.to_dict()))
        self.assertTrue(result.fails("error"))

    def test_known_secret_formats(self):
        examples = {
            "aws_access_key": "AK" + "IA" + "A" * 16,
            "private_key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "slack_token": "xo" + "xb-" + "a" * 25,
            "github_token": "github_" + "pat_" + "a" * 40,
        }
        for kind, value in examples.items():
            with self.subTest(kind=kind):
                self.write("config.txt", value)
                self.assertIn("secret_" + kind, self.codes(scan(self.root)))

    def test_arbitrary_long_strings_are_not_credentials(self):
        self.write("checksum.txt", "a" * 64)
        self.assertFalse(scan(self.root).fails("error"))

    def test_excludes_dependencies_and_custom_directory_at_any_depth(self):
        token = "gh" + "p_" + "b" * 36
        self.write("node_modules/package/key.txt", token)
        self.write("nested/cache/key.txt", token)
        self.write(".git/config", token)
        self.assertFalse(scan(self.root, exclude=["cache"]).fails("error"))
        self.assertTrue(scan(self.root).fails("error"))

    def test_symlinks_are_not_followed_or_used_as_readme(self):
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside)
            (external / "key.txt").write_text("gh" + "p_" + "c" * 36)
            try:
                (self.root / "external").symlink_to(external, target_is_directory=True)
                (self.root / "README.md").symlink_to(external / "key.txt")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            result = scan(self.root)
            self.assertEqual(result.files_scanned, 0)
            self.assertIn("missing_readme", self.codes(result))
            self.assertFalse(result.fails("error"))

    def test_binary_non_utf8_and_large_files_report_incomplete_coverage(self):
        self.write("large.txt", "x" * 25)
        (self.root / "binary.bin").write_bytes(b"a\x00b")
        (self.root / "latin1.txt").write_bytes(b"\xff")
        result = scan(self.root, max_file_bytes=20)
        self.assertEqual(result.files_skipped, 3)
        self.assertEqual(result.files_scanned, 0)
        self.assertIn("skipped_files", self.codes(result))

    def test_file_limit_is_explicit_and_deterministic(self):
        self.write("a.py", "pass\n")
        self.write("b.py", "pass\n")
        first = scan(self.root, max_files=1)
        self.assertIn("file_limit", self.codes(first))
        self.assertEqual(first.files_scanned, 1)
        self.assertEqual(first.to_dict(), scan(self.root, max_files=1).to_dict())

    def test_exact_file_limit_does_not_claim_truncation(self):
        self.write("a.py", "pass\n")
        self.assertNotIn("file_limit", self.codes(scan(self.root, max_files=1)))

    def test_sensitive_files_are_flagged_without_reading_values_into_report(self):
        self.write(".env", "API_URL=https://example.com\n")
        result = scan(self.root)
        self.assertIn("sensitive_file", self.codes(result))
        self.assertNotIn("API_URL", json.dumps(result.to_dict()))

    def test_readme_hints_are_case_insensitive(self):
        self.write("ReadMe.MD", "# Installation\nUsage example\n" + "Useful explanation. " * 10)
        codes = self.codes(scan(self.root))
        self.assertFalse({"missing_readme", "short_readme", "missing_install_docs", "missing_usage_docs"} & codes)

    def test_invalid_paths_and_limits(self):
        with self.assertRaises(FileNotFoundError):
            scan(self.root / "missing")
        file = self.write("file.txt", "text")
        with self.assertRaises(ValueError):
            scan(file)
        for kwargs in ({"max_files": 0}, {"max_file_bytes": -1}):
            with self.assertRaises(ValueError):
                scan(self.root, **kwargs)

    def test_json_cli_redacts_and_returns_policy_exit_code(self):
        token = "gh" + "p_" + "d" * 36
        self.write("secret.py", token)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(self.root), "--format", "json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["counts"]["error"], 1)
        self.assertNotIn(token, output.getvalue())

    def test_cli_none_threshold_and_missing_path(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), "--fail-on", "none"]), 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main([str(self.root / "missing"), "--format", "json"]), 2)
        self.assertIn("error", json.loads(output.getvalue()))

    @unittest.skipIf(os.name == "nt", "Windows filenames disallow control characters")
    def test_text_cli_escapes_terminal_control_characters(self):
        self.write("unsafe\x1b[31m.py", "gh" + "p_" + "e" * 36)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main([str(self.root)]), 1)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn("\\x1b", output.getvalue())


if __name__ == "__main__":
    unittest.main()
