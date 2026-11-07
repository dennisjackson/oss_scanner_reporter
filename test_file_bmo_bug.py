# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import contextlib
import email.utils
import http.client
import io
import os
import re
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import file_bmo_bug as filer

OVERALL_META = 1000

SCAN_README = """# example — findings of scan example-20260101-001

gh:example/project at commit `0123456789ab` · 1 finding(s)

| id | severity | title | location | directory |
|---|---|---|---|---|

## Already public upstream: 1 finding(s), in [already-public-upstream/](x)

## Not security: 1 ordinary bug(s), in [bugs-not-security/](x)
"""

META_SUMMARY = "[example-20260101-001] oss-scanner findings in example"

# The paragraph of an already-public finding's report that names its upstream bug.
UPSTREAM = ("\nAlready public upstream. This looks the same as commit abcdef123456,\n"
            "\"Bug 5000 - Fix the example r=reviewer\"\n"
            "This commit (Bug 5000) adds a counter.\n\n"
            "## Details\nLike the fix for Bug 6000.\n")


class FakeBugzilla:
    """An in-memory Bugzilla; bugs are {id, summary, blocks, groups, ...}."""

    def __init__(self, url="https://bmo.example", api_key=None):
        self.url = url
        self.bugs = {}
        self.attachments = {}
        self.next_id = 100
        self.drop_groups = False
        self.fail_attach = set()
        self.fail_create = None
        self.hidden_from_search = set()
        self.api_key = api_key
        self.searches = 0
        self.visible = {OVERALL_META: {"product": "Product", "component": "Component",
                                       "version": "other"}}

    def add(self, summary, blocks=(), groups=("sec",)):
        self.next_id += 1
        self.bugs[self.next_id] = {"id": self.next_id, "summary": summary,
                                   "blocks": list(blocks), "groups": list(groups)}
        self.attachments[self.next_id] = []
        return self.next_id

    def whoami(self):
        return "filer@example.com"

    def default_security_group(self, product):
        return {"Product": "sec"}.get(product)

    def get_bug(self, bug_id, fields):
        if bug_id in self.bugs:
            bug = self.bugs[bug_id]
            return {field: bug.get(field, []) for field in fields}
        if bug_id not in self.visible:
            raise filer.BugzillaError(f"Bugzilla GET bug/{bug_id}: HTTP 404", 404)
        return {field: self.visible[bug_id].get(field) for field in fields}

    def find_bugs(self, substrings, progress=None):
        self.searches += 1
        return {text: [dict(bug) for bug in self.bugs.values()
                       if text in bug["summary"]
                       and bug["id"] not in self.hidden_from_search]
                for text in substrings}

    def create_bug(self, payload):
        if self.fail_create:
            raise self.fail_create
        bug_id = self.add(payload["summary"], payload.get("blocks", []),
                          [] if self.drop_groups else payload["groups"])
        self.bugs[bug_id].update(payload=payload,
                                 keywords=list(payload.get("keywords", [])))
        return bug_id

    def ensure(self, bug_id, **wanted):
        bug = self.bugs[bug_id]
        for field, values in wanted.items():
            for value in values or []:
                if field == "groups" and self.drop_groups:
                    continue
                if value not in bug.setdefault(field, []):
                    bug[field].append(value)
        return {field: [v for v in values if v not in bug.get(field, [])]
                for field, values in wanted.items()
                if values and any(v not in bug.get(field, []) for v in values)}

    def missing_attachments(self, bug_id, attachments):
        return [a for a in attachments
                if a["file_name"] not in self.attachments[bug_id]]

    def attach_with_retry(self, bug_id, attachment):
        if bug_id in self.fail_attach:
            raise filer.BugzillaError("HTTP 502", 502)
        self.attachments[bug_id].append(attachment["file_name"])

    def by_summary(self, prefix):
        return next(bug for bug in self.bugs.values()
                    if bug["summary"].startswith(prefix))


class FilerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scan_dir = self.root / "scan"
        self.scan_dir.mkdir()
        (self.scan_dir / "README.md").write_text(SCAN_README)
        (self.scan_dir / "build").mkdir()
        (self.scan_dir / "build" / "Dockerfile").write_text("FROM x\n")
        self.finding = self.make_finding("ANT-2026-HIGH1", "high")
        self.make_finding("ANT-2026-LOW1", "low", "already-public-upstream")
        self.make_finding("ANT-2026-BUG1", "NOT SECURITY: ordinary bug",
                          "bugs-not-security")
        self.bugzilla = FakeBugzilla()
        self.target = {"product": "Product", "component": "Component", "version": "other",
                       "group": "sec", "meta_bug": OVERALL_META}

    def make_finding(self, ident, severity, parent=""):
        finding = self.scan_dir / parent / ident
        finding.mkdir(parents=True)
        (finding / "REPORT.md").write_text(
            "=" * 76 + f"\n{ident}  [{severity}]  CWE-367  race\nTitle of {ident}\n\n"
            "## Reproducing\nRun `/tmp/repro` in `/src`.\n\n"
            "## Suggested fix\nPrivate patch details.\n"
        )
        (finding / "repro").write_text("# /tmp/repro.d/example\n")
        (finding / "patches").mkdir()
        (finding / "patches" / "1.patch").write_text(f"--- a/x\n+++ b/x\n# {ident}\n")
        return finding

    def dry_run_output(self, out):
        """The directory a dry run wrote to, removed when the test ends."""
        output = Path(out.rsplit("written to ", 1)[1].split("\n", 1)[0])
        self.addCleanup(shutil.rmtree, output)
        return output

    def found(self, text):
        return self.bugzilla.find_bugs([text])[text]

    def attachment_names(self, ident):
        return [f"{ident}-ORIGINAL-REPORT.md", "proposed_patch_1.patch",
                f"{ident}-reproducer.zip"]

    def unzip(self, data):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def main(self, *args, answer="y", meta_bug=OVERALL_META):
        """Run main() against the fake Bugzilla; returns (stdout, exit message)."""
        argv = ["file_bmo_bug.py", "--meta-bug", str(meta_bug), str(self.scan_dir),
                *args]
        stdout, stderr = io.StringIO(), io.StringIO()

        def connect(url, key):
            self.bugzilla.url, self.bugzilla.api_key = url, key
            return self.bugzilla

        with patch.object(sys, "argv", argv), \
                patch.dict("os.environ", {"BUGZILLA_API_KEY": "env-key"}), \
                patch.object(filer, "Bugzilla", connect), \
                patch("builtins.input", return_value=answer) as prompt, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                filer.main()
                exit_message = None
            except SystemExit as e:
                exit_message = str(e)
        self.prompt = prompt
        self.stderr = stderr.getvalue()
        return stdout.getvalue(), exit_message

    # --- Reports and scans

    def test_report_parsing(self):
        report = (self.finding / "REPORT.md").read_text()
        self.assertEqual(filer.parse_report(report),
                         ("ANT-2026-HIGH1", "high", "Title of ANT-2026-HIGH1"))
        self.assertTrue(filer.build_description(report).endswith(
            "ANT-2026-HIGH1  [high]  CWE-367  race\nTitle of ANT-2026-HIGH1\n\n"
            "## Suggested fix\nPrivate patch details.\n"))
        self.assertNotIn("Reproducing", filer.build_description(report))
        with self.assertRaises(ValueError):
            filer.parse_report("no header\n")

    def test_description_is_not_rewritten(self):
        report = (
            "ANT-2026-TEST [high]\nExample finding\n\n"
            "## Details\nRun `cp -r repro.d /tmp/repro.d && /tmp/repro` "
            "as built in the image.\n\n"
            "## Reproducing\nSteps.\n\n"
            "## Running the reproducer\nInternal notes.\n\n"
            "## Suggested fix\nThe attached patch fixes it. Files in `/tmp/repro.d/`.\n"
            "\n## Related findings\nANT-2026-OTHER.\n"
        )
        self.assertEqual(filer.build_description(report), (
            "ANT-2026-TEST [high]\nExample finding\n\n"
            "## Details\nRun `cp -r repro.d /tmp/repro.d && /tmp/repro` "
            "as built in the image.\n\n"
            "## Suggested fix\nThe attached patch fixes it. Files in `/tmp/repro.d/`.\n"
            "\n## Related findings\nANT-2026-OTHER.\n"
        ))

    def test_load_scan(self):
        scan = filer.load_scan(self.scan_dir)
        self.assertEqual(scan["root"], self.scan_dir.resolve())
        self.assertEqual((scan["id"], scan["project"], scan["repo"], scan["commit"]),
                         ("example-20260101-001", "example", "gh:example/project", "0123456789ab"))
        self.assertEqual(scan["counts"], [("Vulnerabilities", 1),
                                          ("Already public upstream", 1),
                                          ("Not security", 1)])
        for not_a_scan in (self.scan_dir / "bugs-not-security", self.root):
            with self.subTest(path=not_a_scan):
                with self.assertRaises(SystemExit) as cm:
                    filer.load_scan(not_a_scan)
                self.assertIn("is not the root of a scan", str(cm.exception))

    def test_load_findings(self):
        findings = filer.load_findings(filer.load_scan(self.scan_dir))
        self.assertEqual([f["id"] for f in findings],
                         ["ANT-2026-HIGH1", "ANT-2026-LOW1", "ANT-2026-BUG1"])
        self.assertEqual([f["severity"] for f in findings],
                         ["high", "low", "not security: ordinary bug"])
        self.assertEqual(findings[0]["summary"],
                         "[ANT-2026-HIGH1] Title of ANT-2026-HIGH1")
        self.assertEqual([a["file_name"] for a in findings[0]["attachments"]],
                         self.attachment_names("ANT-2026-HIGH1"))

    def test_load_findings_reports_every_problem(self):
        (self.make_finding("ANT-2026-BAD", "high", "x") / "REPORT.md").write_text("?\n")
        self.make_finding("ANT-2026-HIGH1", "high", "copy")
        (self.make_finding("ANT-2026-LONG", "high", "y") / "REPORT.md").write_text(
            "ANT-2026-LONG [high]\nTitle\n" + "x" * filer.MAX_COMMENT_LENGTH)
        with self.assertRaises(SystemExit) as cm:
            filer.load_findings(filer.load_scan(self.scan_dir))
        message = str(cm.exception)
        self.assertIn("x/ANT-2026-BAD: no id, severity and title", message)
        self.assertIn("ANT-2026-HIGH1 is also in ANT-2026-HIGH1", message)
        self.assertIn("y/ANT-2026-LONG: the description is", message)

    # --- Configuration

    def test_api_key_from_the_environment(self):
        with patch.dict("os.environ", {"BUGZILLA_API_KEY": " k1 \n"}), \
                patch.object(filer, "read_masked") as prompt, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(filer.api_key("https://bmo.example"), "k1")
        self.assertIn("Using the API key in $BUGZILLA_API_KEY (***)", stderr.getvalue())
        self.assertNotIn("k1", stderr.getvalue())
        prompt.assert_not_called()

    def test_api_key_is_asked_for(self):
        stderr = io.StringIO()
        with patch.dict("os.environ", {"BUGZILLA_API_KEY": ""}), \
                patch.object(sys.stdin, "isatty", return_value=True), \
                patch.object(filer, "read_masked", return_value=" k2 ") as prompt, \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(filer.api_key("https://bmo.example"), "k2")
        prompt.assert_called_once()
        self.assertIn("https://bmo.example/userprefs.cgi?tab=apikey", stderr.getvalue())
        self.assertIn("BUGZILLA_API_KEY", stderr.getvalue())

    def test_api_key_without_a_terminal(self):
        with patch.dict("os.environ", {}, clear=True), \
                patch.object(sys.stdin, "isatty", return_value=False), \
                patch.object(filer, "read_masked") as prompt:
            with self.assertRaises(SystemExit) as cm:
                filer.api_key("https://bmo.example")
        prompt.assert_not_called()
        self.assertIn("Set BUGZILLA_API_KEY", str(cm.exception))
        self.assertIn("https://bmo.example/userprefs.cgi?tab=apikey", str(cm.exception))

    def test_empty_api_key_answer(self):
        with patch.dict("os.environ", {}, clear=True), \
                patch.object(sys.stdin, "isatty", return_value=True), \
                patch.object(filer, "read_masked", return_value=""), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                filer.api_key("https://bmo.example")
        self.assertEqual(str(cm.exception), "No API key given")

    def test_resolve_target(self):
        self.assertEqual(filer.resolve_target(self.bugzilla, OVERALL_META), self.target)

    # --- Payloads and keywords

    def test_rating_keywords(self):
        expected = {
            "critical": ["sec-critical"], "high": ["sec-high"],
            "medium": ["sec-moderate"], "low": ["sec-low"],
            "not security: ordinary bug": ["sec-other"], "": ["sec-other"],
        }
        for severity, keywords in expected.items():
            with self.subTest(severity=severity):
                self.assertEqual(filer.bug_keywords(severity), keywords)

    def test_payloads_are_always_restricted(self):
        finding = filer.load_findings(filer.load_scan(self.scan_dir))[0]
        payload = filer.build_payload(self.target, finding, 42)
        self.assertEqual(payload, {
            "product": "Product", "component": "Component", "version": "other",
            "type": "defect", "platform": "Unspecified", "op_sys": "Unspecified",
            "summary": finding["summary"], "description": finding["description"],
            "groups": ["sec"], "keywords": ["sec-high"], "blocks": [42],
        })
        for group in (None, ""):
            with self.assertRaises(ValueError):
                filer.build_payload({**self.target, "group": group}, finding, 42)
        meta = filer.build_scan_meta_payload(self.target, filer.load_scan(self.scan_dir))
        self.assertEqual((meta["summary"], meta["type"], meta["keywords"],
                          meta["blocks"], meta["groups"]),
                         (META_SUMMARY, "task", ["meta"], [OVERALL_META], ["sec"]))
        self.assertIn("Commit: 0123456789ab\nVulnerabilities: 1\n"
                      "Already public upstream: 1\nNot security: 1\n",
                      meta["description"])
        self.assertNotIn("Title of", meta["description"])

    # --- Attachments

    def test_reproducer_archive(self):
        reprod = self.finding / "repro.d"
        (reprod / "nested").mkdir(parents=True)
        (reprod / "__pycache__").mkdir()
        (reprod / "__pycache__" / "ignored.pyc").write_bytes(b"ignored")
        (reprod / "nested" / "helper.py").write_bytes(b"path = '/tmp/repro.d/data'")
        (reprod / "input.bin").write_bytes(b"\x00/tmp/repro.d")
        attachments = filer.collect_attachments(self.finding, "TEST")
        self.assertEqual(attachments[-1]["file_name"], "TEST-reproducer.zip")
        self.assertEqual(attachments[-1]["content_type"], "application/zip")
        self.assertFalse(attachments[-1]["is_patch"])
        self.assertEqual(self.unzip(attachments[-1]["data"]), {
            "repro": b"# /tmp/repro.d/example\n",
            "repro.d/nested/helper.py": b"path = '/tmp/repro.d/data'",
            "repro.d/input.bin": b"\x00/tmp/repro.d",
        })
        (self.finding / "repro").unlink()
        shutil.rmtree(reprod)
        shutil.rmtree(self.finding / "patches")
        self.assertEqual([a["file_name"] for a in
                          filer.collect_attachments(self.finding, "TEST")],
                         ["TEST-ORIGINAL-REPORT.md"])

    def test_report_and_patch_attachments(self):
        patches = self.finding / "patches"
        for name in ("10.patch", "2.patch", "3.diff"):
            (patches / name).write_text(f"patch {name}\n")
        attachments = filer.collect_attachments(self.finding, "TEST")
        report, *patch_attachments, _ = attachments
        self.assertEqual(report["file_name"], "TEST-ORIGINAL-REPORT.md")
        self.assertEqual(report["data"], (self.finding / "REPORT.md").read_bytes())
        self.assertIn("## Reproducing", report["data"].decode())
        self.assertEqual((report["content_type"], report["is_patch"]),
                         ("text/plain", False))
        self.assertEqual(
            [(a["file_name"], a["data"]) for a in patch_attachments],
            [("proposed_patch_1.patch", b"--- a/x\n+++ b/x\n# ANT-2026-HIGH1\n"),
             ("proposed_patch_2.patch", b"patch 2.patch\n"),
             ("proposed_patch_3.diff", b"patch 3.diff\n"),
             ("proposed_patch_4.patch", b"patch 10.patch\n")])
        self.assertTrue(all(a["is_patch"] and a["content_type"] == "text/plain"
                            for a in patch_attachments))
        self.assertEqual(patch_attachments[3]["summary"],
                         "Proposed patch 4 for TEST (patches/10.patch)")

    def test_attach_sends_is_patch(self):
        bugzilla = filer.Bugzilla("https://bmo.example", "key")
        attachment = filer.make_attachment("proposed_patch_1.patch", "p", b"x", True)
        with patch.object(bugzilla, "request", return_value={}) as request:
            bugzilla.attach(7, attachment)
        payload = request.call_args.args[2]
        self.assertTrue(payload["is_patch"])
        self.assertEqual(payload["content_type"], "text/plain")

    def test_attachment_limits(self):
        with patch.object(filer, "MAX_ATTACHMENT_SIZE", 200):
            attachment = filer.make_attachment("large.bin", "x" * 251, b"x" * 1000)
            self.assertEqual(attachment["file_name"], "large.bin.zip")
            self.assertEqual(attachment["content_type"], "application/zip")
            self.assertEqual(attachment["summary"], "x" * 249 + "…")
            self.assertEqual(self.unzip(attachment["data"]), {"large.bin": b"x" * 1000})
            zipped = filer.make_attachment("big.patch", "p", b"x" * 1000, is_patch=True)
            self.assertEqual((zipped["file_name"], zipped["is_patch"]),
                             ("big.patch.zip", False))
            with contextlib.redirect_stderr(io.StringIO()) as warnings:
                self.assertIsNone(filer.make_attachment("large.zip", "archive", b"x" * 201))
            self.assertIn("is not attached", warnings.getvalue())

    # --- Bugzilla client

    def test_ensure_adds_missing_fields(self):
        bugzilla = filer.Bugzilla("https://bmo.example", "key")
        states = [
            {"groups": [], "blocks": [1], "keywords": []},
            {"groups": ["sec"], "blocks": [1], "keywords": []},
        ]
        calls = []

        def request(method, path, payload=None):
            calls.append((method, payload))
            if method == "GET":
                return {"bugs": [states.pop(0)]}
            return {}

        with patch.object(bugzilla, "request", side_effect=request):
            missing = bugzilla.ensure(7, groups=["sec"], blocks=[1],
                                      keywords=["sec-other"])
        self.assertEqual(missing, {"keywords": ["sec-other"]})
        self.assertEqual(calls[1], ("PUT", {"groups": {"add": ["sec"]},
                                            "keywords": {"add": ["sec-other"]}}))

    def test_find_bugs_batches_and_keeps_exact_matches(self):
        bugzilla = filer.Bugzilla("https://bmo.example", "key")
        bugs = [{"id": 1, "summary": "[ANT-2026-HIGH1] title"},
                {"id": 2, "summary": "[ant-2026-high1] something else"},
                {"id": 3, "summary": "[ANT-2026-LOW1] [ANT-2026-HIGH1] both"}]
        texts = ["[ANT-2026-HIGH1]", "[ANT-2026-LOW1]", "[ANT-2026-NONE]"]
        with patch.object(filer, "SEARCH_BATCH", 2), \
                patch.object(bugzilla, "request", return_value={"bugs": bugs}) as request:
            found = bugzilla.find_bugs(texts)
        self.assertEqual(found, {"[ANT-2026-HIGH1]": [bugs[0], bugs[2]],
                                 "[ANT-2026-LOW1]": [bugs[2]], "[ANT-2026-NONE]": []})
        self.assertEqual(request.call_count, 2)
        method, path = request.call_args_list[0].args
        self.assertEqual(method, "GET")
        query = urllib.parse.parse_qs(path.split("?", 1)[1])
        self.assertEqual(query["j_top"], ["OR"])
        self.assertEqual((query["f1"], query["o1"], query["v1"], query["v2"]),
                         (["short_desc"], ["substring"], ["[ANT-2026-HIGH1]"],
                          ["[ANT-2026-LOW1]"]))
        self.assertNotIn("summary", query)

    def test_truncated_search_is_an_error(self):
        bugzilla = filer.Bugzilla("https://bmo.example", "key")
        bugs = [{"id": n, "summary": "x"} for n in range(filer.SEARCH_LIMIT)]
        with patch.object(bugzilla, "request", return_value={"bugs": bugs}):
            with self.assertRaises(filer.BugzillaError):
                bugzilla.find_bugs(["[x]"])

    # --- Whole runs

    def test_files_the_meta_bug_and_every_finding(self):
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("File 4 bug(s)?", self.prompt.call_args.args[0])
        meta = self.bugzilla.by_summary("[example-20260101-001]")
        self.assertEqual(meta["summary"], META_SUMMARY)
        self.assertEqual(meta["blocks"], [OVERALL_META])
        self.assertEqual((meta["payload"]["product"], meta["payload"]["component"],
                          meta["payload"]["version"]), ("Product", "Component", "other"))
        self.assertEqual(self.bugzilla.api_key, "env-key")
        self.assertEqual(self.bugzilla.url, filer.DEFAULT_BUGZILLA_URL)
        self.assertEqual(meta["groups"], ["sec"])
        expected = {"ANT-2026-HIGH1": ["sec-high"], "ANT-2026-LOW1": ["sec-low"],
                    "ANT-2026-BUG1": ["sec-other"]}
        for ident, keywords in expected.items():
            with self.subTest(ident=ident):
                bug = self.bugzilla.by_summary(f"[{ident}]")
                self.assertEqual(bug["blocks"], [meta["id"]])
                self.assertEqual(bug["groups"], ["sec"])
                self.assertEqual(bug["keywords"], keywords)
                self.assertEqual(self.bugzilla.attachments[bug["id"]],
                                 self.attachment_names(ident))
                self.assertNotIn("## Reproducing", bug["payload"]["description"])
                self.assertIn("## Suggested fix", bug["payload"]["description"])
        self.assertEqual(len(self.bugzilla.bugs), 4)
        self.assertIn("Filed 3 bug(s), updated 0 existing one(s)", out)

    def test_rerun_files_nothing_twice(self):
        self.main()
        bugs = {k: dict(v) for k, v in self.bugzilla.bugs.items()}
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.prompt.assert_not_called()
        self.assertEqual(self.bugzilla.bugs, bugs)
        self.assertIn(f"Meta bug: {filer.DEFAULT_BUGZILLA_URL}/show_bug.cgi?id=101 (exists)",
                      out)
        self.assertIn("Already filed, nothing to change: 3", out)
        self.assertIn("To file: 0", out)

    def test_existing_bugs_are_reused_and_repaired(self):
        meta = self.bugzilla.add(META_SUMMARY)
        old = self.bugzilla.add("[ANT-2026-HIGH1] filed by hand")
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("File 2 bug(s) and update 2 existing bug(s)?",
                      self.prompt.call_args.args[0])
        self.assertEqual(self.bugzilla.bugs[meta]["blocks"], [OVERALL_META])
        self.assertEqual(self.bugzilla.bugs[old]["blocks"], [meta])
        self.assertEqual(self.bugzilla.attachments[old],
                         self.attachment_names("ANT-2026-HIGH1"))
        self.assertEqual(len(self.found("[ANT-2026-HIGH1]")), 1)
        self.assertEqual(len(self.bugzilla.bugs), 4)
        self.assertIn(f"ANT-2026-HIGH1: bug {old}: block {meta}; attach "
                      "ANT-2026-HIGH1-ORIGINAL-REPORT.md", out)

    def test_existing_public_bug_gets_no_reproducer(self):
        public = self.bugzilla.add("[ANT-2026-HIGH1] public", groups=())
        _, exit_message = self.main()
        self.assertIn("1 problem(s)", exit_message)
        self.assertIn("bug 101 is not in the security group sec", self.stderr)
        self.assertEqual(self.bugzilla.attachments[public], [])

    def test_several_bugs_for_a_finding_are_left_alone(self):
        first = self.bugzilla.add("[ANT-2026-HIGH1] one")
        self.bugzilla.add("[ANT-2026-HIGH1] two")
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("(several bugs: left alone)", out)
        self.assertEqual(self.bugzilla.bugs[first]["blocks"], [])
        self.assertEqual(len(self.found("[ANT-2026-HIGH1]")), 2)

    def test_several_meta_bugs_stop_the_run(self):
        self.bugzilla.add(META_SUMMARY)
        self.bugzilla.add(META_SUMMARY + " (copy)")
        _, exit_message = self.main()
        self.assertIn("has several meta bugs", exit_message)
        self.assertEqual(len(self.bugzilla.bugs), 2)

    def test_declining_files_nothing(self):
        _, exit_message = self.main(answer="n")
        self.assertEqual(exit_message, "Aborted")
        self.assertEqual(self.bugzilla.bugs, {})

    def test_limit(self):
        out, exit_message = self.main("--limit", "2")
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("File 3 bug(s)?", self.prompt.call_args.args[0])
        self.assertIn("To file: 2 of 3 (--limit 2); 1 left for later runs", out)
        self.assertIn("1 finding(s) left to file: run again", out)
        self.assertEqual(len(self.bugzilla.bugs), 3)
        self.assertEqual(self.bugzilla.find_bugs(["[ANT-2026-BUG1]"])["[ANT-2026-BUG1]"], [])
        out, exit_message = self.main("--limit", "2")
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("File 1 bug(s)?", self.prompt.call_args.args[0])
        self.assertIn("To file: 1\n", out)
        self.assertNotIn("left to file", out)
        self.assertEqual(len(self.bugzilla.bugs), 4)
        bug = self.bugzilla.by_summary("[ANT-2026-BUG1]")
        self.assertEqual(bug["blocks"], [101])

    def test_limit_with_an_existing_meta_bug(self):
        meta = self.bugzilla.add(META_SUMMARY, blocks=[OVERALL_META])
        out, exit_message = self.main("--limit", "1")
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("File 1 bug(s)?", self.prompt.call_args.args[0])
        self.assertEqual(len(self.bugzilla.bugs), 2)
        self.assertEqual(self.bugzilla.by_summary("[ANT-2026-")["blocks"], [meta])

    def test_limit_must_be_positive(self):
        for value in ("0", "-1"):
            with self.subTest(value=value):
                _, exit_message = self.main("--limit", value)
                self.assertEqual(exit_message, "2")
                self.assertIn("--limit must be a positive number", self.stderr)
        self.assertEqual(self.bugzilla.bugs, {})

    def test_unrestricted_bug_stops_the_run(self):
        self.bugzilla.drop_groups = True
        _, exit_message = self.main()
        self.assertIn("may NOT be in the security group sec", exit_message)
        self.assertEqual(len(self.bugzilla.bugs), 1)
        self.assertEqual(sum(map(len, self.bugzilla.attachments.values())), 0)

    def test_failed_upload_is_retried_on_the_next_run(self):
        self.bugzilla.fail_attach = {102}
        _, exit_message = self.main()
        self.assertIn("3 problem(s)", exit_message)
        self.assertEqual(self.bugzilla.attachments[102], [])
        self.bugzilla.fail_attach = set()
        _, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertEqual(self.bugzilla.attachments[102],
                         self.attachment_names("ANT-2026-HIGH1"))
        self.assertEqual(len(self.bugzilla.bugs), 4)

    def test_dry_run_files_nothing(self):
        out, exit_message = self.main("--dry-run")
        self.assertIsNone(exit_message, self.stderr)
        self.prompt.assert_not_called()
        self.assertEqual(self.bugzilla.bugs, {})
        self.assertIn(f"Meta bug: to file, {META_SUMMARY!r}, blocking {OVERALL_META}",
                      out)
        self.assertIn("Product: Product :: Component (version other), security group: sec",
                      out)
        self.assertIn("To file: 3\n  top level: 1 (sec-high: 1)\n"
                      "  already-public-upstream/: 1 (sec-low: 1)\n"
                      "  bugs-not-security/: 1 (sec-other: 1)\n", out)
        output = self.dry_run_output(out)
        self.assertEqual(output.parent, Path(tempfile.gettempdir()))
        self.assertTrue(output.name.startswith("bmo-dry-run-"))
        self.assertTrue((output / "meta-description.md").is_file())
        self.assertEqual(sorted(p.name for p in (output / "ANT-2026-HIGH1").iterdir()),
                         sorted(["description.md"]
                                + self.attachment_names("ANT-2026-HIGH1")))
        description = (output / "ANT-2026-BUG1" / "description.md").read_text()
        self.assertIn("Private patch details.", description)
        self.assertNotIn("Run `/tmp/repro` in `/src`.", description)

    def test_missing_security_group_stops_before_lookups(self):
        with patch.object(FakeBugzilla, "default_security_group", return_value=None), \
                patch.object(FakeBugzilla, "find_bugs") as find:
            _, exit_message = self.main()
        self.assertIn("Product has no default security group", exit_message)
        find.assert_not_called()
        self.assertEqual(self.bugzilla.bugs, {})

    def test_unknown_meta_bug_stops_the_run(self):
        _, exit_message = self.main(meta_bug=999)
        self.assertIn("Unable to read bug 999", exit_message)
        self.assertEqual(self.bugzilla.bugs, {})

    def test_meta_bug_must_be_an_id(self):
        _, exit_message = self.main(meta_bug=0)
        self.assertEqual(exit_message, "2")
        self.assertIn("--meta-bug must be a bug id", self.stderr)

    def test_removed_options(self):
        for option in ("--yes", "--bugzilla-url=https://bmo.test"):
            with self.subTest(option=option):
                _, exit_message = self.main(option)
                self.assertEqual(exit_message, "2")
                self.assertIn("unrecognized arguments", self.stderr)

    # --- Changes to existing bugs are planned and confirmed

    def test_changes_to_existing_bugs_are_confirmed(self):
        self.main()
        high = self.bugzilla.by_summary("[ANT-2026-HIGH1]")["id"]
        self.bugzilla.attachments[high].remove("proposed_patch_1.patch")
        out, exit_message = self.main(answer="n")
        self.assertEqual(exit_message, "Aborted")
        self.assertEqual(self.prompt.call_args.args[0],
                         "Update 1 existing bug(s)? [y/N] ")
        self.assertIn(f"To update: 1\n  ANT-2026-HIGH1: bug {high}: attach "
                      "proposed_patch_1.patch\n", out)
        self.assertNotIn("proposed_patch_1.patch", self.bugzilla.attachments[high])
        _, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("proposed_patch_1.patch", self.bugzilla.attachments[high])

    def test_dry_run_shows_changes_to_existing_bugs(self):
        old = self.bugzilla.add("[ANT-2026-HIGH1] filed by hand")
        out, exit_message = self.main("--dry-run")
        self.dry_run_output(out)
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn(f"ANT-2026-HIGH1: bug {old}: block the new meta bug; attach", out)
        self.assertEqual(self.bugzilla.attachments[old], [])
        self.assertFalse((self.scan_dir / filer.LOG_NAME).exists())

    def test_existing_bug_in_another_group_is_left_alone(self):
        other = self.bugzilla.add("[ANT-2026-HIGH1] elsewhere", groups=("other",))
        out, exit_message = self.main()
        self.assertIn(f"ANT-2026-HIGH1: bug {other} (NOT in the security group sec",
                      out)
        self.assertIn("1 problem(s)", exit_message)
        self.assertEqual(self.bugzilla.attachments[other], [])
        self.assertEqual(self.bugzilla.bugs[other]["blocks"], [])

    def test_group_is_checked_again_before_uploading(self):
        old = self.bugzilla.add("[ANT-2026-HIGH1] filed by hand")
        real_ensure = self.bugzilla.ensure

        def ensure(bug_id, **wanted):
            self.bugzilla.bugs[old]["groups"] = []  # changed since the plan
            return real_ensure(bug_id, **wanted)

        with patch.object(self.bugzilla, "ensure", ensure):
            _, exit_message = self.main()
        self.assertIn("problem(s)", exit_message)
        self.assertEqual(self.bugzilla.attachments[old], [])

    # --- Symbolic links

    def test_symbolic_links_are_refused(self):
        secret = self.root / "secret"
        secret.write_text("private key\n")
        (self.finding / "repro.d").mkdir()
        (self.finding / "repro.d" / "key").symlink_to(secret)
        low = self.scan_dir / "already-public-upstream" / "ANT-2026-LOW1"
        (low / "patches" / "2.patch").symlink_to(secret)
        bug = self.scan_dir / "bugs-not-security" / "ANT-2026-BUG1"
        (bug / "repro").unlink()
        (bug / "repro").symlink_to(secret)
        with self.assertRaises(SystemExit) as cm:
            filer.load_findings(filer.load_scan(self.scan_dir))
        message = str(cm.exception)
        self.assertIn("ANT-2026-HIGH1: repro.d/key is a symbolic link", message)
        self.assertIn("ANT-2026-LOW1: patches/2.patch is a symbolic link", message)
        self.assertIn("ANT-2026-BUG1: repro is a symbolic link", message)

    def test_linked_directories_and_special_files_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "x").write_text("x")
        (self.finding / "repro.d").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "repro.d is a symbolic link"):
            filer.collect_attachments(self.finding, "TEST")
        (self.finding / "repro.d").unlink()
        (self.finding / "repro.d" / "sub").mkdir(parents=True)
        (self.finding / "repro.d" / "sub" / "link").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "repro.d/sub/link is a symbolic link"):
            filer.collect_attachments(self.finding, "TEST")
        (self.finding / "repro.d" / "sub" / "link").unlink()
        os.mkfifo(self.finding / "repro.d" / "fifo")
        with self.assertRaisesRegex(ValueError, "repro.d/fifo is not a regular file"):
            filer.collect_attachments(self.finding, "TEST")

    # --- Already public findings

    def write_upstream(self, text):
        report = self.scan_dir / "already-public-upstream" / "ANT-2026-LOW1" / "REPORT.md"
        report.write_text(report.read_text() + text)

    def test_upstream_bugs(self):
        self.assertEqual(filer.upstream_bugs("x\n" + UPSTREAM), [5000])
        self.assertEqual(filer.upstream_bugs(
            "Already public upstream. See https://bugzilla.mozilla.org/show_bug.cgi?id=12345"
            " and bug 67890.\n"), [12345, 67890])
        self.assertEqual(filer.upstream_bugs("Bug 5000 elsewhere.\n"), [])

    def test_already_public_finding_blocks_its_upstream_bug(self):
        self.write_upstream(UPSTREAM)
        self.bugzilla.visible[5000] = {"id": 5000}
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("ANT-2026-LOW1: will also block its upstream bug 5000", out)
        meta = self.bugzilla.by_summary("[example-20260101-001]")["id"]
        self.assertEqual(self.bugzilla.by_summary("[ANT-2026-LOW1]")["blocks"],
                         [meta, 5000])
        self.assertEqual(self.bugzilla.by_summary("[ANT-2026-HIGH1]")["blocks"], [meta])
        self.assertNotIn("Warning", out)

    def test_unreadable_upstream_bug_is_not_linked(self):
        self.write_upstream(UPSTREAM)
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("Warning: ANT-2026-LOW1: its upstream bug 5000 cannot be read",
                      out)
        meta = self.bugzilla.by_summary("[example-20260101-001]")["id"]
        self.assertEqual(self.bugzilla.by_summary("[ANT-2026-LOW1]")["blocks"], [meta])

    def test_several_upstream_bugs_are_not_guessed(self):
        self.write_upstream("\nAlready public upstream. Bug 11111 or bug 22222.\n")
        out, _ = self.main()
        self.assertIn("ANT-2026-LOW1 is already public, but its report names "
                      "11111, 22222: link its bug to the upstream one by hand", out)

    # --- The scan's counts

    def test_counts_must_match_the_readme(self):
        self.make_finding("ANT-2026-EXTRA", "high")
        self.make_finding("ANT-2026-ODD", "low", "unlisted")
        (self.scan_dir / "bugs-not-security" / "ANT-2026-BUG1" / "REPORT.md").unlink()
        with self.assertRaises(SystemExit) as cm:
            filer.load_findings(filer.load_scan(self.scan_dir))
        message = str(cm.exception)
        self.assertIn("README.md says 1 vulnerabilities at the top level, there are 2",
                      message)
        self.assertIn("README.md says 1 findings in bugs-not-security/, there are 0",
                      message)
        self.assertIn("unlisted/: 1 finding(s) README.md does not list", message)

    # --- Requests

    def http_error(self, code, body=b'{"message": "nope"}', headers=None):
        return urllib.error.HTTPError("https://bmo.example/rest/x", code, "error",
                                      headers or {}, io.BytesIO(body))

    def response(self, body=b'{"ok": 1}'):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = body
        return response

    def client(self):
        bugzilla = filer.Bugzilla("https://bmo.example", "key")
        bugzilla.sleep = MagicMock()
        return bugzilla

    def test_lookups_are_retried_after_network_errors(self):
        bugzilla = self.client()
        answers = [TimeoutError("timed out"), http.client.RemoteDisconnected("gone"),
                   self.http_error(502), self.response()]
        with patch("urllib.request.urlopen", side_effect=answers), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bugzilla.request("GET", "bug/1"), {"ok": 1})
        self.assertEqual([c.args[0] for c in bugzilla.sleep.call_args_list], [5, 10, 20])

    def test_unanswered_post_is_not_retried(self):
        bugzilla = self.client()
        for error in (TimeoutError("timed out"), ConnectionResetError("reset"),
                      self.http_error(504)):
            with self.subTest(error=error):
                with patch("urllib.request.urlopen", side_effect=[error]) as urlopen:
                    with self.assertRaises(filer.BugzillaError) as cm:
                        bugzilla.request("POST", "bug", {})
                self.assertTrue(cm.exception.outcome_unknown)
                self.assertEqual(urlopen.call_count, 1)
        bugzilla.sleep.assert_not_called()

    def test_refused_request_is_not_retried(self):
        bugzilla = self.client()
        with patch("urllib.request.urlopen", side_effect=[self.http_error(400)]):
            with self.assertRaises(filer.BugzillaError) as cm:
                bugzilla.request("GET", "bug/1")
        self.assertEqual(cm.exception.code, 400)
        self.assertFalse(cm.exception.outcome_unknown)
        self.assertIn("HTTP 400: nope", str(cm.exception))

    def test_rate_limited_requests_wait_for_retry_after(self):
        bugzilla = self.client()
        answers = [self.http_error(429, headers={"Retry-After": "7"}),
                   self.http_error(429), self.response()]
        with patch("urllib.request.urlopen", side_effect=answers), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bugzilla.request("POST", "bug", {}), {"ok": 1})
        self.assertEqual([c.args[0] for c in bugzilla.sleep.call_args_list], [7, 30])

    def test_too_long_retry_after_stops(self):
        bugzilla = self.client()
        answers = [self.http_error(429, headers={"Retry-After": "3600"})]
        with patch("urllib.request.urlopen", side_effect=answers):
            with self.assertRaisesRegex(filer.BugzillaError, "asks to wait 3600 s"):
                bugzilla.request("POST", "bug", {})
        bugzilla.sleep.assert_not_called()

    def test_retry_after_date(self):
        later = filer.now() + filer.timedelta(seconds=60)
        delay = filer.parse_retry_after(email.utils.format_datetime(later, usegmt=True))
        self.assertTrue(55 <= delay <= 61, delay)
        self.assertIsNone(filer.parse_retry_after("soon"))

    def test_answer_that_is_not_json(self):
        bugzilla = self.client()
        with patch("urllib.request.urlopen",
                   side_effect=[self.response(b"<html>proxy</html>")]):
            with self.assertRaisesRegex(filer.BugzillaError, "not JSON"):
                bugzilla.request("POST", "bug", {})

    def test_unanswered_upload_is_checked_before_retrying(self):
        bugzilla = self.client()
        attachment = filer.make_attachment("a.txt", "a", b"data")
        with patch.object(bugzilla, "attach",
                          side_effect=filer.BugzillaError("timed out")) as attach, \
                patch.object(bugzilla, "request", return_value={
                    "bugs": {"7": [{"file_name": "a.txt", "size": 4}]}}), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(bugzilla.attach_with_retry(7, attachment))
        self.assertEqual(attach.call_count, 1)

    # --- The audit log

    def log_text(self):
        return (self.scan_dir / filer.LOG_NAME).read_text()

    def test_runs_are_logged(self):
        self.main()
        log = self.log_text()
        self.assertTrue(log.startswith("# Audit log of file_bmo_bug.py"))
        events = [line.split()[1:3] for line in log.splitlines()
                  if not line.startswith("#")]
        self.assertEqual(events[:4], [["run", "example-20260101-001"],
                                      ["creating", "example-20260101-001"],
                                      ["filed", "example-20260101-001"],
                                      ["creating", "ANT-2026-HIGH1"]])
        self.assertIn(["attached", "ANT-2026-BUG1"], events)
        self.assertEqual(events[-1], ["done", "example-20260101-001"])
        self.assertRegex(log, r"\n\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  filed      "
                              r"ANT-2026-HIGH1  bug 102 https://")

    def test_logged_bug_is_not_filed_again_when_search_misses_it(self):
        self.main()
        self.bugzilla.hidden_from_search = set(self.bugzilla.bugs)
        out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.prompt.assert_not_called()
        self.assertEqual(len(self.bugzilla.bugs), 4)
        self.assertIn("Already filed, nothing to change: 3", out)

    def test_logged_bug_that_cannot_be_read_stops_the_run(self):
        self.main()
        del self.bugzilla.bugs[102]
        _, exit_message = self.main()
        self.assertIn("says bug 102 was filed for ANT-2026-HIGH1, but it cannot be read",
                      exit_message)

    def test_unanswered_filing_waits_before_filing_again(self):
        self.bugzilla.fail_create = filer.BugzillaError("timed out")
        _, exit_message = self.main()
        self.assertIn("Bugzilla did not say whether it filed", exit_message)
        self.assertIn("creating   example-20260101-001", self.log_text())
        self.bugzilla.fail_create = None
        _, exit_message = self.main()
        self.assertIn("no bug for it can be found yet", exit_message)
        self.assertEqual(self.bugzilla.bugs, {})
        later = filer.now() + filer.PENDING_GRACE + filer.timedelta(minutes=1)
        with patch.object(filer, "now", return_value=later):
            out, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertIn("Meta bug: to file (again: an earlier try left no bug)", out)
        self.assertEqual(len(self.bugzilla.bugs), 4)

    def test_unanswered_filing_that_went_through_is_found(self):
        real_create = self.bugzilla.create_bug

        def create(payload):
            real_create(payload)
            raise filer.BugzillaError("timed out")

        with patch.object(self.bugzilla, "create_bug", create):
            self.main()
        self.assertEqual(len(self.bugzilla.bugs), 1)
        _, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertEqual(len(self.bugzilla.bugs), 4)
        self.assertIn("filed      example-20260101-001  bug 101 (found in Bugzilla)",
                      self.log_text())

    def test_refused_filing_can_be_retried_at_once(self):
        self.bugzilla.fail_create = filer.BugzillaError("HTTP 400: bad", 400)
        _, exit_message = self.main()
        self.assertIn("Unable to file", exit_message)
        self.assertIn("not-filed  example-20260101-001", self.log_text())
        self.bugzilla.fail_create = None
        _, exit_message = self.main()
        self.assertIsNone(exit_message, self.stderr)
        self.assertEqual(len(self.bugzilla.bugs), 4)

    def test_log_is_locked_while_in_use(self):
        path = self.scan_dir / filer.LOG_NAME
        log = filer.AuditLog.open(path)
        self.addCleanup(log.close)
        with self.assertRaises(SystemExit) as cm:
            filer.AuditLog.open(path)
        self.assertIn("is locked: another run", str(cm.exception))
        self.assertEqual(filer.AuditLog.open(path, writable=False).records, {})

    def test_damaged_log_stops_the_run(self):
        (self.scan_dir / filer.LOG_NAME).write_text(
            "2026-11-06T10:00:00Z  filed  ANT-2026-HIGH1  oops\n")
        _, exit_message = self.main()
        self.assertIn(f"{filer.LOG_NAME}:1: no \"bug <id>\"", exit_message)

    # --- Masked API key prompt

    def test_key_masker(self):
        masker = filer.KeyMasker()
        self.assertEqual(masker.feed("abc"), "***")
        self.assertEqual(masker.feed("\x7f"), "\b \b")
        self.assertEqual(masker.feed("\x1b[D"), "")  # left arrow: ignored
        self.assertEqual(masker.feed("d\nignored"), "*")
        self.assertTrue(masker.done)
        self.assertEqual(masker.text, "abd")
        masker = filer.KeyMasker()
        masker.feed("xy\x15z\r")
        self.assertEqual(masker.text, "z")
        masker = filer.KeyMasker()
        masker.feed("\x04")
        self.assertTrue(masker.eof)

    def test_read_masked_on_a_terminal(self):
        import pty
        import termios
        controller, terminal = pty.openpty()
        self.addCleanup(os.close, controller)
        self.addCleanup(os.close, terminal)
        before = termios.tcgetattr(terminal)
        os.write(controller, b"secret-key\n")
        echo = io.StringIO()
        self.assertEqual(filer.read_masked("Key: ", fd=terminal, echo=echo),
                         "secret-key")
        self.assertEqual(echo.getvalue(), "Key: " + "*" * 10 + "\n")
        self.assertEqual(termios.tcgetattr(terminal), before)

    def test_api_key_is_kept_out_of_errors(self):
        bugzilla = filer.Bugzilla("https://bmo.example", "sekrit")
        error = self.http_error(400, b'{"message": "bad key sekrit"}')
        with patch("urllib.request.urlopen", side_effect=[error]):
            with self.assertRaises(filer.BugzillaError) as cm:
                bugzilla.request("GET", "whoami")
        self.assertIn("bad key ***", str(cm.exception))
        self.assertNotIn("sekrit", str(cm.exception))

    # --- Progress output

    def test_progress_is_shown(self):
        out, _ = self.main()
        self.assertIn("Reading the findings of scan example-20260101-001", self.stderr)
        self.assertIn("Read 3 finding(s) with 9 attachment(s)", self.stderr)
        self.assertIn("Audit log: ", self.stderr)
        self.assertIn(f"Checking the API key with {filer.DEFAULT_BUGZILLA_URL} ...",
                      self.stderr)
        self.assertIn("Looking for existing bugs (4) ...", self.stderr)
        self.assertRegex(out, r"\[1/4\] Filing \[example-20260101-001\] .* \.\.\. filed "
                              + re.escape(filer.DEFAULT_BUGZILLA_URL)
                              + r"/show_bug.cgi\?id=101 \(\d+\.\d s\)\n")
        self.assertRegex(out, r"\[4/4\] Filing \[ANT-2026-BUG1\]")
        self.assertRegex(out, r"\n  attaching ANT-2026-HIGH1-reproducer.zip "
                              r"\(\d+(\.\d)? (bytes|KB)\) \.\.\. done \(\d+\.\d s\)\n")
        self.assertRegex(out, r"Filed 3 bug\(s\), updated 0 existing one\(s\) in \d+ s")

    def test_open_step_is_ended_by_other_messages(self):
        output = filer.Output()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            output.step("attaching x")
            output.status("HTTP 502; retrying in 5 s")
            output.done()
        self.assertRegex(stdout.getvalue(),
                         r"^attaching x \.\.\. \nattaching x \.\.\. done \(\d+\.\d s\)\n$")
        self.assertEqual(stderr.getvalue(), "HTTP 502; retrying in 5 s\n")

    def test_human_size(self):
        self.assertEqual([filer.human_size(n) for n in (5, 2048, 3 * 1024 * 1024)],
                         ["5 bytes", "2.0 KB", "3.0 MB"])



if __name__ == "__main__":
    unittest.main()
