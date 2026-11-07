#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""File the findings of an OSS-scanner scan as security bugs on Bugzilla.

Usage: file_bmo_bug.py --meta-bug <bug id> [--dry-run] [--limit N] <scan directory>

The scan directory is the root of a scan: its README.md starts
"# <project> — findings of scan <scan-id>" and gives the number of findings
at the top level and in each subdirectory it lists (already-public-upstream/,
bugs-not-security/, ...). Nothing is done unless the findings found match
those numbers. One run files

  * the scan's meta bug, "[<scan-id>] ...", which blocks the --meta-bug bug
    (the overall oss-scanner meta bug),
    unless a bug with "[<scan-id>]" in its summary already exists, and
  * a bug for every finding below the directory (every REPORT.md), blocking
    the scan's meta bug, unless a bug with "[<finding-id>]" in its summary
    already exists. Such a bug is skipped, but made to block the meta bug and
    given any of its attachments that are missing, so a run that stopped
    partway can simply be run again. Existing bugs that are not in the
    security group are left alone.

A finding in the "Already public upstream" subdirectory whose report names
one upstream bug ("Already public upstream. ... Bug 1234567 ...") is also
made to block that bug, so the two are easy to compare.

Each finding's bug gets its REPORT.md as the description, without the
"Reproducing" and "Running the reproducer" sections, and as attachments the
full REPORT.md as <id>-ORIGINAL-REPORT.md, each patch in patches/ as
proposed_patch_<n>.patch, and `repro` with `repro.d/` zipped together.
Symbolic links and other special files in a finding are refused, not read.

The bugs are filed in the product, component and version of the --meta-bug
bug, in the product's default security group: there is no way to file one
publicly. Findings rated critical/high/medium/low in their report header get
sec-critical/sec-high/sec-moderate/sec-low; any others get sec-other.

--limit N files at most N new finding bugs (the scan's meta bug, if it is
still to be filed, does not count); run again to file the next ones.

The Bugzilla API key is read from $BUGZILLA_API_KEY, or asked for. The plan
-- the bugs to file and every change to existing bugs -- is shown, and
confirmed, before anything is changed.

Audit log: everything a run does is recorded in bmo-filing.log in the scan
directory, one line per event. The script also reads it back: a bug the log
records as filed is never filed again, even if Bugzilla's search does not
show it (yet), and a filing that Bugzilla did not answer is not tried again
until PENDING_GRACE has passed without the bug turning up.

Run only one copy at a time for a scan. The log is locked while a run uses
it, but that only covers this copy of the scan directory: two runs from
different copies or machines can each file every finding.

Requests that Bugzilla rate-limits (HTTP 429) are retried after the delay
it asks for; lookups are also retried after network errors and 5xx answers.
"""

import argparse
import base64
import email.utils
import errno
import fcntl
import getpass
import http.client
import io
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024
MAX_COMMENT_LENGTH = 65535

DEFAULT_BUGZILLA_URL = "https://bugzilla.mozilla.org"
API_KEY_VARIABLE = "BUGZILLA_API_KEY"

REQUEST_TIMEOUT = 300
# Retries of a request Bugzilla refused with HTTP 429, and the longest wait
# (in seconds) between them; a longer Retry-After stops the run instead.
RATE_LIMIT_RETRIES = 10
MAX_RETRY_WAIT = 600
# Retries of a lookup or update (GET, PUT) after a network error or a 5xx.
TRANSIENT_RETRIES = 3

# Findings looked up per Bugzilla search, and the most results one may have.
SEARCH_BATCH = 40
SEARCH_LIMIT = 500

LOG_NAME = "bmo-filing.log"
# How long a filing Bugzilla did not answer blocks filing that finding again.
PENDING_GRACE = timedelta(minutes=15)

# The severity in a report's header ("ANT-2026-XXXX  [high] ...") is its
# rating. Findings with any other severity (e.g. "NOT SECURITY: ordinary
# bug") are still filed in the security group, tagged UNRATED_KEYWORDS.
RATING_KEYWORDS = {
    "critical": ["sec-critical"],
    "high": ["sec-high"],
    "medium": ["sec-moderate"],
    "low": ["sec-low"],
}
UNRATED_KEYWORDS = ["sec-other"]
BUG_DEFAULTS = {"type": "defect", "platform": "Unspecified", "op_sys": "Unspecified"}

SKIPPED_DIRS = {"repro.d", "patches", "node_modules", "__pycache__"}

# The README group whose findings are already public upstream.
ALREADY_PUBLIC = "Already public upstream"


def now():
    return datetime.now(timezone.utc)


# --- Output -----------------------------------------------------------------


class Output:
    """What the user sees: the plan and the results on stdout, progress and
    problems on stderr (so that the plan can be saved on its own).

    A step ("Filing ... ", "attaching ... ") stays open on its line until it
    is done, so a slow request shows what is being waited for; anything else
    printed meanwhile starts a new line.
    """

    def __init__(self):
        self.open = False
        self.step_message = None
        self.step_started = 0.0

    def _close(self):
        if self.open:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self.open = False

    def say(self, message=""):
        self._close()
        print(message, flush=True)

    def status(self, message):
        self._close()
        print(message, file=sys.stderr, flush=True)

    def step(self, message):
        self._close()
        sys.stdout.write(f"{message} ... ")
        sys.stdout.flush()
        self.open, self.step_message, self.step_started = True, message, time.monotonic()

    def done(self, result="done"):
        took = f"{result} ({time.monotonic() - self.step_started:.1f} s)"
        if self.open:
            sys.stdout.write(took + "\n")
            sys.stdout.flush()
            self.open = False
        else:
            print(f"{self.step_message} ... {took}", flush=True)

    def progress(self, label, total):
        """A callback(done, total) showing a counter on a terminal; elsewhere
        only the label is shown, once."""
        if not sys.stderr.isatty():
            self.status(f"{label} ({total}) ...")
            return lambda done, total: None
        self._close()

        def progress(done, total):
            print(f"\r{label}: {done}/{total}", end="\n" if done == total else "",
                  file=sys.stderr, flush=True)
        progress(0, total)
        return progress


out = Output()


def human_size(size):
    for unit in ("bytes", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{size} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024


def find_findings(root):
    """The directories below root that hold a REPORT.md, sorted by path."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if not d.startswith(".") and d not in SKIPPED_DIRS
        )
        if "REPORT.md" in filenames and Path(dirpath) != root:
            found.append(Path(dirpath))
            dirnames[:] = []
    return sorted(found)


def parse_report(text):
    """(id, severity, title) from the report header; severity is lower case."""
    m = re.search(r"^(ANT-\d{4}-[A-Z0-9]+)[ \t]+\[([^\]\n]*)\][^\n]*\n([^\n]+)$",
                  text, re.M)
    if not m:
        raise ValueError("no id, severity and title in the report header")
    return m[1], m[2].strip().lower(), m[3].strip()


UPSTREAM_PARAGRAPH_RE = re.compile(r"^Already public upstream\..*?(?=\n[ \t]*\n|\Z)",
                                   re.M | re.S)
UPSTREAM_BUG_RE = re.compile(
    r"\bbug[ \t]+(\d{4,9})\b|show_bug\.cgi\?id=(\d+)|bugzilla\.mozilla\.org/(\d+)\b",
    re.I)


def upstream_bugs(text):
    """The bugs named in the report's "Already public upstream." paragraph."""
    paragraph = UPSTREAM_PARAGRAPH_RE.search(text)
    ids = []
    for m in UPSTREAM_BUG_RE.finditer(paragraph[0] if paragraph else ""):
        bug_id = int(next(group for group in m.groups() if group))
        if bug_id not in ids:
            ids.append(bug_id)
    return ids


# --- Scans ------------------------------------------------------------------

SCAN_TITLE_RE = re.compile(r"\A# (?P<project>.+?) — findings of scan (?P<scan>\S+)\n")
SCAN_COMMIT_RE = re.compile(
    r"^(?P<repo>\S+) at commit `(?P<commit>[0-9a-f]+)` · (?P<count>\d+) finding",
    re.M,
)
SCAN_GROUP_RE = re.compile(
    r"^## (?P<title>[^:\n]+): (?P<count>\d+) [^\n]*?\bin \[(?P<dir>[^\]/\n]+)/?\]",
    re.M)


def parse_scan(text):
    """The header of a scan's top-level README, or None if it is not one."""
    title = SCAN_TITLE_RE.match(text)
    commit = SCAN_COMMIT_RE.search(text)
    if not title or not commit:
        return None
    groups = [{"title": m["title"], "count": int(m["count"]), "dir": m["dir"]}
              for m in SCAN_GROUP_RE.finditer(text)]
    return {
        "project": title["project"],
        "id": title["scan"],
        "repo": commit["repo"],
        "commit": commit["commit"],
        "count": int(commit["count"]),
        "groups": groups,
        "counts": [("Vulnerabilities", int(commit["count"]))]
                  + [(g["title"], g["count"]) for g in groups],
    }


def load_scan(root):
    """The scan whose root directory is root; exits if it is not one."""
    root = Path(root).expanduser().resolve()
    readme = root / "README.md"
    scan = parse_scan(readme.read_text()) if readme.is_file() else None
    if not scan:
        sys.exit(f"{root} is not the root of a scan: its README.md must start "
                 "\"# <project> — findings of scan <scan-id>\"")
    return {**scan, "root": root}


def scan_meta_summary(scan):
    return f"[{scan['id']}] oss-scanner findings in {scan['project']}"


def scan_meta_description(scan):
    lines = [
        f"Meta bug for the findings of the oss-scanner scan {scan['id']} "
        f"of {scan['project']}.",
        "",
        f"Repository: {scan['repo']}",
        f"Commit: {scan['commit']}",
    ]
    lines += [f"{title}: {count}" for title, count in scan["counts"]]
    lines += ["", "The bugs filed for these findings block this bug."]
    return "\n".join(lines) + "\n"


def split_sections(text):
    parts = re.split(r"(?m)^(?=## )", text)
    return [(p.split("\n", 1)[0][3:].strip() if p.startswith("## ") else None, p)
            for p in parts]


# Sections of the report left out of the bug's description. The full report
# is attached to the bug.
OMITTED_SECTIONS = ("Reproducing", "Running the reproducer")
TEXT_SUFFIXES = {".md", ".patch", ".diff", ".txt"}


def build_description(text):
    """The report, verbatim, without the sections in OMITTED_SECTIONS."""
    sections = [section for title, section in split_sections(text)
                if title not in OMITTED_SECTIONS]
    return "".join(sections).rstrip() + "\n"


def content_type_for(name):
    suffix = Path(name).suffix.lower()
    if suffix == ".zip":
        return "application/zip"
    if suffix in TEXT_SUFFIXES:
        return "text/plain"
    return "application/octet-stream"


# --- Attachments ------------------------------------------------------------


def read_file(path, finding):
    """The contents of path, which must be a regular file and not a symbolic
    link: the scan directory is not trusted to point only at itself."""
    where = path.relative_to(finding).as_posix()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError(f"{where} is a symbolic link: refusing to read it") from None
        raise
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError(f"{where} is not a regular file: refusing to read it")
        return f.read()


def is_real_dir(path, finding):
    """Whether path is a directory; a symbolic link is an error."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(mode):
        raise ValueError(f"{path.relative_to(finding).as_posix()} is a symbolic link: "
                         "refusing to read it")
    return stat.S_ISDIR(mode)


def zip_files(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in files:
            z.writestr(name, data)
    return buffer.getvalue()


def make_attachment(name, summary, data, is_patch=False):
    """Prepare an upload, compressing oversized files and enforcing the limit."""
    content_type = content_type_for(name)
    if len(data) > MAX_ATTACHMENT_SIZE and content_type != "application/zip":
        data = zip_files([(name, data)])
        name += ".zip"
        content_type = "application/zip"
        is_patch = False
    if len(data) > MAX_ATTACHMENT_SIZE:
        out.status(f"warning: {name} is too large ({len(data)} bytes) and is not "
                   "attached")
        return None
    return {
        "file_name": name,
        "summary": summary if len(summary) <= 250 else summary[:249] + "…",
        "content_type": content_type,
        "is_patch": is_patch,
        "data": data,
    }


def _natural_key(path):
    return [int(part) if part.isdigit() else part
            for part in re.split(r"(\d+)", path.name)]


def reproducer_files(finding):
    """(name, data) of `repro` and every file below `repro.d/`, sorted."""
    files = []
    if os.path.lexists(finding / "repro"):
        files.append(("repro", read_file(finding / "repro", finding)))
    reprod = finding / "repro.d"
    if not is_real_dir(reprod, finding):
        return files
    found = []
    for dirpath, dirnames, filenames in os.walk(reprod):
        for name in dirnames:
            is_real_dir(Path(dirpath) / name, finding)
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        found += [Path(dirpath) / name for name in filenames]
    for path in sorted(found):
        files.append((path.relative_to(finding).as_posix(), read_file(path, finding)))
    return files


def collect_attachments(finding, ident):
    """The attachments of a finding's bug, in upload order:

    * the full REPORT.md, as <id>-ORIGINAL-REPORT.md,
    * each file of patches/, as proposed_patch_<n>.patch (in natural order),
    * `repro` and `repro.d/` zipped together, unchanged, keeping their layout.

    Raises ValueError for a symbolic link or special file.
    """
    files = [(f"{ident}-ORIGINAL-REPORT.md", f"Full report of {ident}",
              read_file(finding / "REPORT.md", finding), False)]

    patches = finding / "patches"
    if is_real_dir(patches, finding):
        paths = sorted((p for p in patches.iterdir() if not is_real_dir(p, finding)),
                       key=_natural_key)
        for n, path in enumerate(paths, 1):
            files.append((f"proposed_patch_{n}{path.suffix or '.patch'}",
                          f"Proposed patch {n} for {ident} (patches/{path.name})",
                          read_file(path, finding), True))

    reproducer = reproducer_files(finding)
    if reproducer:
        files.append((f"{ident}-reproducer.zip",
                      "Reproducer: " + ", ".join(n for n, _ in reproducer),
                      zip_files(reproducer), False))

    attachments = [make_attachment(*f) for f in files]
    return [a for a in attachments if a]


# --- Bugzilla ---------------------------------------------------------------


class BugzillaError(RuntimeError):
    """A failed request. code is the HTTP status, or None if there was no
    answer (a network error or timeout): the request may have been carried out.
    """

    def __init__(self, message, code=None, retry_after=None):
        super().__init__(message)
        self.code = code
        self.retry_after = retry_after

    @property
    def outcome_unknown(self):
        """Whether the request may have been carried out all the same."""
        return self.code is None or self.code >= 500


def parse_retry_after(value):
    """A Retry-After header (seconds or an HTTP date) in seconds, or None."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return int(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((when - now()).total_seconds()) + 1)


class Bugzilla:
    def __init__(self, url, api_key):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.sleep = time.sleep

    def request(self, method, path, payload=None):
        """Send a request, retrying it where that is safe:

        * after HTTP 429, which Bugzilla sends without doing anything, once
          the Retry-After delay has passed;
        * GET and PUT (which here only add values to lists) after a network
          error or a 5xx, which may or may not have been carried out.

        A POST that may have been carried out is left to the caller.
        """
        rate_limited = transient = 0
        while True:
            try:
                return self._send(method, path, payload)
            except BugzillaError as e:
                if e.code == 429 and rate_limited < RATE_LIMIT_RETRIES:
                    rate_limited += 1
                    delay = e.retry_after if e.retry_after is not None else 30
                elif (method != "POST" and e.outcome_unknown
                      and transient < TRANSIENT_RETRIES):
                    transient += 1
                    delay = (e.retry_after if e.retry_after is not None
                             else 5 * 2 ** (transient - 1))
                else:
                    raise
                if delay > MAX_RETRY_WAIT:
                    raise BugzillaError(f"{e} (Bugzilla asks to wait {delay} s; "
                                        "try again later)", e.code) from e
                out.status(f"{e}; retrying in {delay} s")
                self.sleep(delay)

    def _send(self, method, path, payload=None):
        headers = {
            "Accept": "application/json",
            "User-Agent": "oss-scanner-filer/1.0",
        }
        if self.api_key:
            headers["X-BUGZILLA-API-KEY"] = self.api_key
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.url}/rest/{path}", data=data,
                                     method=method, headers=headers)
        what = f"Bugzilla {method} {path.split('?', 1)[0]}"
        try:
            return self._answer(what, req)
        except BugzillaError as e:
            if self.api_key and self.api_key in str(e):
                raise BugzillaError(str(e).replace(self.api_key, "***"), e.code,
                                    e.retry_after) from None
            raise

    def _answer(self, what, req):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
                body = response.read()
        except urllib.error.HTTPError as e:
            try:
                message = e.read().decode("utf-8", "replace")
                message = json.loads(message).get("message", message)
            except (OSError, http.client.HTTPException, ValueError, AttributeError):
                message = e.reason
            raise BugzillaError(f"{what}: HTTP {e.code}: {message}", e.code,
                                parse_retry_after(e.headers.get("Retry-After")
                                                  if e.headers else None)) from e
        except urllib.error.URLError as e:
            raise BugzillaError(f"{what}: {e.reason}") from e
        except (OSError, http.client.HTTPException) as e:
            raise BugzillaError(f"{what}: {e!r}") from e
        try:
            result = json.loads(body)
        except ValueError as e:
            raise BugzillaError(f"{what}: the answer is not JSON") from e
        if isinstance(result, dict) and result.get("error"):
            raise BugzillaError(f"{what}: {result.get('message', result)}", 400)
        return result

    def whoami(self):
        result = self.request("GET", "whoami")
        return result.get("login") or result.get("name") or str(result.get("id"))

    def default_security_group(self, product):
        result = self.request(
            "GET",
            f"product?names={urllib.parse.quote(product)}"
            "&include_fields=default_security_group",
        )
        products = result.get("products") or [{}]
        return products[0].get("default_security_group")

    def create_bug(self, payload):
        return self.request("POST", "bug", payload)["id"]

    def find_bugs(self, substrings, progress=None):
        """{substring: [bugs (id, summary, blocks, groups) whose summary has it]}.

        Looks for SEARCH_BATCH substrings per search. Only bugs this user can
        see are found.
        """
        found = {s: [] for s in substrings}
        for start in range(0, len(substrings), SEARCH_BATCH):
            batch = substrings[start:start + SEARCH_BATCH]
            params = [("include_fields", "id,summary,blocks,groups"),
                      ("limit", SEARCH_LIMIT), ("j_top", "OR")]
            # Repeated "summary" parameters would be ANDed: use one
            # "substring" condition per string, ORed together.
            for n, text in enumerate(batch, 1):
                params += [(f"f{n}", "short_desc"), (f"o{n}", "substring"),
                           (f"v{n}", text)]
            bugs = self.request("GET", "bug?" + urllib.parse.urlencode(params))
            bugs = bugs.get("bugs", [])
            if len(bugs) >= SEARCH_LIMIT:
                raise BugzillaError(f"Bugzilla search: {len(bugs)} results, "
                                    "some may be missing", 400)
            for bug in bugs:
                # The server's match ignores case; keep exact matches only.
                for text in batch:
                    if text in bug.get("summary", ""):
                        found[text].append(bug)
            if progress:
                progress(min(start + SEARCH_BATCH, len(substrings)), len(substrings))
        return found

    def get_bug(self, bug_id, fields):
        return self.request(
            "GET", f"bug/{bug_id}?include_fields={','.join(fields)}"
        )["bugs"][0]

    def ensure(self, bug_id, **wanted):
        """Add the missing values of list fields (groups, blocks, keywords).

        Bug creation silently drops some fields for users without editbugs.
        Returns {field: [values still missing]} after trying to add them.
        """
        wanted = {field: values for field, values in wanted.items() if values}
        if not wanted:
            return {}

        def missing():
            bug = self.get_bug(bug_id, wanted)
            result = {}
            for field, values in wanted.items():
                absent = [v for v in values if v not in bug.get(field, [])]
                if absent:
                    result[field] = absent
            return result

        absent = missing()
        if absent:
            self.request("PUT", f"bug/{bug_id}",
                         {field: {"add": values} for field, values in absent.items()})
            absent = missing()
        return absent

    def missing_attachments(self, bug_id, attachments):
        """The attachments the bug has none of (same file name and size)."""
        result = self.request(
            "GET", f"bug/{bug_id}/attachment?include_fields=file_name,size"
        )
        present = {(a["file_name"], a["size"]) for a in result["bugs"][str(bug_id)]}
        return [a for a in attachments
                if (a["file_name"], len(a["data"])) not in present]

    def has_attachment(self, bug_id, attachment):
        return not self.missing_attachments(bug_id, [attachment])

    def attach_with_retry(self, bug_id, attachment, retries=2):
        # An upload without an answer may still have gone through: look
        # before trying again.
        for attempt in range(retries + 1):
            try:
                return self.attach(bug_id, attachment)
            except BugzillaError as e:
                if not e.outcome_unknown or attempt == retries:
                    raise
                out.status(f"  {e}; checking whether it was attached")
                self.sleep(5 * (attempt + 1))
                if self.has_attachment(bug_id, attachment):
                    return None

    def attach(self, bug_id, attachment):
        payload = {
            "ids": [bug_id],
            "file_name": attachment["file_name"],
            "summary": attachment["summary"],
            "content_type": attachment["content_type"],
            "is_patch": attachment.get("is_patch", False),
            "data": base64.b64encode(attachment["data"]).decode(),
        }
        return self.request("POST", f"bug/{bug_id}/attachment", payload)


class KeyMasker:
    """The keys typed at a masked prompt: feed() takes what was typed and
    returns what to echo, a * for each character."""

    def __init__(self):
        self.chars = []
        self.done = False
        self.eof = False
        self._escape = False

    @property
    def text(self):
        return "".join(self.chars)

    def feed(self, typed):
        echo = []
        for ch in typed:
            if self.done:
                break
            if self._escape:  # arrow keys and the like: ESC [ ... <letter or ~>
                self._escape = not (ch.isalpha() or ch == "~")
            elif ch == "\x1b":
                self._escape = True
            elif ch in "\r\n":
                self.done = True
            elif ch in "\x7f\x08":  # backspace
                if self.chars:
                    self.chars.pop()
                    echo.append("\b \b")
            elif ch == "\x15":  # Ctrl-U
                echo.append("\b \b" * len(self.chars))
                self.chars.clear()
            elif ch == "\x04":  # Ctrl-D
                if not self.chars:
                    self.done = self.eof = True
            elif ch >= " ":
                self.chars.append(ch)
                echo.append("*")
        return "".join(echo)


def read_masked(prompt, fd=None, echo=None):
    """A line read from the terminal, showing a * for each character typed.
    Ctrl-C raises KeyboardInterrupt, Ctrl-D on an empty line EOFError."""
    fd = sys.stdin.fileno() if fd is None else fd
    echo = sys.stderr if echo is None else echo
    try:
        import termios
    except ImportError:  # not a Unix system
        return getpass.getpass(prompt)
    try:
        old = termios.tcgetattr(fd)
    except termios.error:  # not a terminal after all
        return getpass.getpass(prompt)
    new = termios.tcgetattr(fd)
    new[3] &= ~(termios.ECHO | termios.ICANON)  # keep ISIG: Ctrl-C still works
    new[6][termios.VMIN], new[6][termios.VTIME] = 1, 0
    masker = KeyMasker()
    echo.write(prompt)
    echo.flush()
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        while not masker.done:
            data = os.read(fd, 1024)
            if not data:
                raise EOFError
            echo.write(masker.feed(data.decode("utf-8", "replace")))
            echo.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        echo.write("\n")
        echo.flush()
    if masker.eof:
        raise EOFError
    return masker.text


def api_key(url):
    """The API key from $BUGZILLA_API_KEY, or asked for on the terminal."""
    key = os.environ.get(API_KEY_VARIABLE, "").strip()
    if key:
        out.status(f"Using the API key in ${API_KEY_VARIABLE} (***)")
        return key
    page = f"{url}/userprefs.cgi?tab=apikey"
    if not sys.stdin.isatty():
        sys.exit(f"Set {API_KEY_VARIABLE} to a Bugzilla API key; "
                 f"you can create one at {page}")
    out.status(f"{API_KEY_VARIABLE} is not set. Create an API key at\n  {page}\n"
               f"and paste it below (or set {API_KEY_VARIABLE} to skip this).")
    try:
        key = read_masked("Bugzilla API key: ").strip()
    except (EOFError, KeyboardInterrupt):
        key = ""
    if not key:
        sys.exit("No API key given")
    return key


def finding_rating(severity):
    """The rating of a finding (its header's severity), or None if unrated."""
    return severity if severity in RATING_KEYWORDS else None


def bug_keywords(severity):
    rating = finding_rating(severity)
    return list(RATING_KEYWORDS[rating] if rating else UNRATED_KEYWORDS)


def base_payload(target, summary, description, keywords, blocks):
    """A bug to create. It is always restricted to a security group."""
    if not target.get("group"):
        raise ValueError("a security group is required")
    payload = {
        "product": target["product"],
        "component": target["component"],
        "version": target["version"],
        **BUG_DEFAULTS,
        "summary": summary,
        "description": description,
        "groups": [target["group"]],
    }
    keywords = list(dict.fromkeys(keywords))
    if keywords:
        payload["keywords"] = keywords
    blocks = [b for b in blocks if b]
    if blocks:
        payload["blocks"] = blocks
    return payload


def build_payload(target, finding, meta_id):
    return base_payload(target, finding["summary"], finding["description"],
                        bug_keywords(finding["severity"]), [meta_id])


def build_scan_meta_payload(target, scan):
    payload = base_payload(target, scan_meta_summary(scan),
                           scan_meta_description(scan), ["meta"],
                           [target["meta_bug"]])
    payload["type"] = "task"
    return payload


# --- Audit log --------------------------------------------------------------

LOG_HEADER = """\
# Audit log of file_bmo_bug.py: what was filed on Bugzilla for this scan.
# One line per event: <UTC time>  <event>  <subject>  <details>
# The subject is a finding id, or the scan id for the scan's meta bug.
# The script reads back the "creating", "filed" and "not-filed" lines so it
# never files anything twice: do not edit or delete them. Notes can be added
# as lines starting with "#".
"""
LOG_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_log(text, path):
    """{subject: {"filed": [bug ids], "pending": time or None}} from the log.

    "pending" is the time of a "creating" that has no outcome after it.
    """
    records = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            sys.exit(f"{path}:{number}: not a log line: {line!r}")
        when, event, subject = parts[:3]
        if event not in ("creating", "filed", "not-filed"):
            continue
        try:
            when = datetime.strptime(when, LOG_TIME_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            sys.exit(f"{path}:{number}: bad time {when!r}")
        record = records.setdefault(subject, {"filed": [], "pending": None})
        if event == "creating":
            record["pending"] = when
        elif event == "filed":
            m = re.match(r"bug (\d+)\b", parts[3] if len(parts) > 3 else "")
            if not m:
                sys.exit(f"{path}:{number}: no \"bug <id>\" in {line!r}")
            if int(m[1]) not in record["filed"]:
                record["filed"].append(int(m[1]))
            record["pending"] = None
        else:
            record["pending"] = None
    return records


class AuditLog:
    """The scan's bmo-filing.log. A writable one is locked while it is open,
    so that two runs on this copy of the scan cannot overlap."""

    def __init__(self, path, records, file=None):
        self.path = path
        self.records = records
        self.file = file

    @classmethod
    def open(cls, path, writable=True):
        if not writable:
            text = path.read_text() if path.exists() else ""
            return cls(path, parse_log(text, path))
        try:
            file = open(path, "a+", encoding="utf-8")
        except OSError as e:
            sys.exit(f"Unable to open the log {path}: {e}")
        try:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            file.close()
            sys.exit(f"{path} is locked: another run is filing this scan. "
                     "Wait for it to finish.")
        file.seek(0)
        text = file.read()
        log = cls(path, parse_log(text, path), file)
        if not text:
            file.write(LOG_HEADER)
            log._flush()
        return log

    def record(self, subject):
        return self.records.get(subject, {"filed": [], "pending": None})

    def write(self, event, subject, details=""):
        """Append an event; a no-op for a read-only (dry run) log."""
        if self.file is None:
            return
        details = " ".join(str(details).split())
        self.file.write(f"{now().strftime(LOG_TIME_FORMAT)}  {event:<9}  "
                        f"{subject}  {details}".rstrip() + "\n")
        self._flush()
        if event == "filed":
            record = self.records.setdefault(subject, {"filed": [], "pending": None})
            bug_id = int(details.split()[1])
            if bug_id not in record["filed"]:
                record["filed"].append(bug_id)

    def _flush(self):
        self.file.flush()
        os.fsync(self.file.fileno())

    def close(self):
        """Close the log, which releases its lock."""
        if self.file is not None:
            self.file.close()
            self.file = None


# --- Findings and plan ------------------------------------------------------


def check_counts(scan, findings):
    """Problems with the findings found against the README's numbers."""
    expected = {"": ("vulnerabilities at the top level", scan["count"])}
    for group in scan["groups"]:
        expected[group["dir"]] = (f"findings in {group['dir']}/", group["count"])
    found = {}
    for finding in findings:
        found[finding["dir"]] = found.get(finding["dir"], 0) + 1
    errors = []
    for directory, (what, count) in expected.items():
        if found.get(directory, 0) != count:
            errors.append(f"README.md says {count} {what}, there are "
                          f"{found.get(directory, 0)}")
    for directory, count in found.items():
        if directory not in expected:
            errors.append(f"{directory}/: {count} finding(s) README.md does not list")
    return errors


def load_findings(scan):
    """Read every finding of the scan; exits listing all the problems found."""
    findings, errors, seen = [], [], {}
    group_titles = {g["dir"]: g["title"] for g in scan["groups"]}
    for path in find_findings(scan["root"]):
        where = path.relative_to(scan["root"])
        try:
            report = read_file(path / "REPORT.md", path).decode()
            ident, severity, title = parse_report(report)
            attachments = collect_attachments(path, ident)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            errors.append(f"{where}: {e}")
            continue
        if ident in seen:
            errors.append(f"{where}: {ident} is also in {seen[ident]}")
            continue
        seen[ident] = where
        description = build_description(report)
        if len(description) > MAX_COMMENT_LENGTH:
            errors.append(f"{where}: the description is {len(description)} "
                          f"characters long, Bugzilla accepts {MAX_COMMENT_LENGTH}")
            continue
        directory = where.parent.as_posix()
        directory = "" if directory == "." else directory
        group = group_titles.get(directory)
        findings.append({
            "path": path,
            "dir": directory,
            "id": ident,
            "severity": severity,
            "summary": f"[{ident}] {title}",
            "description": description,
            "upstream": upstream_bugs(report) if group == ALREADY_PUBLIC else None,
            "attachments": attachments,
        })
    if not errors and not findings:
        sys.exit(f"No findings (REPORT.md) below {scan['root']}")
    if not errors:
        errors = check_counts(scan, findings)
    if errors:
        sys.exit("Problems with the findings of the scan:\n  " + "\n  ".join(errors))
    return findings


def known_bugs(bugzilla, log, subject, hits):
    """The bugs of a finding (or of the scan, for its meta bug): those found by
    the search and those the log says were filed.

    Exits if the log names a bug that cannot be read, or if an unanswered
    filing is too recent for its bug to be known not to exist.
    Returns (bugs, retrying: whether an unanswered filing is to be tried again).
    """
    record = log.record(subject)
    bugs = list(hits)
    for bug_id in record["filed"]:
        if any(bug["id"] == bug_id for bug in bugs):
            continue
        out.status(f"Reading bug {bug_id}, which {log.path.name} records for {subject}"
                   " but the search did not find ...")
        try:
            bugs.append(bugzilla.get_bug(bug_id, ["id", "summary", "blocks", "groups"]))
        except (BugzillaError, KeyError, IndexError) as e:
            sys.exit(f"{log.path} says bug {bug_id} was filed for {subject}, but it "
                     f"cannot be read ({e}). Check it by hand.")
    retrying = False
    if not bugs and record["pending"]:
        since = record["pending"]
        if now() - since < PENDING_GRACE:
            later = (since + PENDING_GRACE).strftime(LOG_TIME_FORMAT)
            sys.exit(f"A run filing {subject} stopped at "
                     f"{since.strftime(LOG_TIME_FORMAT)} without an answer from "
                     "Bugzilla, and no bug for it can be found yet. It may still "
                     f"show up: run again after {later}.")
        retrying = True
    return bugs, retrying


# Stands for the scan's meta bug in a plan, when it is still to be filed.
NEW_META = "the new meta bug"


def upstream_link(bugzilla, finding, warnings):
    """The upstream bug an already-public finding's bug is to block, or None."""
    ids = finding["upstream"]
    if ids is None:
        return None
    if len(ids) != 1:
        named = f"names {', '.join(map(str, ids))}" if ids else "names no bug"
        warnings.append(f"{finding['id']} is already public, but its report {named}: "
                        "link its bug to the upstream one by hand")
        return None
    out.status(f"Checking {finding['id']}'s upstream bug {ids[0]} ...")
    try:
        bugzilla.get_bug(ids[0], ["id"])
    except (BugzillaError, KeyError, IndexError) as e:
        warnings.append(f"{finding['id']}: its upstream bug {ids[0]} cannot be read "
                        f"({e}): not linking it")
        return None
    return ids[0]


def make_plan(bugzilla, target, scan, findings, log, limit=None):
    """Everything a run is to do. Looks up, in Bugzilla and the log, the scan's
    meta bug and the bug of every finding, and works out what to file and what
    to change on the bugs that exist."""
    subjects = [scan["id"]] + [f["id"] for f in findings]
    try:
        hits = bugzilla.find_bugs([f"[{s}]" for s in subjects],
                                  out.progress("Looking for existing bugs",
                                               len(subjects)))
    except BugzillaError as e:
        sys.exit(f"Unable to search Bugzilla: {e}")

    metas, meta_retry = known_bugs(bugzilla, log, scan["id"], hits[f"[{scan['id']}]"])
    if len(metas) > 1:
        sys.exit(f"Scan {scan['id']} has several meta bugs: "
                 + ", ".join(str(bug["id"]) for bug in metas))
    meta = metas[0] if metas else None
    meta_blocks = ([target["meta_bug"]] if meta and target["meta_bug"]
                   not in meta.get("blocks", []) else [])

    plan = {"meta": meta, "meta_retry": meta_retry, "meta_blocks": meta_blocks,
            "items": [], "warnings": []}
    to_file = 0
    existing = []
    for finding in findings:
        bugs, retrying = known_bugs(bugzilla, log, finding["id"],
                                    hits[f"[{finding['id']}]"])
        item = {"finding": finding, "bugs": bugs, "retrying": retrying,
                "blocks": [], "attach": []}
        if len(bugs) > 1:
            item["action"] = "several"
        elif bugs:
            in_group = target["group"] in bugs[0].get("groups", [])
            item["action"] = "update" if in_group else "unrestricted"
            if in_group:
                existing.append(item)
        elif limit is None or to_file < limit:
            item["action"] = "file"
            to_file += 1
        else:
            item["action"] = "later"
        if item["action"] in ("file", "update"):
            # The warnings matter when a bug is filed; they were shown then
            # for the bugs that exist, which may have been linked by hand.
            item["link"] = upstream_link(
                bugzilla, finding, plan["warnings"] if item["action"] == "file" else [])
        plan["items"].append(item)

    progress = (out.progress("Checking the attachments of the existing bugs",
                             len(existing)) if existing else None)
    for n, item in enumerate(existing, 1):
        bug = item["bugs"][0]
        wanted = [meta["id"] if meta else NEW_META, item["link"]]
        item["blocks"] = [b for b in wanted
                          if b and (b == NEW_META or b not in bug.get("blocks", []))]
        try:
            item["attach"] = bugzilla.missing_attachments(
                bug["id"], item["finding"]["attachments"])
        except BugzillaError as e:
            sys.exit(f"Unable to list the attachments of bug {bug['id']}: {e}")
        if not item["blocks"] and not item["attach"]:
            item["action"] = "done"
        progress(n, len(existing))
    return plan


def count_actions(plan):
    """(bugs to file, existing bugs to change) of a plan."""
    actions = [item["action"] for item in plan["items"]]
    to_file = actions.count("file") + (0 if plan["meta"] else 1)
    to_update = actions.count("update") + (1 if plan["meta_blocks"] else 0)
    return to_file, to_update


def bug_list(bugs):
    return ", ".join(str(bug["id"]) for bug in bugs)


def print_plan(target, scan, findings, plan, url, user):
    meta = plan["meta"]
    items = plan["items"]
    by_action = {}
    for item in items:
        by_action.setdefault(item["action"], []).append(item)

    out.say(f"Scan {scan['id']} of {scan['project']}: {len(findings)} finding(s) "
          f"in {scan['root']}")
    out.say(f"Product: {target['product']} :: {target['component']} "
          f"(version {target['version']}), security group: {target['group']}")
    out.say(f"Filing as: {user}")
    if meta:
        change = (f", to be made to block {target['meta_bug']}"
                  if plan["meta_blocks"] else "")
        out.say(f"Meta bug: {url}/show_bug.cgi?id={meta['id']} (exists){change}")
    else:
        again = " (again: an earlier try left no bug)" if plan["meta_retry"] else ""
        out.say(f"Meta bug: to file{again}, {scan_meta_summary(scan)!r}, "
              f"blocking {target['meta_bug']}")

    done = by_action.get("done", [])
    if done:
        out.say(f"Already filed, nothing to change: {len(done)}")
    updates = by_action.get("update", [])
    if updates:
        out.say(f"To update: {len(updates)}")
        for item in updates:
            changes = []
            if item["blocks"]:
                changes.append("block " + ", ".join(map(str, item["blocks"])))
            if item["attach"]:
                changes.append("attach "
                               + ", ".join(a["file_name"] for a in item["attach"]))
            out.say(f"  {item['finding']['id']}: bug {item['bugs'][0]['id']}: "
                  + "; ".join(changes))
    left_alone = by_action.get("several", []) + by_action.get("unrestricted", [])
    if left_alone:
        out.say(f"Left alone: {len(left_alone)}")
        for item in left_alone:
            if item["action"] == "several":
                reason = "several bugs: left alone"
            else:
                reason = f"NOT in the security group {target['group']}: fix it by hand"
            out.say(f"  {item['finding']['id']}: bug {bug_list(item['bugs'])} ({reason})")

    selected = by_action.get("file", [])
    later = by_action.get("later", [])
    if later:
        out.say(f"To file: {len(selected)} of {len(selected) + len(later)} (--limit "
              f"{len(selected)}); {len(later)} left for later runs")
    else:
        out.say(f"To file: {len(selected)}")
    groups = {}
    for item in selected:
        directory = item["finding"]["dir"]
        keywords = ", ".join(bug_keywords(item["finding"]["severity"]))
        counts = groups.setdefault(directory, {})
        counts[keywords] = counts.get(keywords, 0) + 1
    for directory, counts in groups.items():
        where = f"{directory}/" if directory else "top level"
        out.say(f"  {where}: {sum(counts.values())} ("
              + ", ".join(f"{k}: {n}" for k, n in counts.items()) + ")")
    for item in selected + updates:
        if item.get("retrying"):
            out.say(f"  {item['finding']['id']}: again, an earlier try left no bug")
        if item.get("link") and item["action"] == "file":
            out.say(f"  {item['finding']['id']}: will also block its upstream bug "
                  f"{item['link']}")
    for warning in plan["warnings"]:
        out.say(f"Warning: {warning}")
    return count_actions(plan)


def write_dry_run(scan, findings):
    out = Path(tempfile.mkdtemp(prefix="bmo-dry-run-"))
    (out / "meta-description.md").write_text(scan_meta_description(scan))
    for finding in findings:
        directory = out / finding["id"]
        directory.mkdir()
        (directory / "description.md").write_text(finding["description"])
        for attachment in finding["attachments"]:
            (directory / attachment["file_name"]).write_bytes(attachment["data"])
    return out


def confirm(question):
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def confirmation_question(to_file, to_update):
    parts = []
    if to_file:
        parts.append(f"file {to_file} bug(s)")
    if to_update:
        parts.append(f"update {to_update} existing bug(s)")
    return " and ".join(parts).capitalize() + "?"


# --- Filing -----------------------------------------------------------------


def resolve_target(bugzilla, meta_bug):
    """Where to file: the product, component and version of the meta bug, and
    the product's default security group."""
    try:
        bug = bugzilla.get_bug(meta_bug, ["product", "component", "version"])
    except BugzillaError as e:
        sys.exit(f"Unable to read bug {meta_bug}: {e}")
    except (KeyError, IndexError):
        sys.exit(f"Bug {meta_bug} does not exist or you cannot see it")
    try:
        group = bugzilla.default_security_group(bug["product"])
    except BugzillaError as e:
        sys.exit(f"Unable to look up the security group of {bug['product']}: {e}")
    if not group:
        sys.exit(f"{bug['product']} has no default security group")
    return {"product": bug["product"], "component": bug["component"],
            "version": bug["version"], "group": group, "meta_bug": meta_bug}


def fail(log, subject, message):
    out.status(f"  FAILED {message}")
    log.write("failed", subject, message)
    return 1


def add_blocks(bugzilla, log, subject, bug_id, blocks):
    """Make the bug block the given bugs; returns the number of failures."""
    try:
        missing = bugzilla.ensure(bug_id, blocks=blocks).get("blocks", [])
        error = "the change was not applied"
    except BugzillaError as e:
        missing, error = blocks, str(e)
    for blocked in blocks:
        if blocked not in missing:
            out.say(f"  bug {bug_id} ({subject}) now blocks bug {blocked}")
            log.write("blocks", subject, f"bug {bug_id} now blocks bug {blocked}")
    if missing:
        return fail(log, subject, f"to make bug {bug_id} block "
                    f"{', '.join(map(str, missing))}: {error}")
    return 0


def create_restricted(bugzilla, log, subject, payload, extra_blocks=(), label=""):
    """File the bug and make sure it is in its security group (exits if not),
    then make it block extra_blocks. Returns (bug id, number of failures)."""
    log.write("creating", subject, payload["summary"])
    out.step(f"{label}Filing {payload['summary']}")
    try:
        bug_id = bugzilla.create_bug(payload)
    except BugzillaError as e:
        out.done("FAILED")
        if e.outcome_unknown:
            log.write("failed", subject, f"no answer to the filing: {e}")
            sys.exit(f"Bugzilla did not say whether it filed {payload['summary']!r}: "
                     f"{e}\nRun again: the next run looks for the bug before filing "
                     f"it again (see {log.path}).")
        log.write("not-filed", subject, str(e))
        sys.exit(f"Unable to file {payload['summary']!r}: {e}\n"
                 "Run again to file the rest.")
    bug_url = f"{bugzilla.url}/show_bug.cgi?id={bug_id}"
    log.write("filed", subject, f"bug {bug_id} {bug_url}")
    group = payload["groups"][0]
    out.done(f"filed {bug_url}")
    out.step(f"  checking that bug {bug_id} is in the security group {group}")
    try:
        missing = bugzilla.ensure(bug_id, groups=payload["groups"],
                                  blocks=payload.get("blocks"),
                                  keywords=payload.get("keywords"))
    except BugzillaError as e:
        missing = {"groups": payload["groups"]}
        out.status(f"  FAILED to check the bug's fields: {e}")
    out.done("FAILED" if "groups" in missing else "it is")
    if "groups" in missing:
        log.write("failed", subject, f"bug {bug_id} may NOT be in the security "
                  f"group {group}")
        sys.exit(f"{bug_url} may NOT be in the security group {group}: "
                 "fix it by hand. Nothing more was filed or uploaded.")
    failures = 0
    for field, values in missing.items():
        failures += fail(log, subject, f"to set {field} of bug {bug_id}: "
                         f"{', '.join(map(str, values))}")
    # Added after filing, so that a bug the user may not change cannot stop
    # the filing itself.
    if extra_blocks:
        failures += add_blocks(bugzilla, log, subject, bug_id, list(extra_blocks))
    return bug_id, failures


def upload(bugzilla, log, subject, bug_id, attachments):
    """Upload the attachments; returns the number of failures."""
    failures = 0
    for attachment in attachments:
        out.step(f"  attaching {attachment['file_name']} "
                 f"({human_size(len(attachment['data']))})")
        try:
            bugzilla.attach_with_retry(bug_id, attachment)
            out.done()
            log.write("attached", subject, f"bug {bug_id} {attachment['file_name']} "
                      f"({len(attachment['data'])} bytes)")
        except BugzillaError as e:
            out.done("FAILED")
            failures += fail(log, subject,
                             f"to attach {attachment['file_name']} to bug {bug_id}: {e}")
    return failures


def update_existing(bugzilla, log, target, item, meta_id, label=""):
    """Make the changes the plan has for an existing bug: the bugs it is to
    block and the attachments it is missing. Returns the number of failures."""
    subject = item["finding"]["id"]
    bug_id = item["bugs"][0]["id"]
    blocks = [meta_id if b == NEW_META else b for b in item["blocks"]]
    out.say(f"{label}Updating bug {bug_id} ({subject})")
    failures = add_blocks(bugzilla, log, subject, bug_id, blocks) if blocks else 0
    if not item["attach"]:
        return failures
    # The plan checked the group, but that may have been a while ago.
    try:
        groups = bugzilla.get_bug(bug_id, ["groups"]).get("groups", [])
    except (BugzillaError, KeyError, IndexError) as e:
        return failures + fail(log, subject, f"to check the group of bug {bug_id}: {e}")
    if target["group"] not in groups:
        return failures + fail(log, subject, f"bug {bug_id} is not in the security "
                               f"group {target['group']}: not attaching anything")
    return failures + upload(bugzilla, log, subject, bug_id, item["attach"])


def record_found(log, subject, bugs):
    """Log a bug that was found in Bugzilla but is not in the log."""
    if len(bugs) == 1 and bugs[0]["id"] not in log.record(subject)["filed"]:
        log.write("filed", subject, f"bug {bugs[0]['id']} (found in Bugzilla)")


def file_scan(bugzilla, target, scan, plan, log, user):
    to_file, to_update = count_actions(plan)
    started = time.monotonic()
    if to_file or to_update:
        log.write("run", scan["id"], f"by {user}: file {to_file}, update {to_update}")
    steps = to_file + to_update
    position = 0

    def label():
        nonlocal position
        position += 1
        return f"[{position}/{steps}] "

    meta = plan["meta"]
    failures = 0
    if meta:
        meta_id = meta["id"]
        record_found(log, scan["id"], [meta])
        if plan["meta_blocks"]:
            out.say(f"{label()}Updating the meta bug {meta_id}")
            failures += add_blocks(bugzilla, log, scan["id"], meta_id,
                                   plan["meta_blocks"])
    else:
        meta_id, problems = create_restricted(bugzilla, log, scan["id"],
                                              build_scan_meta_payload(target, scan),
                                              label=label())
        failures += problems

    filed = updated = 0
    for item in plan["items"]:
        finding, action = item["finding"], item["action"]
        record_found(log, finding["id"], item["bugs"])
        if action == "unrestricted":
            bug_id = item["bugs"][0]["id"]
            failures += fail(log, finding["id"], f"bug {bug_id} is not in the security "
                             f"group {target['group']}: left alone, fix it by hand")
        elif action == "update":
            failures += update_existing(bugzilla, log, target, item, meta_id,
                                        label())
            updated += 1
        elif action == "file":
            # Never upload a reproducer unless the bug is known to be
            # restricted: create_restricted exits otherwise.
            link = [item["link"]] if item.get("link") else []
            bug_id, problems = create_restricted(
                bugzilla, log, finding["id"], build_payload(target, finding, meta_id),
                link, label())
            failures += problems
            failures += upload(bugzilla, log, finding["id"], bug_id,
                               finding["attachments"])
            filed += 1
    left = sum(item["action"] == "later" for item in plan["items"])
    out.say(f"Filed {filed} bug(s), updated {updated} existing one(s) in "
            f"{time.monotonic() - started:.0f} s; meta bug: "
            f"{bugzilla.url}/show_bug.cgi?id={meta_id}")
    if to_file or to_update or failures:
        log.write("done", scan["id"], f"filed {filed}, updated {updated}, "
                  f"{failures} problem(s)")
    if left:
        out.say(f"{left} finding(s) left to file: run again")
    if failures:
        sys.exit(f"{failures} problem(s), see above and {log.path}; "
                 "run again to retry")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--meta-bug", required=True, type=int,
                        help="the overall oss-scanner meta bug; bugs are filed in "
                             "its product and component")
    parser.add_argument("scan", type=Path, help="root directory of the scan")
    parser.add_argument("--dry-run", action="store_true",
                        help="show the plan and write the bugs' descriptions and "
                             "attachments to a directory; change nothing")
    parser.add_argument("--limit", type=int, metavar="N",
                        help="file at most N new finding bugs (default: no limit)")
    args = parser.parse_args()
    if args.meta_bug <= 0:
        parser.error("--meta-bug must be a bug id")
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be a positive number")

    scan = load_scan(args.scan)
    out.status(f"Reading the findings of scan {scan['id']} in {scan['root']} ...")
    findings = load_findings(scan)
    attachments = [a for f in findings for a in f["attachments"]]
    out.status(f"Read {len(findings)} finding(s) with {len(attachments)} attachment(s), "
               f"{human_size(sum(len(a['data']) for a in attachments))}")
    log = AuditLog.open(scan["root"] / LOG_NAME, writable=not args.dry_run)
    recorded = sum(len(r["filed"]) for r in log.records.values())
    out.status(f"Audit log: {log.path} ({recorded} bug(s) recorded"
               + (", not written in a dry run)" if args.dry_run else ")"))
    try:
        run(args, scan, findings, log)
    finally:
        log.close()


def run(args, scan, findings, log):
    bugzilla = Bugzilla(DEFAULT_BUGZILLA_URL, api_key(DEFAULT_BUGZILLA_URL))
    out.status(f"Checking the API key with {bugzilla.url} ...")
    try:
        user = bugzilla.whoami()
    except BugzillaError as e:
        sys.exit(f"Bugzilla does not accept the API key: {e}")
    out.status(f"Reading bug {args.meta_bug}, the overall meta bug, and the "
               "security group of its product ...")
    target = resolve_target(bugzilla, args.meta_bug)
    plan = make_plan(bugzilla, target, scan, findings, log, args.limit)
    out.say()
    to_file, to_update = print_plan(target, scan, findings, plan, bugzilla.url, user)

    if args.dry_run:
        out.say(f"Descriptions and attachments written to {write_dry_run(scan, findings)}"
              "\nIt holds the reproducers: delete it when done.")
        return
    if (to_file or to_update) and not confirm(confirmation_question(to_file, to_update)):
        sys.exit("Aborted")
    out.say()
    file_scan(bugzilla, target, scan, plan, log, user)

if __name__ == "__main__":
    main()
