#!/usr/bin/env python3
# Bazarish project (c) 2026
"""Fails on a catch block that discards its exception.

Hiding an error is a defect in this project, so every catch must do one of three
things: report it (log, an error response, a UI signal), propagate it, or turn it
into a value the caller is forced to look at. A block that does none of those is
reported here, and the run fails.

A site that genuinely needs none of the three - a parse whose failure IS the
answer - goes in tools/error-hiding-allow.txt as "<path>:<line> reason", and the
reason has to be written out.

Usage: audit-error-hiding.py [roots...]   (default: this repository's sources)
"""
import pathlib
import re
import sys

# A handled catch reports, propagates, or converts into an inspectable value.
kHandledMarkers = (
    "log::", "respondError", "throw", "emit ", "actionFailed", "op.fail", "printf",
    "std::cerr", "sendHtml", "ok = false", ".ok =", "outcome", "errorCode", "error =", "err =",
    "status =", "failed", "Failed", "= false", "reason",
    # Carrying the exception's message somewhere is reporting it, wherever it lands.
    ".what()",
)
kSourceSuffixes = (".cpp", ".hpp")
# Tests are where an exception IS the expected result, so a catch that only
# records "it threw" is the assertion, not a hidden error.
kSkipDirs = ("third_party", "build", ".git", "tests")
kMaxBlockLines = 60


def block_at(lines, start):
    """The catch block beginning on `start`, or None when it opens no brace."""
    if "{" not in lines[start]:
        return None
    depth = 0
    opened = False
    out = []
    for index in range(start, min(start + kMaxBlockLines, len(lines))):
        segment = lines[index]
        if index == start:
            segment = segment[segment.index("{"):]
        depth += segment.count("{") - segment.count("}")
        opened = opened or "{" in segment
        out.append(lines[index])
        if opened and depth <= 0:
            return out
    return out


def allowed_sites(repo):
    allow = {}
    path = repo / "tools" / "error-hiding-allow.txt"
    if not path.exists():
        return allow
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        site, _, reason = line.partition(" ")
        allow[site] = reason.strip()
    return allow


def main(argv):
    repo = pathlib.Path(__file__).resolve().parent.parent
    roots = [pathlib.Path(a) for a in argv[1:]] or [pathlib.Path(".")]
    allow = allowed_sites(pathlib.Path("."))
    if not allow:
        allow = allowed_sites(repo)
    findings = []
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.suffix not in kSourceSuffixes:
                continue
            if any(part in kSkipDirs for part in path.parts):
                continue
            lines = path.read_text(errors="ignore").splitlines()
            for index, line in enumerate(lines):
                match = re.search(r"\bcatch\s*\(", line)
                if match is None:
                    continue
                if '"' in line[:match.start()]:
                    continue  # a catch inside a string literal (embedded JS, a message)
                body = block_at(lines, index)
                if body is None:
                    continue
                inner = body[1:-1] if len(body) > 2 else []
                code = "\n".join(l.split("//")[0] for l in inner).strip()
                if any(marker in code for marker in kHandledMarkers):
                    continue
                # Returning a value hands the failure to the caller to inspect; a
                # bare "return;" hands over nothing and is the classic swallow.
                if re.search(r"\breturn\s+[^;\s]", code):
                    continue
                site = f"{path.as_posix()}:{index + 1}"
                if site in allow:
                    continue
                findings.append((site, code.replace("\n", " ")[:70] or "(discards it)"))
    for site, code in findings:
        print(f"{site}: catch discards the error -- {code}")
    if findings:
        print(f"\n{len(findings)} silent catch block(s). Report, propagate, or convert -- or "
              f"add the site to tools/error-hiding-allow.txt with a reason.")
        return 1
    print("no silent catch blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
