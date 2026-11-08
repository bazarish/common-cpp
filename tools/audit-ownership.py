#!/usr/bin/env python3
# Bazarish project (c) 2026
"""Fails on ownership the project rules forbid.

- a raw pointer declared in one of our headers, unless it points to a C library's
  handle, a Qt class (Q...), text (char) or a type the repository lists as owned by
  Qt's parent tree;
- a std::thread let go with detach();
- new without a smart pointer or a Qt parent to take it, and any delete;
- nlohmann's from_cbor outside JsonRead.cpp, which is the only reader that bounds
  the depth of what it parses.

A site that must stay carries "ownership: allowed - <reason>" on its line or the
line above. tools/ownership-allow.txt names, one per line, the classes whose
objects belong to a Qt parent, so a pointer to one is an observer Qt keeps valid.

Usage: audit-ownership.py [roots...]   (default: this repository's sources)
"""
import pathlib
import re
import sys

kSourceSuffixes = (".cpp", ".hpp")
kSkipDirs = ("third_party", "build", ".git", "tests")
kTestFilePrefix = "Test"
kMarker = "ownership: allowed"
kCborReader = "JsonRead.cpp"

# Handles of the C libraries the project wraps, and what C APIs hand over as text.
kForeignTypes = {
    "char", "void", "sqlite3", "sqlite3_stmt", "sqlite3_backup", "BIO", "BIGNUM", "X509",
    "SSL", "SSL_CTX", "EVP_PKEY", "EVP_PKEY_CTX", "EVP_MD_CTX", "EVP_CIPHER_CTX", "EVP_KDF",
    "EVP_KDF_CTX", "CMS_ContentInfo", "OpusEncoder", "OpusDecoder", "quirc", "QRcode",
    "JNIEnv", "jobject", "sockaddr", "Handle",
}

# A class of ours starts upper case; a lower case name before "*" is a product, not a type.
kPointerDeclaration = re.compile(
    r"\b(?:const\s+)?((?:[a-z_]\w*::)*[A-Z]\w*)\s*\*\s*(?:const\s+)?[a-z_]\w*\s*[;,)=\[]")
kThreadDetach = re.compile(r"\b\w*(?:thread|worker)\w*\s*\.\s*detach\s*\(\s*\)", re.IGNORECASE)
kNew = re.compile(r"\bnew\s+[A-Za-z_][\w:<>]*\s*[({]")
# Handed straight to an owner: a smart pointer, or a Qt call that takes the object.
kOwnedNew = re.compile(
    r"(?:unique_ptr|shared_ptr)\s*<[^>]*>\s*\w*\s*[({]\s*new\b|\.reset\(\s*new\b"
    r"|addImageProvider\(.*\bnew\b")
kQtParent = re.compile(r"\(\s*(?:[^()]*,\s*)?(?:this|&\w+)\s*\)\s*;")
kDelete = re.compile(r"(?<![=\w])\s*\bdelete\s+[A-Za-z_(]")
kFromCbor = re.compile(r"\bfrom_cbor\s*\(")


def qt_owned_types(repo):
    path = repo / "tools" / "ownership-allow.txt"
    if not path.exists():
        return set()
    names = set()
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            names.add(line.split()[0])
    return names


def code_of(line):
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return text.split("//")[0]


def marked(lines, index):
    return kMarker in lines[index] or (index > 0 and kMarker in lines[index - 1])


def findings_in(path, qt_owned):
    lines = path.read_text(errors="ignore").splitlines()
    found = []
    header = path.suffix == ".hpp"
    for index, raw in enumerate(lines):
        code = code_of(raw)
        if not code.strip() or code.lstrip().startswith(("#", "*", "/*")):
            continue
        why = None
        if header:
            for match in kPointerDeclaration.finditer(code):
                pointee = match.group(1).split("::")[-1]
                if (pointee in kForeignTypes or pointee in qt_owned or pointee.startswith("Q")
                        or pointee.startswith("_")):
                    continue
                why = f"raw pointer to {pointee}"
                break
        if why is None and kThreadDetach.search(code):
            why = "a thread let go with detach()"
        if why is None and kNew.search(code) and not kOwnedNew.search(code) \
                and not kQtParent.search(code):
            why = "new with nothing to own it"
        if why is None and kDelete.search(code) and "= delete" not in code:
            why = "delete"
        if why is None and kFromCbor.search(code) and path.name != kCborReader:
            why = "from_cbor without the depth bound"
        if why is not None and not marked(lines, index):
            found.append((f"{path.as_posix()}:{index + 1}", why, raw.strip()[:70]))
    return found


def main(argv):
    roots = [pathlib.Path(a) for a in argv[1:]] or [pathlib.Path(".")]
    qt_owned = qt_owned_types(pathlib.Path("."))
    findings = []
    for root in roots:
        qt_owned |= qt_owned_types(root)
        for path in sorted(root.rglob("*")):
            if path.suffix not in kSourceSuffixes:
                continue
            if any(part in kSkipDirs for part in path.parts) or path.name.startswith(kTestFilePrefix):
                continue
            findings.extend(findings_in(path, qt_owned))
    for site, why, code in findings:
        print(f"{site}: {why} -- {code}")
    if findings:
        print(f"\n{len(findings)} ownership finding(s). Own it, observe it by reference, or mark "
              f"the site \"{kMarker} - <reason>\".")
        return 1
    print("no ownership findings")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
