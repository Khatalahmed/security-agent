#!/usr/bin/env python3
"""Reproducibly fetch the real-CVE corpus WITHOUT vendoring third-party code.

For each case in manifest.json this:
  1. blobless-clones the repo once into _repos/<name> (cached, no checkout),
  2. extracts the single changed file at the vulnerable SHA  -> _fetched/<id>/vulnerable/<basename>
                              and at the security-fix SHA    -> _fetched/<id>/fixed/<basename>

Nothing is written into the tracked tree except under _fetched/ and _repos/,
both of which are gitignored. Pure stdlib + the `git` CLI; idempotent.

Usage (from security-agent/):
    python evaluation/fixtures_realcve/fetch.py          # fetch all
    python evaluation/fixtures_realcve/fetch.py --list   # show cases, no network
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
REPOS = HERE / "_repos"
FETCHED = HERE / "_fetched"


def _run(args: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def _repo_dir(repo_url: str) -> Path:
    name = repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    return REPOS / name


def ensure_repo(repo_url: str) -> Path:
    """Blobless, no-checkout clone (history metadata only; blobs fetched on demand)."""
    dest = _repo_dir(repo_url)
    if dest.is_dir():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] clone (blobless) {repo_url} -> {dest}")
    _run(["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(dest)])
    return dest


def extract(repo: Path, sha: str, path: str, out: Path) -> int:
    """Write the file content at <sha>:<path> to `out`. Returns byte length."""
    # `git show` fetches just the needed blob(s) under the blobless clone.
    blob = subprocess.run(["git", "show", f"{sha}:{path}"], cwd=repo,
                          check=True, capture_output=True).stdout
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    return len(blob)


def fetch_case(case: dict) -> None:
    repo = ensure_repo(case["repo"])
    base = case["path"].split("/")[-1]
    for label, sha in (("vulnerable", case["vuln_sha"]), ("fixed", case["fix_sha"])):
        out = FETCHED / case["id"] / label / base
        n = extract(repo, sha, case["path"], out)
        exp = case.get("size_bytes", {}).get("vuln" if label == "vulnerable" else "fixed")
        flag = ""
        if exp is not None and n != exp:
            flag = f"  [!] size {n} != manifest {exp} (upstream changed?)"
        print(f"    {case['id']}/{label}: {n} B -> {out.relative_to(HERE)}{flag}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print cases and exit (no network)")
    args = ap.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases = manifest["cases"]
    if args.list:
        for c in cases:
            print(f"  {c['id']:40} {c['class']:16} {c['repo']} @ {c['fix_sha'][:10]}")
        return 0
    print(f"[*] fetching {len(cases)} case(s) into {FETCHED.relative_to(HERE.parent.parent)} "
          "(gitignored; nothing vendored)")
    for c in cases:
        fetch_case(c)
    print("[*] done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
