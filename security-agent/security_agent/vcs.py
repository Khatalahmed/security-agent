"""Minimal git helpers for incremental (diff) audits — stdlib subprocess.

Returns the set of repo-relative (forward-slash) paths that changed, so an audit
can analyze only what a PR/commit touched instead of the whole tree. Assumes
`--repo` is the git work-tree root.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True)


def is_git_repo(repo: Path) -> bool:
    r = _git(repo, "rev-parse", "--is-inside-work-tree")
    return r.returncode == 0 and r.stdout.strip() == "true"


def changed_files(repo: Path, ref: str | None = None) -> tuple[set[str], str]:
    """Return (changed_relpaths, error).

    ref given  -> files changed between <ref> and the working tree.
    ref None   -> uncommitted changes vs HEAD.
    Untracked (new, non-ignored) files are always included — they're the most
    important to audit. On any failure returns (set(), error-message).
    """
    if not is_git_repo(repo):
        return set(), "not a git repository (--diff needs --repo to be a git work tree)"
    target = ref if ref else "HEAD"
    d = _git(repo, "diff", "--name-only", "--relative", target)
    if d.returncode != 0:
        return set(), (d.stderr.strip() or f"git diff against '{target}' failed")
    changed = {ln.strip() for ln in d.stdout.splitlines() if ln.strip()}
    u = _git(repo, "ls-files", "--others", "--exclude-standard")
    if u.returncode == 0:
        changed |= {ln.strip() for ln in u.stdout.splitlines() if ln.strip()}
    return changed, ""
