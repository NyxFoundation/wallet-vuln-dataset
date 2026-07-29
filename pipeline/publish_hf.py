"""publish_hf.py — push a built dataset directory to a HuggingFace dataset
repo on the `main` branch (no revision tagging).

Layout convention: a single repo (`NyxFoundation/vulnerability-reports`)
hosts every domain as a separate top-level folder, which HF auto-detects
as a `config`:

    <repo>/
      README.md                 (global, schema + provenance)
      defi/
        train.parquet
        manifest.json           (per-domain build state)
      lending/
        train.parquet
        manifest.json
      ...

Consumers load a single domain via:

    from datasets import load_dataset
    ds = load_dataset("NyxFoundation/vulnerability-reports", "defi", split="train")

This script publishes one domain at a time. It uploads
`<domain>/train.parquet` + `<domain>/manifest.json` (and re-uploads the
global `README.md` so a freshly-cloned repo still has it). Other domains'
folders are left untouched — `delete_patterns=["<domain>/*"]` is scoped.

Inputs:
    --src    <out-dir>/<domain>/   (created by build_derived.py)
    --repo   default NyxFoundation/vulnerability-reports

Authentication: `HF_TOKEN` env var (or any other source the
`huggingface_hub` token resolver understands, e.g. `huggingface-cli login`).

`--dry-run` skips network calls and writes the staged tree to a tempdir
so the source directory stays untouched.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
DEFAULT_TEMPLATE = "README.md.j2"
DEFAULT_REPO = "NyxFoundation/vulnerability-reports"

# HF repo ids: <org-or-user>/<name>, alnum + `_` + `-` + `.` per HF rules.
REPO_RE = re.compile(r"^[A-Za-z0-9_-]+/[A-Za-z0-9._-]+$")
# Domain becomes a HF config name + a top-level folder; same constraints
# as the workflow's input validation, applied here too as defense in depth.
DOMAIN_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def render_card(repo_id: str, template_name: str = DEFAULT_TEMPLATE) -> str:
    """Render the GLOBAL dataset card. Content is independent of which
    domain is currently being published — domain-specific stats live in
    `<domain>/manifest.json` instead."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(default=False),
        trim_blocks=False,
        lstrip_blocks=False,
    )
    tmpl = env.get_template(template_name)
    return tmpl.render(repo_id=repo_id)


def _stage(src: Path, manifest: dict, domain: str, card: str) -> tempfile.TemporaryDirectory:
    """Build a tempdir mirroring the HF repo layout for upload_folder().

    Layout:
        <td>/
          README.md
          <domain>/train.parquet
          <domain>/manifest.json
    """
    parquet_relative = manifest.get("parquet_path") or "train.parquet"
    parquet_src = src / parquet_relative
    if not parquet_src.exists():
        sys.exit(f"parquet not found at {parquet_src} (manifest.parquet_path={parquet_relative!r})")
    manifest_src = src / "manifest.json"

    td = tempfile.TemporaryDirectory(prefix="speca-publish-hf-")
    staging = Path(td.name)
    domain_dir = staging / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(parquet_src, domain_dir / "train.parquet")
    shutil.copy2(manifest_src, domain_dir / "manifest.json")
    # The dataset card carries em-dashes / non-ASCII; force utf-8 so
    # write_text doesn't fall back to the system locale (cp932 on
    # Japanese Windows) and choke.
    (staging / "README.md").write_text(card, encoding="utf-8")
    return td


def push(staging: Path, repo_id: str, domain: str, token: str, commit_message: str) -> str:
    from huggingface_hub import HfApi
    from huggingface_hub.utils import HfHubHTTPError

    api = HfApi(token=token)
    try:
        api.create_repo(repo_id=repo_id, repo_type="dataset", exist_ok=True)
    except HfHubHTTPError as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status in (401, 403):
            sys.exit(f"HF auth failed (HTTP {status}) creating {repo_id}: token lacks write scope on the org?")
        if status == 404:
            sys.exit(f"HF org/user not found (HTTP 404) creating {repo_id}: does the org exist and is the token valid?")
        raise

    try:
        commit_info = api.upload_folder(
            folder_path=str(staging),
            repo_id=repo_id,
            repo_type="dataset",
            revision="main",
            commit_message=commit_message,
            # Scoped to THIS domain's folder so other domains' folders
            # (and the repo-root README.md) survive untouched. We DO want
            # README.md re-uploaded fresh — that happens because it's in
            # `staging/`, not because of delete_patterns.
            delete_patterns=[f"{domain}/*"],
        )
    except HfHubHTTPError as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status in (401, 403):
            sys.exit(f"HF auth failed (HTTP {status}) uploading to {repo_id}: token lacks write scope?")
        raise
    return getattr(commit_info, "commit_url", "") or ""


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--src", required=True,
                   help="Path to <out-dir>/<domain>/ produced by build_derived.py.")
    p.add_argument("--repo", default=DEFAULT_REPO,
                   help=f"HF dataset repo id (default: {DEFAULT_REPO}).")
    p.add_argument("--require-org", default="NyxFoundation",
                   help="Reject --repo not under this org. Use '' to allow any.")
    p.add_argument("--commit-message", default="",
                   help="Commit message; default = 'Update <domain> @ <scraped_at>'.")
    p.add_argument("--dry-run", action="store_true",
                   help="Render the README and stage files; skip the network push.")
    p.add_argument("--token", default="",
                   help="HF token; default = $HF_TOKEN or huggingface_hub default.")
    args = p.parse_args()

    src = Path(args.src)
    manifest_path = src / "manifest.json"
    if not manifest_path.exists():
        sys.exit(f"manifest.json not found in {src}")
    manifest = json.loads(manifest_path.read_text())

    domain = manifest.get("domain", "")
    if not DOMAIN_RE.fullmatch(domain):
        sys.exit(f"manifest.domain must match {DOMAIN_RE.pattern!r}; got {domain!r}")

    if not REPO_RE.fullmatch(args.repo):
        sys.exit(f"--repo must match {REPO_RE.pattern!r}; got {args.repo!r}")
    if args.require_org:
        org = args.repo.split("/", 1)[0]
        if org != args.require_org:
            sys.exit(
                f"--repo {args.repo} not under required org {args.require_org!r}. "
                f"Pass --require-org '' to allow other orgs."
            )

    card = render_card(args.repo)
    print(f"rendered README.md ({len(card)} chars)")

    commit_message = (
        args.commit_message
        or f"Update {domain} @ {manifest['scraped_at']}"
    )

    td = _stage(src, manifest, domain, card)
    try:
        staging = Path(td.name)
        if args.dry_run:
            print("[dry-run] would push:")
            for p in sorted(staging.rglob("*")):
                if p.is_file():
                    # POSIX-style separators so the dry-run preview
                    # mirrors the HF on-repo layout regardless of OS.
                    rel = p.relative_to(staging).as_posix()
                    print(f"  - {rel} ({p.stat().st_size} bytes)")
            print(f"  to repo: {args.repo} (revision: main, config: {domain})")
            print(f"  commit message: {commit_message!r}")
            return 0

        token = args.token or os.environ.get("HF_TOKEN", "")
        if not token:
            sys.exit("no HF token: set --token or $HF_TOKEN, or run `huggingface-cli login`")

        commit_url = push(staging, args.repo, domain, token, commit_message)
        print(f"pushed config '{domain}' to https://huggingface.co/datasets/{args.repo} (revision main)")
        if commit_url:
            print(f"  commit: {commit_url}")
    finally:
        td.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
