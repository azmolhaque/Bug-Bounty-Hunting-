#!/usr/bin/env python3
"""
Google OSS VRP — GitHub Actions configuration audit.

Sparse-clones only `.github/` from each OT0/OT1 repository and flags workflows that can run
attacker-controlled input WITHOUT a maintainer approving a PR first — the bar the programme
rules set for a supply-chain reward.

    ./scan-workflows.py --clone      # fetch/refresh .github from every repo
    ./scan-workflows.py              # analyse what is already on disk

Read-only. Clones public repositories; opens nothing, sends nothing.
"""
import argparse, os, re, subprocess, sys, json
from pathlib import Path

TIERS = Path("oss-tiers.txtpb")
ROOT  = Path("repos")

# Triggers that execute in the BASE repository context — token and secrets available — and are
# not gated behind the "approve workflows from first-time contributors" click.
RISKY_TRIGGERS = [
    "pull_request_target", "issue_comment", "workflow_run",
    "issues", "discussion", "discussion_comment", "pull_request_review",
    "pull_request_review_comment", "fork", "watch",
]

# Context values an outside contributor controls verbatim.
UNTRUSTED = [
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.comment\.body",
    r"github\.event\.pull_request\.(title|body)",
    r"github\.event\.pull_request\.head\.(ref|label)",
    r"github\.event\.pull_request\.head\.repo\.(description|homepage|default_branch|full_name)",
    r"github\.event\.review(_comment)?\.body",
    r"github\.event\.discussion\.(title|body)",
    r"github\.event\.head_commit\.(message|author\.(name|email))",
    r"github\.event\.commits\[",
    r"github\.event\.workflow_run\.head_(branch|commit\.message)",
    r"github\.head_ref",
]
UNTRUSTED_RE = re.compile("|".join(UNTRUSTED))

# Checking out the PR's own code inside a base-context trigger = running attacker code.
PR_CHECKOUT_RE = re.compile(
    r"ref:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)"
    r"|github\.event\.workflow_run\.head_(sha|branch)"
    r"|github\.head_ref)", re.I)

def repos():
    if not TIERS.exists():
        sys.exit(f"missing {TIERS} — curl it from google/bughunters first")
    rows = re.findall(r'url:\s*"([^"]+)"\s*tier:\s*TIER_(OT\d)', TIERS.read_text())
    return [(u.replace("https://github.com/", ""), t)
            for u, t in rows if "github.com" in u and t in ("OT0", "OT1")]

def clone(slug):
    dest = ROOT / slug.replace("/", "__")
    if dest.exists():
        subprocess.run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin"],
                       capture_output=True)
        subprocess.run(["git", "-C", str(dest), "reset", "--hard", "FETCH_HEAD"],
                       capture_output=True)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
         f"https://github.com/{slug}.git", str(dest)], capture_output=True, text=True)
    if r.returncode:
        print(f"  ! clone failed {slug}: {r.stderr.strip().splitlines()[-1:]}")
        return None
    subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", ".github"],
                   capture_output=True)
    return dest

def triggers_of(text):
    """Trigger names appearing before the first job definition."""
    head = re.split(r"^jobs:", text, maxsplit=1, flags=re.M)[0]
    return [t for t in RISKY_TRIGGERS if re.search(rf"^\s*{t}\s*:", head, re.M)]

def run_blocks(text):
    """Crude but effective: the body of each `run:` step."""
    out = []
    for m in re.finditer(r"^(\s*)run:\s*\|?(.*?)(?=^\1\S|\Z)", text, re.M | re.S):
        out.append(m.group(2))
    return out

def analyse(path, slug, tier):
    wf = path / ".github" / "workflows"
    if not wf.is_dir():
        return []
    hits = []
    for f in sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))):
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        trig = triggers_of(text)
        if not trig:
            continue
        score, why = 0, []
        if PR_CHECKOUT_RE.search(text):
            score += 5; why.append("checks out PR/untrusted ref in base context")
        inj = {m.group(0) for b in run_blocks(text) for m in UNTRUSTED_RE.finditer(b)}
        if inj:
            score += 4; why.append(f"untrusted input in run: {sorted(inj)[:4]}")
        if re.search(r"secrets\.[A-Z_]", text):
            score += 2; why.append("references secrets")
        if re.search(r"runs-on:.*self-hosted", text, re.I):
            score += 2; why.append("self-hosted runner")
        if re.search(r"permissions:\s*\n\s*.*write", text):
            score += 1; why.append("write permissions")
        if score:
            hits.append(dict(tier=tier, repo=slug, workflow=f.name,
                             triggers=trig, score=score, why=why))
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clone", action="store_true")
    a = ap.parse_args()
    rs = repos()
    print(f"{len(rs)} OT0/OT1 GitHub repositories\n")
    all_hits = []
    for slug, tier in rs:
        path = clone(slug) if a.clone else ROOT / slug.replace("/", "__")
        if not path or not path.exists():
            continue
        h = analyse(path, slug, tier)
        all_hits += h
        if a.clone:
            print(f"  {tier}  {slug:<45} {len(h)} candidate(s)")
    all_hits.sort(key=lambda h: (-h["score"], h["tier"]))
    Path("candidates.json").write_text(json.dumps(all_hits, indent=2))
    print(f"\n{len(all_hits)} candidates -> candidates.json\n")
    for h in all_hits[:30]:
        print(f"[{h['score']:>2}] {h['tier']}  {h['repo']}  ::  {h['workflow']}")
        print(f"      on: {', '.join(h['triggers'])}")
        for w in h["why"]:
            print(f"      - {w}")
        print()

if __name__ == "__main__":
    main()
