"""Package local edits and existing history without staging or committing."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "agent/pii.py", "agent/policy.py", "agent/runner.py", "agent/ledger.py",
    "corpus/ticket-901.md", "corpus/ticket-902.md", "corpus/ticket-903.md",
    "corpus/ticket-904.md", "corpus/ticket-904b.md", ".pre-commit-config.yaml",
    "requirements.lock", "reports/secrets-incident.md", "injection-corpus.md",
    "reports/baseline.md", "reports/attack-before.log", "reports/attack-after.log",
    "reports/ledger.jsonl", "reports/compliance-mapping.md", "reports/dpia-lite.md",
    "reports/verification.md",
)


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def package() -> None:
    sha = git("rev-parse", "HEAD").decode().strip()
    output = ROOT / "submission"
    output.mkdir(exist_ok=True)
    bundle = output / "GIT-HISTORY.bundle"
    git("bundle", "create", str(bundle), "--all", "HEAD")
    git("bundle", "verify", str(bundle))
    # Read the working tree, including required evidence ignored by Git. The
    # bundle is only the existing history; edits remain local and unstaged.
    names = set(git("ls-files", "-z").decode().strip("\0").split("\0")) | set(REQUIRED)
    for directory in ("reports", "scripts", "tests", "corpus"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and path.suffix in {".md", ".json", ".jsonl", ".txt", ".xml", ".py", ".log"}:
                names.add(path.relative_to(ROOT).as_posix())
    names.discard("reports/sink.log")
    files = {name: (ROOT / name).read_bytes() for name in names if (ROOT / name).is_file()}
    missing = set(REQUIRED) - files.keys()
    if missing:
        raise SystemExit(f"Missing required local files: {sorted(missing)}")
    assert "reports/sink.log" not in files
    assert not any(name.startswith(".venv/") for name in files)
    assert not files["reports/attack-after.log"]
    assert b"KH-000999" in files["reports/attack-before.log"]
    handoff = f"""# Day 24 L3 submission — Nguyen Quang Minh

Existing source HEAD: `{sha}`
Final submission commit SHA: **not created**; the user requested local-only edits.
All completed changes remain unstaged and uncommitted in the original workspace.

The ZIP includes all required files, supporting evidence, unchanged grading
tests, and GIT-HISTORY.bundle containing the full original Git history.
The bundle does not contain the local lab edits; the ZIP contains those files.
Do not create a new Git repository from extracted files: retain the original
repository, or restore the bundle and overlay the edited files from this ZIP.

From the extracted package directory:

```bash
git clone GIT-HISTORY.bundle restored-lab
cp -a agent corpus reports scripts tests .gitignore .pre-commit-config.yaml requirements.lock injection-corpus.md restored-lab/
cd restored-lab
git rev-parse HEAD
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install pre-commit
```

Install the official Gitleaks v8.30.1 release into PATH, then:

```bash
python -m pytest tests/ -q
gitleaks version
pre-commit install
pre-commit run --all-files
python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
gitleaks git --config .gitleaks.toml --redact --verbose .
```

The history scan intentionally returns exit 1 for one invalid LAB24-DEMO token
at commit 1bdd849. The current-file scan and pre-commit hook pass.
The required tests run a sink only on 127.0.0.1:10024.

Results: 43 tests passed; PII precision/recall 1.000; 4/4 lures ready;
attack-before.log has 5 synthetic POSTs; attack-after.log is intentionally
empty; ledger verifies True with 264 entries. See reports/verification.md.
Legal clauses not verified from original text are explicitly marked
"chưa xác minh" in reports/compliance-mapping.md.

Submit/push the restored repository using the coach/TA's stated destination;
no remote push is performed by this packaging script. .venv and sink.log are
excluded. This package was prepared with AI assistance, which is permitted by
the repository's RULES.md; review the controls and evidence before presenting.
"""
    (output / "HANDOFF.md").write_text(handoff, encoding="utf-8")
    files["HANDOFF.md"] = handoff.encode("utf-8")
    files["GIT-HISTORY.bundle"] = bundle.read_bytes()
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                       for name, data in sorted(files.items()))
    files["SHA256SUMS"] = manifest.encode()
    target = output / f"{ROOT.name}-submission.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zipped:
        for name, data in sorted(files.items()):
            zipped.writestr(f"{ROOT.name}/{name}", data)
    with zipfile.ZipFile(target) as zipped:
        assert zipped.testzip() is None
        for name, data in files.items():
            assert zipped.read(f"{ROOT.name}/{name}") == data
    print(f"Source HEAD (no new commit): {sha}\nArchive: {target}\nFiles: {len(files)}\nBytes: {target.stat().st_size}")


if __name__ == "__main__":
    package()
