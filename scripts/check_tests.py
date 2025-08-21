"""Script to verify 1:1 mapping between src/wazuh_dfn and tests/ per README rules.

Usage: python scripts/check_tests.py

Exits with code 0 if all expected tests exist; prints a report and exits 1 if missing.
"""
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "wazuh_dfn"
TESTS_ROOT = Path(__file__).resolve().parents[1] / "tests"

expect = []

# Walk src and build expected test paths
for p in SRC_ROOT.rglob("*.py"):
    # skip package init files
    if p.name == "__init__.py":
        continue
    # compute relative path under src/wazuh_dfn
    rel = p.relative_to(SRC_ROOT)
    # target test path under tests mirroring rel
    target = TESTS_ROOT / rel.parent / f"test_{p.stem}.py"
    expect.append((p, target))

missing = []
for srcp, testp in expect:
    if not testp.exists():
        missing.append((str(srcp.relative_to(SRC_ROOT)), str(testp.relative_to(TESTS_ROOT))))

if missing:
    print("Missing test files (source -> expected test):")
    for s, t in missing:
        print(f"  {s} -> {t}")
    raise SystemExit(1)

print("All expected test files exist.")
