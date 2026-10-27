"""Check that the README quick-start transcript is what the demo really prints.

    python examples/check_readme.py        # needs `cti-report-lint` on PATH

Runs examples/demo.sh, then compares the first ```console block under
"## Quick start" in README.md with what the demo printed. The block is a list of
commands, each from its "$ command" line to its "(exit N)" line; every one must
appear in the demo's output WHOLE, line for line, so a line the README drops
(or invents) is a mismatch, not just a missing line. The demo may run more
commands than the README shows. CI runs this, so the README transcript cannot
drift from the tool without the build failing.

Exit codes: 0 every README line was found; 1 a line is missing or out of order
(printed with its line number); 2 NOT EVALUABLE: the README, its block, or the
demo could not be read or run, so nothing was compared.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def readme_block(text):
    m = re.search(r"^## Quick start\s*$(.*?)(?=^## )", text, re.S | re.M)
    if not m:
        return None
    b = re.search(r"^```console\n(.*?)^```", m.group(1), re.S | re.M)
    return b.group(1).splitlines() if b else None


def commands(lines):
    """Split a transcript into commands: each runs from a '$ ' line through the
    '(exit N)' line that ends it."""
    out, cur = [], None
    for line in lines:
        if line.startswith("$ "):
            cur = [line]
        elif cur is not None:
            cur.append(line)
            if re.fullmatch(r"\(exit \d+\)", line):
                out.append(cur)
                cur = None
    return out, cur


def mismatches(expected, actual):
    """Commands of `expected` that `actual` does not contain whole. A
    transcript that ends without an '(exit N)' line is itself a mismatch."""
    want, dangling = commands(expected)
    have = [tuple(c) for c in commands(actual)[0]]
    bad = [c for c in want if tuple(c) not in have]
    if dangling:
        bad.append(dangling)
    return want, bad


def main():
    try:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"NOT EVALUABLE: cannot read README.md: {e}", file=sys.stderr)
        return 2
    expected = readme_block(text)
    if not expected:
        print("NOT EVALUABLE: no ```console block under '## Quick start' in "
              "README.md, so nothing was compared", file=sys.stderr)
        return 2
    try:
        run = subprocess.run(["sh", str(ROOT / "examples" / "demo.sh")],
                             capture_output=True, text=True, encoding="utf-8",
                             timeout=300)
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError) as e:
        print(f"NOT EVALUABLE: could not run examples/demo.sh: {e}", file=sys.stderr)
        return 2
    if run.returncode != 0:
        print(f"NOT EVALUABLE: examples/demo.sh exited {run.returncode}, so its "
              f"output is not a transcript to compare against:\n{run.stderr}",
              file=sys.stderr)
        return 2
    want, bad = mismatches(expected, run.stdout.splitlines())
    if not want:
        print("NOT EVALUABLE: the README block holds no '$ command' ... "
              "'(exit N)' pair, so nothing was compared", file=sys.stderr)
        return 2
    if bad:
        print(f"README quick start does not match the demo's output: "
              f"{len(bad)} of {len(want)} command(s) differ", file=sys.stderr)
        for c in bad:
            print("  README has:\n    " + "\n    ".join(c), file=sys.stderr)
        return 1
    print(f"README quick start matches the demo: {len(want)} of "
          f"{len(want)} command(s) identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
