"""Command line: `cti-report-lint`.

    cti-report-lint check REPORT [--min-5w1h N] [--findings-required-from DATE] [--json]
    cti-report-lint redact IN --map MAP [-o OUT]
    cti-report-lint restore IN --map MAP [-o OUT]

Exit codes for `check`:

    0   the report passes every check
    1   BLOCKED: at least one issue (each is printed with its reason)
    2   NOT EVALUABLE: the report is missing, a directory, not valid UTF-8, or
        otherwise unreadable. Never a pass, and not a block either: the tool
        could not look.
    64  usage error

Exit codes for `redact` and `restore`:

    0   done
    1   refused: restore found a placeholder the map does not hold or one
        from another map, or redact was given text that already carries
        this map's placeholders
    2   redact: the output would not restore byte-exact (nothing written);
        an input or map is missing, unreadable or malformed, or an output
        could not be written (nothing partial is left behind)
    64  usage error, including input, map and output naming the same file

The map holds every original value, so it is created with mode 0600 and
replaced atomically: a crash mid-write never leaves a half map beside a
redacted report. With -o, redact stages the output and the map and replaces
the output first, so a failed write leaves the previous map untouched.
Input is read and output written without newline translation, so CRLF and
CR files round-trip byte for byte.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from . import redact as redaction
from . import identifiers
from . import standards as analytic
from . import validate

EXIT_PASS, EXIT_BLOCKED, EXIT_NOT_EVALUABLE, EXIT_USAGE = 0, 1, 2, 64

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _date_arg(value: str) -> str:
    try:
        ok = bool(_DATE.fullmatch(value)) and bool(datetime.date.fromisoformat(value))
    except ValueError:
        ok = False
    if not ok:
        # shape alone let "2026-99-99" through, and it sorts after every
        # real date, so it grandfathered every report
        raise argparse.ArgumentTypeError(
            f"expected a real YYYY-MM-DD date, got {value!r}")
    return value


def _min_5w1h_arg(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected an integer 0-6, got {value!r}") from None
    if not 0 <= n <= 6:
        raise argparse.ArgumentTypeError(f"expected an integer 0-6, got {n}")
    return n


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="cti-report-lint",
        description="Check that an incident or threat-intelligence report claims "
                    "only what its evidence supports, and redact personal data "
                    "in a way you can reverse exactly.",
        epilog="Exit codes: 0 pass or done, 1 blocked or refused, "
               "2 could not evaluate (never a pass), 64 usage error.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    c = sub.add_parser("check", help="run every check on one Markdown report")
    c.add_argument("report", type=Path,
                   help="the Markdown report to check (evidence goes in its YAML frontmatter)")
    c.add_argument("--min-5w1h", type=_min_5w1h_arg,
                   default=validate.DEFAULT_MIN_5W1H, metavar="N",
                   help="how many of who/what/when/where/why/how the report "
                        "must answer (default: %(default)s)")
    c.add_argument("--findings-required-from", type=_date_arg, default=None,
                   metavar="DATE",
                   help="YYYY-MM-DD. Reports dated before DATE may omit "
                        "findings (they pass, marked as grandfathered). "
                        "Default: off, so every report must declare findings.")
    c.add_argument("--json", action="store_true",
                   help="machine-readable result on stdout")
    c.add_argument("--attack-json", type=Path, default=None, metavar="FILE",
                   help="an enterprise-attack STIX bundle: check ATT&CK technique ids "
                        "(without it they are reported NOT CHECKED)")
    c.add_argument("--kev-json", type=Path, default=None, metavar="FILE",
                   help="CISA's KEV catalog: check exploited-in-the-wild claims "
                        "(without it they are reported NOT CHECKED)")

    k = sub.add_parser("skeleton", help="print a findings block for a report that has none "
                                        "(one finding per likelihood judgment; writes nothing)")
    k.add_argument("report", type=Path, help="a report with no findings block yet")

    for name, what in (("redact", "replace personal data with placeholders"),
                       ("restore", "put the original text back")):
        sp = sub.add_parser(name, help=what)
        sp.add_argument("input", type=Path,
                        help="the report to redact" if name == "redact"
                        else "the redacted report to restore")
        sp.add_argument("--map", type=Path, required=True,
                        help="the JSON map of placeholder to original value. "
                             "redact writes it (and reuses it if it exists, to keep "
                             "numbering consistent across files); restore reads it")
        sp.add_argument("-o", "--output", type=Path,
                        help="write the result here (default: print to stdout)")
    return ap


def _check(args: argparse.Namespace) -> int:
    if args.report.is_dir():
        print(f"NOT EVALUABLE: {args.report} is a directory; check takes one "
              "report file. This is not a pass and not a block.", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    if not args.report.is_file():
        why = ("is not a regular file" if args.report.exists()
               else "not found")
        print(f"NOT EVALUABLE: report {why}: {args.report}. This is not a "
              "pass and not a block.", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    refs = {}
    for key, path, loader in (("attack", args.attack_json, identifiers.load_attack),
                              ("kev", args.kev_json, identifiers.load_kev)):
        if path is None:
            continue
        try:
            refs[key] = loader(path)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            print(f"NOT EVALUABLE: reference file {path} could not be used ({e.__class__.__name__}: "
                  f"{e}). This is not a pass and not a block.", file=sys.stderr)
            return EXIT_NOT_EVALUABLE
    try:
        r = validate.validate_report(
            args.report, min_5w1h=args.min_5w1h,
            findings_required_from=args.findings_required_from,
            attack=refs.get("attack"), kev=refs.get("kev"))
    except OSError as e:
        print(f"NOT EVALUABLE: cannot read {args.report}: {e}. This is not a "
              "pass and not a block.", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    except UnicodeDecodeError as e:
        print(f"NOT EVALUABLE: {args.report} is not valid UTF-8 ({e.reason} at "
              f"byte {e.start}), so it was not checked. This is not a pass and "
              "not a block.", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        verdict = "PASS" if r["verified_ok"] else "BLOCKED"
        print(f"{args.report}: {verdict}  "
              f"(5W1H {r['coverage_5w1h']}/6, "
              f"{len(r['findings_graded'])} graded finding(s), "
              f"{len(r['conflicts'])} conflict(s))")
        if r.get("findings_grandfathered"):
            # Loud on a pass, on purpose: checks 3-5 evaluated nothing here.
            print(f"  NOTE: no findings declared — GRANDFATHERED "
                  f"(dated {r['report_date']}, before the "
                  f"{args.findings_required_from} ratchet). Checks 3-5 "
                  f"evaluated nothing on this report.")
        for issue in r["issues"]:
            print(f"  {issue}")
        for key, label, flag in (("attack", "ATT&CK technique id(s)", "--attack-json"),
                                 ("kev", "exploited-in-the-wild claim(s)", "--kev-json")):
            info = r["identifiers"][key]
            if info["ids"] and not info["checked"]:
                print(f"  NOTE: {info['ids']} {label} NOT CHECKED (no {flag})")
        for c in r["conflicts"]:
            if c.get("resolution") == "HUMAN_RESOLVED":
                print(f"  conflicts[{c['index']}]: {c['severity']} {c['ctype']} on "
                      f"'{c['subject']}' resolved by {c['decided_by']} "
                      f"(winner: {c['winner'] or 'neither'}): {c['decision_note']}")
        for g in r["findings_graded"]:
            print(f"  finding[{g['index']}] {g['type']} strength "
                  f"{g['strength']:.1f}"
                  + (f" likelihood '{g['likelihood']}'"
                     if g["likelihood"] else "")
                  + (f", {g['independent_sources']} independent source(s)"
                     if g.get("independent_sources") is not None else ""))
    return EXIT_PASS if r["verified_ok"] else EXIT_BLOCKED


def _no_duplicate_keys(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r} in map")
        out[k] = v
    return out


def _read_json_map(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=_no_duplicate_keys)
    if not isinstance(data, dict):
        raise ValueError("map must be a JSON object")
    redaction.map_nonce(data)          # raises ValueError on a malformed map
    return data


def _stage(path: Path, text: str, *, private: bool) -> str:
    """Write `text` to a temp file beside `path` and return its name. Nothing
    is visible at `path` until _commit. Newlines are written as given
    (newline=""), so CRLF and CR input round-trip byte for byte."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent) or ".", prefix=f".{path.name}.",
                               suffix=".tmp")
    try:
        # mkstemp creates the file 0600 on POSIX, independent of the umask
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        if not private:
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp, 0o666 & ~umask)
    except BaseException:
        _discard(tmp)
        raise
    return tmp


def _discard(tmp: str) -> None:
    try:
        os.unlink(tmp)
    except OSError:
        pass


def _write_private(path: Path, text: str) -> None:
    """Atomically replace `path` with `text`, created 0600 whatever the umask."""
    tmp = _stage(path, text, private=True)
    try:
        os.replace(tmp, path)
    except BaseException:
        _discard(tmp)
        raise


@contextlib.contextmanager
def _map_lock(path: Path):
    """Exclusive lock on a stable sibling file for the whole read-allocate-
    commit of a redaction, so two writers on one map serialize instead of
    both allocating the same placeholder. Works across processes and threads
    (a separate open file description per call). The lock file is left in
    place: removing it would let a waiter lock a deleted inode."""
    lock = path.parent / f".{path.name}.lock"
    fh = open(lock, "a+b")
    try:
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except ImportError:                       # Windows
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        fh.close()                                # releases the lock


def _commit_pair(out_path: Path, out_text: str, map_path: Path,
                 map_text: str) -> None:
    """Publish output then map. If the map cannot be published the previous
    output is put back, so a failure leaves the pair as it was. Raises OSError
    whose text says what state the files are in."""
    staged: list[str] = []
    backup = None
    replaced = False
    try:
        staged.append(_stage(out_path, out_text, private=False))
        staged.append(_stage(map_path, map_text, private=True))
        if out_path.exists():
            fd, backup = tempfile.mkstemp(dir=str(out_path.parent) or ".",
                                          prefix=f".{out_path.name}.", suffix=".bak.tmp")
            os.close(fd)
            shutil.copy2(out_path, backup)
        os.replace(staged[0], out_path)
        replaced = True
        os.replace(staged[1], map_path)
    except OSError as e:
        for tmp in staged:
            _discard(tmp)
        state = "Nothing was changed."
        if replaced:
            try:
                if backup is not None:
                    os.replace(backup, out_path)
                    backup = None
                else:
                    os.unlink(out_path)
            except OSError as e2:
                state = (f"{out_path} WAS CHANGED and could not be put back "
                         f"({e2}); it no longer matches {map_path}"
                         + (f". Its previous content is in {backup}" if backup else ""))
                backup = None                    # keep the only copy
        raise OSError(f"{e}. {state}") from e
    finally:
        if backup is not None:
            _discard(backup)


def _same_file(a: Path, b: Path) -> bool:
    try:
        if a.resolve() == b.resolve():
            return True
        # a hard link has two names and one inode
        return a.exists() and b.exists() and os.path.samefile(a, b)
    except OSError:
        return False


def _do_redact(args: argparse.Namespace, prog: str, text: str) -> tuple[int | None, str]:
    """Redact under the map lock. Returns (exit code, redacted text); the code is
    None when the caller still has to write the text to stdout."""
    seed = {}
    if args.map.exists():
        try:
            seed = _read_json_map(args.map)
        except (OSError, ValueError) as e:
            print(f"{prog}: cannot read seed map {args.map}: {e}",
                  file=sys.stderr)
            return EXIT_NOT_EVALUABLE, ''
    try:
        out, mapping = redaction.redact(text, seed)
    except ValueError as e:
        print(f"{prog}: refused: {e}", file=sys.stderr)
        return EXIT_BLOCKED, ''
    except redaction.RoundTripError as e:
        print(f"{prog}: {e}", file=sys.stderr)
        return EXIT_NOT_EVALUABLE, ''
    except AssertionError as e:
        # overlapping spans from find_spans: a bug, never an input; refuse
        # like any other failed self-check instead of a traceback
        print(f"{prog}: redaction would not restore byte-exact; nothing "
              f"written ({e})", file=sys.stderr)
        return EXIT_NOT_EVALUABLE, ''
    map_text = json.dumps(mapping, indent=2, ensure_ascii=False)
    if args.output:
        try:
            _commit_pair(args.output, out, args.map, map_text)
        except OSError as e:
            print(f"{prog}: cannot write {args.output} or {args.map}: {e}",
                  file=sys.stderr)
            return EXIT_NOT_EVALUABLE, ''
    else:
        try:
            _write_private(args.map, map_text)
        except OSError as e:
            print(f"{prog}: cannot write map {args.map}: {e}. Nothing was "
                  "written.", file=sys.stderr)
            return EXIT_NOT_EVALUABLE, ''
    n_new = len(mapping) - len(seed)
    print(f"redacted {len(mapping)} span(s) ({n_new} new); map -> "
          f"{args.map}", file=sys.stderr)
    if args.output:
        return EXIT_PASS, out
    return None, out


def _redact_or_restore(args: argparse.Namespace) -> int:
    prog = f"cti-report-lint {args.cmd}"
    named = [("input", args.input), ("--map", args.map)]
    if args.output:
        named.append(("--output", args.output))
    for i, (na, pa) in enumerate(named):
        for nb, pb in named[i + 1:]:
            if _same_file(pa, pb):
                print(f"{prog}: error: {na} and {nb} are the same file ({pa}); "
                      "that would overwrite data the other needs", file=sys.stderr)
                return EXIT_USAGE
    try:
        # newline="": no universal-newline translation, so \r\n and \r survive
        with open(args.input, encoding="utf-8", newline="") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        print(f"{prog}: cannot read {args.input}: {e}", file=sys.stderr)
        return EXIT_NOT_EVALUABLE

    if args.cmd == "redact":
        with _map_lock(args.map):
            rc, out = _do_redact(args, prog, text)
        if rc is not None:
            return rc
    else:
        try:
            mapping = _read_json_map(args.map)
        except (OSError, ValueError) as e:
            print(f"{prog}: cannot read map {args.map}: {e}", file=sys.stderr)
            return EXIT_NOT_EVALUABLE
        try:
            out = redaction.restore(text, mapping)
        except KeyError as e:
            print(e.args[0] if e.args else "restore refused", file=sys.stderr)
            return EXIT_BLOCKED

    try:
        if args.output:
            # restore writes the ORIGINAL personal data: same care as the map
            _write_private(args.output, out)
        else:
            _write_stdout(out)
    except OSError as e:
        print(f"{prog}: cannot write output {args.output}: {e}", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    return EXIT_PASS


def _write_stdout(text: str) -> None:
    """Write text to stdout exactly: through the byte buffer when there is
    one, so no platform newline translation touches \r\n or \r."""
    buf = getattr(sys.stdout, "buffer", None)
    if buf is None:
        sys.stdout.write(text)
        return
    sys.stdout.flush()
    buf.write(text.encode("utf-8"))
    buf.flush()


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        # argparse exits 2 on a usage error, which would read as NOT EVALUABLE.
        return EXIT_PASS if e.code in (0, None) else EXIT_USAGE
    if args.cmd == "check":
        return _check(args)
    if args.cmd == "skeleton":
        return _skeleton(args)
    return _redact_or_restore(args)


def _skeleton(args: argparse.Namespace) -> int:
    """Print a frontmatter `findings:` block with one finding per likelihood judgment in the
    prose. Every finding starts at the WEAKEST grade (ANECDOTAL, trust 1, reliability F, nothing
    confirming it), so the report blocks until the analyst grades the evidence. The report is
    never written."""
    try:
        text = args.report.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"NOT EVALUABLE: {args.report} could not be read ({e.__class__.__name__})",
              file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    text = text[1:] if text.startswith("\ufeff") else text
    fm, body = validate._split_frontmatter(text)
    if fm is None:
        print(f"NOT EVALUABLE: {args.report} has frontmatter that cannot be parsed; fix it first",
              file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    if fm.get("findings"):
        print(f"{args.report} already declares {len(fm['findings'])} finding(s); nothing to add",
              file=sys.stderr)
        return EXIT_BLOCKED
    line0 = text[:len(text) - len(body)].count("\n")
    terms = analytic.prose_terms(body)
    # a report that already has frontmatter gets lines to paste inside it; a plain report gets
    # a whole fenced block to put at its top
    fenced = not text.startswith("---")
    out = (["---"] if fenced else []) + ["findings:"]
    for off, term, said in terms:
        out += [f"  # line {line0 + body.count(chr(10), 0, off) + 1}: \"{said}\"",
                "  - finding_type: ANECDOTAL   # PRIMARY | CONFIRMED | DERIVED | ANECDOTAL | CONTESTED",
                "    trust_score: 1            # 1-5, the evidence you actually have",
                "    source_reliability: F     # A-F (Admiralty)",
                "    confirmed_by: []          # what independently confirms it",
                f"    likelihood: {term}"]
    if not terms:
        out += ["  []   # no likelihood judgment found in the prose"]
    if fenced:
        out.append("---")
    print("\n".join(out))
    where = (f"Put this block at the top of {args.report}" if fenced else
             f"Paste these lines inside the frontmatter of {args.report} (between its --- lines)")
    print(f"{len(terms)} judgment(s) found. {where}; each finding starts at the weakest grade, "
          "so grade the real evidence before it can pass.", file=sys.stderr)
    return EXIT_PASS
