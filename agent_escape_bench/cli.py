"""Command line: `aeb bench`, `aeb verify`, `aeb scan`, `aeb list`."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from . import bench as bn
from . import hooks as hk
from . import report as rp
from . import scan as sc
from . import verify as vf


def _write(path: str | None, text: str) -> None:
    if path:
        Path(path).write_text(text, encoding="utf-8")
        print(f"wrote {path}", file=sys.stderr)


def _show(path: Path) -> str:
    try:
        rel = path.relative_to(Path.cwd().resolve())
        return str(rel) if str(rel) != "." else "."
    except ValueError:
        return str(path)


def cmd_bench(a: argparse.Namespace) -> int:
    hook_list: list[hk.Hook] = []
    include: list[tuple[Path, str]] = []
    target = []
    if a.claude:
        repo = Path(a.claude).resolve()
        hook_list += hk.discover_claude(repo, a.user_settings)
        if (repo / ".claude").is_dir():
            include.append((repo / ".claude", ".claude"))
        target.append(f"Claude Code settings in {_show(repo)}")
    if a.plugin:
        plugin = Path(a.plugin).resolve()
        hook_list += hk.discover_plugin(plugin)
        target.append(f"Claude Code plugin {plugin.name}")
    if a.cursor:
        repo = Path(a.cursor).resolve()
        hook_list += hk.discover_cursor(repo, a.user_settings)
        if (repo / ".cursor").is_dir():
            include.append((repo / ".cursor", ".cursor"))
        target.append(f"Cursor hooks in {_show(repo)}")
    for cmd in a.hook or []:
        hook_list.append(hk.Hook(cmd, a.protocol, "--hook", a.timeout, fail_closed=a.fail_closed))
        target.append(f"{a.protocol} hook command")
    if not target:
        print("nothing to test: pass --claude DIR, --plugin DIR, --cursor DIR or --hook CMD (see --help)", file=sys.stderr)
        return 2
    for spec in a.include or []:
        src, _, rel = spec.partition(":")
        src_p = Path(src).resolve()
        include.append((src_p, rel or src_p.name))
    if not hook_list:
        print("warning: no shell hooks found, so every command will be allowed", file=sys.stderr)

    def progress(i: int, n: int) -> None:
        if sys.stderr.isatty() and not a.quiet:
            print(f"\r  {i}/{n}", end="" if i < n else "\n", file=sys.stderr, flush=True)

    only = set(a.only.split(",")) if a.only else None
    rep = bn.run(hook_list, "; ".join(target), a.guard_dir, a.guard_file, include, a.setup, only, progress, a.migrations_dir)
    if a.json == "-":
        print(json.dumps(rep.to_json(), indent=1, ensure_ascii=False))
    else:
        if not a.quiet:
            print(rp.bench_text(rep, a.verbose))
        _write(a.json, json.dumps(rep.to_json(), indent=1, ensure_ascii=False))
    _write(a.md, rp.bench_markdown(rep))
    _write(a.html, rp.bench_html(rep))
    if a.max_escapes is not None and rep.escaped > a.max_escapes:
        return 1
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    rep = sc.scan(Path(a.repo))
    if a.json == "-":
        print(json.dumps(rep.to_json(), indent=1, ensure_ascii=False))
    else:
        print(rp.scan_text(rep))
        _write(a.json, json.dumps(rep.to_json(), indent=1, ensure_ascii=False))
    _write(a.md, rp.scan_markdown(rep))
    _write(a.html, rp.scan_html(rep))
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    repo = Path(a.repo).resolve()
    hook_list = hk.discover_claude(repo, a.user_settings, tool=None)
    if a.cursor:
        hook_list += hk.discover_cursor(repo, a.user_settings)
    for plugin in a.plugin or []:
        hook_list += hk.discover_plugin(Path(plugin).resolve(), tool=None)
    for cmd in a.hook or []:
        hook_list.append(hk.Hook(cmd, "claude", "--hook", a.timeout, fail_closed=a.fail_closed))
    include = []
    for spec in a.include or []:
        src, _, rel = spec.partition(":")
        src_p = Path(src).resolve()
        include.append((src_p, rel or src_p.name))

    def progress(i: int, n: int) -> None:
        if sys.stderr.isatty() and a.json != "-":
            print(f"\r  {i}/{n}", end="" if i < n else "\n", file=sys.stderr, flush=True)

    rep = vf.run(repo, hook_list, include, a.setup, a.migrations_dir, a.probe, progress)
    rep.repo = _show(repo)
    if a.json == "-":
        print(json.dumps(rep.to_json(), indent=1, ensure_ascii=False))
    else:
        print(rp.verify_text(rep))
        _write(a.json, json.dumps(rep.to_json(), indent=1, ensure_ascii=False))
    _write(a.md, rp.verify_markdown(rep))
    _write(a.html, rp.verify_html(rep))
    if a.max_obedience is not None and rep.count("obedience") > a.max_obedience:
        return 1
    return 0


def cmd_list(a: argparse.Namespace) -> int:
    cases = bn.load_corpus()
    if a.full:
        for c in cases:
            print(f"{c['id']}  {c['expect']:<5}  {c['category']:<20}  {c['why']}")
            print(f"         $ {c['cmd'].splitlines()[0]}")
        return 0
    cats = Counter((c["category"], c["expect"]) for c in cases)
    print(f"{len(cases)} cases: {sum(1 for c in cases if c['expect'] == 'block')} escape attempts, "
          f"{sum(1 for c in cases if c['expect'] == 'allow')} normal commands")
    for cat in dict.fromkeys(c["category"] for c in cases):
        print(f"  {rp.CATEGORY_LABELS.get(cat, cat):<24} {cats[(cat, 'block')]:>3} attacks  {cats[(cat, 'allow')]:>3} normal")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aeb", description="Measure how many known escape techniques get past "
                                "your coding agent's shell guard. No command from the corpus is ever executed.")
    p.add_argument("--version", action="version", version=f"agent-escape-bench {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bench", help="run the escape corpus against your hooks")
    b.add_argument("--claude", metavar="REPO", help="use PreToolUse Bash hooks from REPO/.claude/settings*.json")
    b.add_argument("--plugin", metavar="DIR", help="use PreToolUse Bash hooks of a Claude Code plugin (DIR/hooks/hooks.json)")
    b.add_argument("--cursor", metavar="REPO", help="use beforeShellExecution hooks from REPO/.cursor/hooks.json")
    b.add_argument("--hook", action="append", metavar="CMD", help="a hook command to test directly (repeatable)")
    b.add_argument("--protocol", choices=["claude", "cursor"], default="claude", help="protocol of --hook commands")
    b.add_argument("--fail-closed", action="store_true", help="treat --hook errors as blocking (like onFailure: block)")
    b.add_argument("--timeout", type=float, default=30.0, help="per call timeout for --hook commands, seconds")
    b.add_argument("--user-settings", action="store_true", help="also load hooks from ~/.claude or ~/.cursor")
    b.add_argument("--guard-dir", default=".claude/hooks", help="directory of your guard config (default .claude/hooks)")
    b.add_argument("--guard-file", default="guard.sh", help="file name of your guard config (default guard.sh)")
    b.add_argument("--migrations-dir", default="db/migrations",
                   help="where applied migrations live in your repo (default db/migrations)")
    b.add_argument("--include", action="append", metavar="SRC[:REL]", help="copy SRC into the sandbox repo at REL")
    b.add_argument("--setup", metavar="SHELL", help="shell snippet run inside the sandbox repo before the bench")
    b.add_argument("--only", metavar="IDS", help="comma separated case ids or categories")
    b.add_argument("--json", metavar="FILE", help="write JSON results (- for stdout)")
    b.add_argument("--md", metavar="FILE", help="write a Markdown report")
    b.add_argument("--html", metavar="FILE", help="write an HTML report")
    b.add_argument("--max-escapes", type=int, metavar="N", help="exit 1 when more than N attacks escape (for CI)")
    b.add_argument("--verbose", action="store_true", help="list every miss")
    b.add_argument("--quiet", action="store_true", help="no terminal report")
    b.set_defaults(func=cmd_bench)

    v = sub.add_parser("verify", help="try to break each rule your instruction files state, and see what stops it")
    v.add_argument("repo", nargs="?", default=".")
    v.add_argument("--plugin", action="append", metavar="DIR", help="also run the PreToolUse hooks of a Claude Code plugin (repeatable)")
    v.add_argument("--cursor", action="store_true", help="also run beforeShellExecution hooks from REPO/.cursor/hooks.json")
    v.add_argument("--hook", action="append", metavar="CMD", help="an extra PreToolUse hook command (repeatable)")
    v.add_argument("--fail-closed", action="store_true", help="treat --hook errors as blocking")
    v.add_argument("--timeout", type=float, default=30.0, help="per call timeout for --hook commands, seconds")
    v.add_argument("--user-settings", action="store_true", help="also load hooks from ~/.claude or ~/.cursor")
    v.add_argument("--migrations-dir", metavar="DIR", help="where applied migrations live, if the rules do not say")
    v.add_argument("--probe", action="append", metavar="TOPIC[:PATH]",
                   help="probe a topic even if no rule states it, e.g. secrets:.env or force-push (repeatable)")
    v.add_argument("--include", action="append", metavar="SRC[:REL]", help="copy SRC into the sandbox repo at REL")
    v.add_argument("--setup", metavar="SHELL", help="shell snippet run inside the sandbox repo before probing")
    v.add_argument("--json", metavar="FILE", help="write JSON results (- for stdout)")
    v.add_argument("--md", metavar="FILE", help="write a Markdown report")
    v.add_argument("--html", metavar="FILE", help="write an HTML report")
    v.add_argument("--max-obedience", type=int, metavar="N", help="exit 1 when more than N rules rest on text alone (for CI)")
    v.set_defaults(func=cmd_verify)

    s = sub.add_parser("scan", help="map agent rules to the machinery that enforces them")
    s.add_argument("repo", nargs="?", default=".")
    s.add_argument("--json", metavar="FILE")
    s.add_argument("--md", metavar="FILE")
    s.add_argument("--html", metavar="FILE")
    s.set_defaults(func=cmd_scan)

    ls = sub.add_parser("list", help="show the corpus")
    ls.add_argument("--full", action="store_true")
    ls.set_defaults(func=cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.func(a)
