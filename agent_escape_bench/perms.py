"""A model of Claude Code deny and ask permission rules, written from the public documentation.

This is not Claude Code's engine and it is not run by Claude Code. It answers one question for
`aeb verify`: would one of the repository's own deny or ask rules stop this tool call? What it models:

* Read and Edit path rules use gitignore patterns. `//p` is absolute, `~/p` is under home, `/p` is
  relative to the settings source (the project root for project settings), `p` and `./p` relative to
  the working directory. A Read deny rule also blocks Edit and Write on the same path.
* Write(path), NotebookEdit(path), Glob(path) and MultiEdit(path) rules never match a path.
* Bash rules match the command text with `*` standing for any text; `:*` at the end equals ` *`.
  Deny and ask rules apply when any subcommand matches, past wrappers and leading assignments.
* Read and Edit deny rules also apply to file commands Claude Code recognizes in Bash (cat, head,
  tail, sed, tee; grep with a named file is treated the same) and to redirect targets. They do not apply to interpreters such as python or node.

Everything else (permission modes, protected paths, the classifier, the sandbox) is outside the model.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

RANK = {"allow": 0, "ask": 1, "deny": 2}
NEVER_MATCHING_PATH_TOOLS = {"Write", "NotebookEdit", "Glob", "MultiEdit"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob"}
READ_COMMANDS = {"cat", "head", "tail", "less", "more"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg"}  # the first argument is the pattern, the rest are files
SEPARATORS = {";", "&&", "||", "|", "|&", "&", "(", ")", "\n"}
OUT_REDIRECTS = {">", ">>", "&>", ">|", "&>>"}
IN_REDIRECTS = {"<"}
FD_REDIRECTS = {">&", "<&"}

# Paths Claude Code itself never auto-approves writes to (except in bypassPermissions mode).
PROTECTED_DIRS = (".git", ".config/git", ".vscode", ".idea", ".husky", ".cargo", ".devcontainer", ".yarn",
                  ".mvn", ".claude")
PROTECTED_FILES = {".gitconfig", ".gitmodules", ".bashrc", ".bash_profile", ".bash_login", ".bash_aliases",
                   ".bash_logout", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".profile", ".envrc",
                   ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnp.cjs", ".pnp.loader.mjs", ".pnpmfile.cjs", "bunfig.toml",
                   ".bunfig.toml", ".bazelrc", ".bazelversion", ".bazeliskrc", ".pre-commit-config.yaml",
                   "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml", "gradle-wrapper.properties",
                   "maven-wrapper.properties", ".devcontainer.json", ".ripgreprc", "pyrightconfig.json", ".mcp.json",
                   ".claude.json"}


def builtin_protected(rel: str) -> bool:
    """Claude Code prompts for writes here in default and acceptEdits modes, whatever the repository says."""
    parts = rel.strip("/").split("/")
    if parts[-1] in PROTECTED_FILES:
        return True
    joined = "/".join(parts)
    return any(joined == d or joined.startswith(d + "/") for d in PROTECTED_DIRS)


@dataclass
class PermRule:
    kind: str  # deny | ask
    tool: str
    spec: str | None
    source: str
    raw: str
    base: str  # what a leading "/" anchors to


@dataclass
class Decision:
    decision: str  # allow | ask | deny
    rule: str = ""
    why: str = ""


def load(repo: Path, findings: list[str] | None = None) -> list[PermRule]:
    rules: list[PermRule] = []
    for f in (repo / ".claude" / "settings.json", repo / ".claude" / "settings.local.json"):
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            continue
        perms = data.get("permissions") or {}
        for kind in ("deny", "ask"):
            for raw in perms.get(kind, []) or []:
                m = re.fullmatch(r"\s*([A-Za-z_][\w-]*)\s*(?:\((.*)\))?\s*", str(raw), re.S)
                if not m:
                    continue
                tool, spec = m.group(1), m.group(2)
                if spec in ("*", ""):
                    spec = None
                rules.append(PermRule(kind, tool, spec, str(f.relative_to(repo)), str(raw), str(repo)))
                if findings is not None and spec is not None and tool in NEVER_MATCHING_PATH_TOOLS:
                    findings.append(f"{f.relative_to(repo)} permissions.{kind} {raw!r} never matches: Claude Code checks "
                                    f"paths against Edit(...) and Read(...) rules only. Use Edit({spec}) instead.")
    return rules


# ---------- paths ----------

def _glob_regex(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


def path_matches(spec: str, path: str, base: str, cwd: str, home: str) -> bool:
    """gitignore-style match of an absolute path against a Read/Edit rule spec."""
    if spec.startswith("//"):
        anchor, pat = "", spec[1:]
    elif spec.startswith("~/"):
        anchor, pat = home, spec[1:]
    elif spec.startswith("/"):
        anchor, pat = base, spec
    else:
        pat = spec[2:] if spec.startswith("./") else spec
        if "/" not in pat.rstrip("/") and not spec.startswith("./"):
            anchor, pat = cwd, "/**/" + pat  # no separator: matches at any depth below cwd
        else:
            anchor, pat = cwd, "/" + pat
    dir_only = pat.endswith("/")
    rx = re.compile(re.escape(anchor.rstrip("/")) + _glob_regex(pat.rstrip("/")))
    candidates = [path]
    p = path
    while True:  # a rule that matches a directory covers everything under it
        p = posixpath.dirname(p)
        if not p or p == "/" or p in candidates:
            break
        candidates.append(p)
    return any(rx.fullmatch(c) for i, c in enumerate(candidates) if not (dir_only and i == 0))


def _file_rules(rules: list[PermRule], tools: set[str], path: str, cwd: str, home: str) -> Decision:
    best = Decision("allow")
    for r in rules:
        if r.tool not in tools or RANK[r.kind] <= RANK[best.decision]:
            continue
        if r.spec is None or (r.tool not in NEVER_MATCHING_PATH_TOOLS and path_matches(r.spec, path, r.base, cwd, home)):
            best = Decision(r.kind, f"{r.source}: {r.raw}")
    return best


def decide_file(rules: list[PermRule], tool: str, path: str, cwd: str, home: str) -> Decision:
    """Read, Edit or Write tool call on an absolute path."""
    if tool == "Read":
        return _file_rules(rules, {"Read"}, path, cwd, home)
    edit = _file_rules(rules, {"Edit", tool}, path, cwd, home)
    read_deny = _file_rules([r for r in rules if r.kind == "deny"], {"Read"}, path, cwd, home)
    if read_deny.decision == "deny":
        read_deny.why = "a Read deny rule also blocks edits"
    return max((edit, read_deny), key=lambda d: RANK[d.decision])


# ---------- Bash ----------

def _drop_heredocs(cmd: str) -> str:
    lines, out, end = cmd.split("\n"), [], None
    for line in lines:
        if end is not None:
            if line.strip() == end:
                end = None
            continue
        out.append(line)
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        if m:
            end = m.group(1)
    return "\n".join(out)


@dataclass
class Simple:
    words: list[str]
    out: list[str]
    inp: list[str]
    cwd: str


def parse_bash(cmd: str, cwd: str) -> list[Simple]:
    """Split a command line into simple commands with their redirects and the directory they run in."""
    text = _drop_heredocs(cmd)
    nested = re.findall(r"\$\(([^()]*)\)|`([^`]*)`", text)
    lex = shlex.shlex(text.replace("\n", " ; "), posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError:
        tokens = text.split()
    out: list[Simple] = []
    cur = Simple([], [], [], cwd)
    stack = [cwd]
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in SEPARATORS or (t and set(t) <= set(";&|()") and t not in OUT_REDIRECTS):
            if cur.words or cur.out or cur.inp:
                out.append(cur)
                cwd = _after(cur, cwd, stack)
            cur = Simple([], [], [], cwd)
        elif t in FD_REDIRECTS:
            i += 1
            if cur.words and re.fullmatch(r"\d+", cur.words[-1]):
                cur.words.pop()
        elif t in OUT_REDIRECTS or t in IN_REDIRECTS or t in ("<<", "<<<", "<<-"):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if t in OUT_REDIRECTS and target and not target.startswith("&"):
                cur.out.append(target)
            elif t in IN_REDIRECTS and target:
                cur.inp.append(target)
            i += 1
            if cur.words and re.fullmatch(r"\d+", cur.words[-1]):
                cur.words.pop()  # 2> file: the 2 is a file descriptor
        else:
            cur.words.append(t)
        i += 1
    if cur.words or cur.out or cur.inp:
        out.append(cur)
    for a, b in nested:
        out += parse_bash(a or b, out[0].cwd if out else cwd)
    return out


def _after(s: Simple, cwd: str, stack: list[str]) -> str:
    if not s.words:
        return cwd
    prog, args = s.words[0], s.words[1:]
    if prog in ("cd", "pushd") and args and not re.search(r"[$`*?~]", args[0]):
        if prog == "pushd":
            stack.append(cwd)
        return posixpath.normpath(posixpath.join(cwd, args[0]))
    if prog == "popd" and len(stack) > 1:
        return stack.pop()
    return cwd


def _strip(words: list[str]) -> list[str]:
    w = list(words)
    while w and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", w[0]):
        w = w[1:]
    while w and w[0] in WRAPPERS:
        prog, w = w[0], w[1:]
        if prog == "timeout":
            while w and w[0].startswith("-"):
                w = w[1:]
            w = w[1:] if w else w  # duration
        elif prog in ("nice", "stdbuf"):
            while w and w[0].startswith("-"):
                w = w[2:] if w[0] in ("-n",) else w[1:]
    if w and w[0] == "xargs" and len(w) > 1 and not w[1].startswith("-"):
        w = w[1:]
    return w


def _bash_rule_matches(spec: str, text: str) -> bool:
    if spec.endswith(":*"):
        spec = spec[:-2] + " *"
    rx = "".join(".*" if ch == "*" else re.escape(ch) for ch in spec)
    if re.fullmatch(rx, text, re.S):
        return True
    return spec.endswith(" *") and spec.count("*") == 1 and text == spec[:-2]


def decide_bash(rules: list[PermRule], cmd: str, root: str, home: str) -> Decision:
    best = Decision("allow")

    def take(d: Decision) -> None:
        nonlocal best
        if RANK[d.decision] > RANK[best.decision]:
            best = d

    for s in parse_bash(cmd, root):
        texts = {" ".join(s.words), " ".join(_strip(s.words))}
        for r in rules:
            if r.tool == "Bash" and (r.spec is None or any(t and _bash_rule_matches(r.spec, t) for t in texts)):
                take(Decision(r.kind, f"{r.source}: {r.raw}"))
        words = _strip(s.words)
        prog, args = (words[0], words[1:]) if words else ("", [])
        files_args = [a for a in args if not a.startswith("-")]
        reads, edits = list(s.inp), list(s.out)
        if prog in READ_COMMANDS:
            reads += files_args
        elif prog in PATTERN_FIRST:
            reads += files_args[1:]
        elif prog == "sed":
            inplace = any(a.startswith("-i") or a.startswith("--in-place") for a in args)
            (edits if inplace else reads).extend(files_args[1:])
        elif prog == "tee":
            edits += files_args
        for rel in reads:
            take(_file_rules(rules, {"Read"}, _abs(rel, s.cwd, home), root, home))
        for rel in edits:
            if rel in ("/dev/null",):
                continue
            take(decide_file(rules, "Edit", _abs(rel, s.cwd, home), root, home))
    return best


def _abs(rel: str, cwd: str, home: str) -> str:
    if rel.startswith("~/"):
        return posixpath.normpath(home + rel[1:])
    return posixpath.normpath(rel if rel.startswith("/") else posixpath.join(cwd, rel))


def decide(rules: list[PermRule], tool: str, tool_input: dict, root: str, home: str) -> Decision:
    if tool == "Bash":
        return decide_bash(rules, str(tool_input.get("command", "")), root, home)
    path = str(tool_input.get("file_path", ""))
    return decide_file(rules, tool, os.path.normpath(path), root, home)
