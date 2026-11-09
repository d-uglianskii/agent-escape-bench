"""Static scan: which agent rules are enforced by machinery, and which rest on text alone.

The scanner reads agent instruction files (CLAUDE.md, AGENTS.md, Cursor rules, ...),
extracts directive sentences, sorts them into topics and looks for mechanical
enforcement of each topic: agent hooks, permission rules, CI jobs, git hooks,
CODEOWNERS. It is a heuristic map, not a proof: it tells you where to look.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

INSTRUCTION_GLOBS = [
    "CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", ".claude/rules/**/*.md", "AGENTS.md", "**/AGENTS.md",
    "GEMINI.md", ".cursorrules", ".cursor/rules/**/*.mdc", ".cursor/rules/**/*.md", ".windsurfrules",
    ".github/copilot-instructions.md", ".github/instructions/**/*.md",
]
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

DIRECTIVE = re.compile(
    r"^(run|use|keep|prefer|ask|make sure|ensure)\b"
    r"|\b(never|don't|do not|must|must not|always|only|avoid|forbidden|prohibited|should not|shouldn't|required?)\b"
    r"|(никогда|нельзя|запрещ|всегда|только|обязательно|должн|неизменя|не\s+(трогай|меняй|правь|редактируй|коммить|используй|удаляй|запускай|читай|пиши|добавляй|делай|пушь))"
    r"|\bне\s+\w+(ать|ять|еть|ить)\b|\b(immutable|read[ -]only)\b",
    re.I)
# A list under a heading like "Forbidden" or "Never" is a list of rules even when items carry no directive word.
PROHIBITIVE_HEADING = re.compile(r"запрещ|нельзя|никогда|не делай|\bnever\b|don'?t|do not|forbidden|prohibited|"
                                 r"must not|off[ -]limits|not allowed", re.I)

# topic: (keywords in the rule, evidence matchers)
TOPICS: dict[str, dict] = {
    "migrations": {"label": "Applied migrations are immutable",
                   "kw": r"migrat|миграц", "ev": r"migrat"},
    "ci-config": {"label": "CI / workflow files are off limits",
                  "kw": r"\.github|workflows?\b|ci config|ci files?|pipeline|пайплайн|конфиг ci", "ev": r"\.github|workflow"},
    "agent-config": {"label": "Agent settings and hooks are off limits",
                     "kw": r"settings\.json|\.claude|\.cursor|hooks?\b.*(agent|claude)|настройк", "ev": r"\.claude|settings\.json|\.cursor"},
    "secrets": {"label": "Secrets and .env stay private",
                "kw": r"\.env\b|secret|\btokens?\b(?!\.\w)|api[ _-]?key|credential|password|секрет|токен|парол", "ev": r"\.env|secret|gitleaks|trufflehog|detect-secrets"},
    "tests": {"label": "Tests must pass",
              "kw": r"\btests?\b|pytest|jest|vitest|go test|cargo test|тест", "ev": r"pytest|jest|vitest|go test|cargo test|npm (run )?test|pnpm test|yarn test|make test|\btest\b"},
    "lint-types": {"label": "Lint, format and types must pass",
                   "kw": r"lint|eslint|prettier|format|typecheck|tsc\b|mypy|ruff|types?\b|линт|тип", "ev": r"lint|eslint|prettier|tsc|typecheck|mypy|ruff|golangci|clippy|biome"},
    "git-hooks": {"label": "Do not skip git hooks",
                  "kw": r"no-verify|pre-commit|-n\b.*commit|git hooks?", "ev": r"no-verify|hooksPath|pre-commit|husky|lefthook"},
    "force-push": {"label": "No force push / history rewrite",
                   "kw": r"force|push --force|-f\b.*push|reset --hard|rebase|history", "ev": r"force|reset --hard"},
    "lockfiles": {"label": "Lockfiles are not edited by hand",
                  "kw": r"lock ?file|package-lock|yarn\.lock|pnpm-lock|go\.sum|poetry\.lock|cargo\.lock|lock-файл", "ev": r"lock ?file|package-lock|yarn\.lock|pnpm-lock|go\.sum|poetry\.lock|cargo\.lock|frozen-lockfile|npm ci\b|--locked"},
    "generated": {"label": "Generated files are not edited by hand",
                  "kw": r"generated|codegen|autogen|сгенерир|генерир", "ev": r"generated|codegen|git diff --exit-code"},
    "dependencies": {"label": "No new dependencies without approval",
                     "kw": r"dependenc|\bpackages?\b(?!-lock)|librar|зависимост|библиотек", "ev": r"npm (i|install|add)|pip install|poetry add|go get|cargo add|yarn add|pnpm add",
                     "ev_ci": r"dependency-review|license-check|licensee|pip-audit|npm audit|osv-scanner"},
    "destructive": {"label": "No destructive commands",
                    "kw": r"rm -rf|drop table|truncate|delete|destructive|удал", "ev": r"rm -rf|rm\b|drop|truncate|delete"},
}
JUDGMENT = re.compile(r"scope|refactor|minimal|small (pr|change)|ask (before|first)|explain|style|naming|readab|honest|invent|verified|"
                      r"рефактор|объясн|спрашивай|уточн|стил|выдумыва|проверено|обход|инструкци|по .*плану", re.I)

# Rules about what the agent claims or reports cannot be checked by a mechanism, whatever words they contain.
HONESTY = re.compile(r"не проверен|не запускал|без проверки|нельзя писать|что не проверено|not verified|unverified|"
                     r"never claim|don'?t claim|honest|invent|выдумыва", re.I)

PATH_TOPICS = {"migrations", "ci-config", "agent-config", "secrets", "lockfiles", "generated"}

# Which tool a permission rule uses decides which topics it can be evidence for.
PERMISSION_TOPICS = {
    "file": {"migrations", "ci-config", "agent-config", "secrets", "lockfiles", "generated"},
    "bash": {"git-hooks", "force-push", "destructive", "dependencies", "secrets"},
}

CI_FILES = [".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", "bitbucket-pipelines.yml",
            ".circleci/config.yml", "azure-pipelines.yml", "Jenkinsfile", ".buildkite/*.yml"]
GIT_HOOK_FILES = [".pre-commit-config.yaml", ".husky/*", "lefthook.yml", "lefthook.yaml", ".lefthook.yml"]


@dataclass
class Rule:
    text: str
    file: str
    line: int
    topic: str = ""
    status: str = ""  # enforced | partial | text-only | judgment | unclassified
    evidence: list[str] = field(default_factory=list)


@dataclass
class Mechanism:
    kind: str  # agent-hook | permission | ci | git-hook | codeowners
    where: str
    text: str  # what it runs / matches, lowercased for matching


@dataclass
class ScanReport:
    repo: str
    instruction_files: list[str]
    rules: list[Rule]
    mechanisms: list[Mechanism]
    findings: list[str]

    def counted(self) -> list[Rule]:
        return [r for r in self.rules if r.status in ("enforced", "partial", "text-only")]

    def share(self) -> float:
        c = self.counted()
        if not c:
            return 0.0
        return (sum(1 for r in c if r.status == "enforced") + 0.5 * sum(1 for r in c if r.status == "partial")) / len(c)

    def to_json(self) -> dict:
        return {"tool": "agent-escape-bench scan", "repo": self.repo, "instruction_files": self.instruction_files,
                "enforced_share": round(self.share(), 3),
                "rules": [asdict(r) for r in self.rules], "mechanisms": [asdict(m) for m in self.mechanisms],
                "findings": self.findings}


def _glob(repo: Path, patterns: list[str]) -> list[Path]:
    seen, out = set(), []
    for pat in patterns:
        for p in sorted(repo.glob(pat)):
            if p.is_file() and not (set(p.relative_to(repo).parts) & SKIP_DIRS) and p not in seen:
                seen.add(p)
                out.append(p)
    return out


def extract_rules(path: Path, repo: Path) -> list[Rule]:
    rules, in_code, heading = [], False, ""
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        item = re.match(r"^([-*+]|\d+[.)])\s+", line)
        if line.startswith("#") or (line.endswith(":") and len(line) < 80 and not item):
            heading = line
        if not line or line.startswith(("#", "|", "---", "<!--")) or len(line) > 400:
            continue
        text = re.sub(r"^([-*+]|\d+[.)])\s+", "", line).strip()
        if len(text) < 8 or not (DIRECTIVE.search(text) or (item and PROHIBITIVE_HEADING.search(heading))):
            continue
        rules.append(Rule(text, str(path.relative_to(repo)), n))
    return rules


def _read(p: Path, limit: int = 200_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _hook_script_text(command: str, repo: Path) -> str:
    """Follow script paths mentioned in a hook command so the scan sees what the hook checks."""
    scripts = ""
    command = command.replace('"', "").replace("'", "")
    for token in re.findall(r"[\w./${}~-]+\.(?:sh|py|js|mjs|ts|rb|bash)", command):
        p = token.replace("${CLAUDE_PROJECT_DIR}", str(repo)).replace("$CLAUDE_PROJECT_DIR", str(repo)).strip("\"'")
        path = Path(p) if Path(p).is_absolute() else repo / p
        if path.is_file():
            scripts += "\n" + _read(path)
            # helpers sourced next to the script
            for lib in re.findall(r"source\s+[\"']?\$\(dirname [\"']?\$0[\"']?\)/([\w.-]+)", scripts):
                lp = path.parent / lib
                if lp.is_file():
                    scripts += "\n" + _read(lp)
    # judge by what the script checks; the command line alone only counts when it is the check (inline hook)
    return scripts if scripts.strip() else command


def collect_mechanisms(repo: Path, findings: list[str]) -> list[Mechanism]:
    mech: list[Mechanism] = []
    for f in (repo / ".claude" / "settings.json", repo / ".claude" / "settings.local.json"):
        if not f.is_file():
            continue
        try:
            data = json.loads(_read(f))
        except ValueError:
            findings.append(f"{f.relative_to(repo)} is not valid JSON: Claude Code may ignore it entirely.")
            continue
        perms = data.get("permissions") or {}
        for kind in ("deny", "ask"):
            for rule in perms.get(kind, []) or []:
                mech.append(Mechanism("permission", f"{f.relative_to(repo)} permissions.{kind}", str(rule).lower()))
                if re.match(r"(Write|NotebookEdit|Glob|MultiEdit)\(.+\)$", str(rule)):
                    findings.append(f"permissions.{kind} rule {rule!r} never matches: Claude Code checks paths against "
                                    "Edit(...) and Read(...) rules only. Use Edit(...) with the same path.")
        for event, entries in (data.get("hooks") or {}).items():
            for entry in entries or []:
                for h in entry.get("hooks", []) or []:
                    cmd = str(h.get("command", ""))
                    mech.append(Mechanism("agent-hook", f"{f.relative_to(repo)} {event}[{entry.get('matcher', '*')}]",
                                          _hook_script_text(cmd, repo).lower()))
        if data.get("enabledPlugins") and (repo / ".egd" / "egd.toml").is_file():
            mech.append(Mechanism("agent-hook", ".egd/egd.toml (read by the enabled plugin) PreToolUse",
                                  _read(repo / ".egd" / "egd.toml").lower()))
        if data.get("enabledPlugins"):
            findings.append("Plugins are enabled in settings. Their hooks are not visible to this scan; "
                            "run `aeb bench --plugin <dir>` for each plugin that guards Bash.")
    cursor = repo / ".cursor" / "hooks.json"
    if cursor.is_file():
        try:
            data = json.loads(_read(cursor))
            for event, entries in (data.get("hooks") or {}).items():
                for h in entries or []:
                    mech.append(Mechanism("agent-hook", f".cursor/hooks.json {event}",
                                          _hook_script_text(str(h.get("command", "")), repo / ".cursor").lower()))
        except ValueError:
            findings.append(".cursor/hooks.json is not valid JSON.")
    for p in _glob(repo, CI_FILES):
        mech.append(Mechanism("ci", str(p.relative_to(repo)), _read(p).lower()))
    for p in _glob(repo, GIT_HOOK_FILES):
        mech.append(Mechanism("git-hook", str(p.relative_to(repo)), _read(p).lower()))
    for p in (repo / "CODEOWNERS", repo / ".github" / "CODEOWNERS", repo / "docs" / "CODEOWNERS"):
        if p.is_file():
            mech.append(Mechanism("codeowners", str(p.relative_to(repo)), _read(p).lower()))
    return mech


STRONG = {"agent-hook", "permission"}  # acts before the agent's action lands


def classify(rule: Rule, mechs: list[Mechanism]) -> None:
    text = rule.text.lower()
    if HONESTY.search(text):
        rule.status = "judgment"
        return
    scores = {t: len(re.findall(spec["kw"], text, re.I)) for t, spec in TOPICS.items()}
    ranked = sorted((n, t) for t, n in scores.items() if n)
    if ranked and (len(ranked) == 1 or ranked[-1][0] > ranked[-2][0]):
        rule.topic = ranked[-1][1]
    if not rule.topic:
        rule.status = "judgment" if JUDGMENT.search(text) else "unclassified"
        return
    ev = re.compile(TOPICS[rule.topic]["ev"], re.I)
    hits = []
    for m in mechs:
        if m.kind == "agent-hook" and "pretooluse" not in m.where.lower() and rule.topic not in ("tests", "lint-types"):
            continue  # a PostToolUse/Stop hook cannot prevent a write to a protected path
        if m.where.startswith(".egd/egd.toml") and rule.topic not in PATH_TOPICS:
            continue  # the plugin config only proves path protection, not that tests are strong or formats are checked
        if m.kind == "codeowners" and rule.topic not in ("migrations", "ci-config", "agent-config", "lockfiles", "generated"):
            continue
        if m.kind == "ci" and rule.topic in ("secrets", "agent-config", "force-push", "destructive") and not re.search(
                r"gitleaks|trufflehog|detect-secrets", m.text):
            continue
        pattern = re.compile(TOPICS[rule.topic]["ev_ci"], re.I) if m.kind == "ci" and "ev_ci" in TOPICS[rule.topic] else ev
        if m.kind == "permission":
            tool, _, arg = m.text.partition("(")
            # Claude Code checks paths against Edit(...) and Read(...) only; Write(path) never matches
            family = "bash" if tool == "bash" else "file" if tool in ("read", "edit") else ""
            if not family or rule.topic not in PERMISSION_TOPICS[family] or not pattern.search(arg):
                continue
        if pattern.search(m.text):
            hits.append(f"{m.kind}: {m.where}")
    rule.evidence = hits
    if not hits:
        rule.status = "text-only"
    elif any(h.split(":", 1)[0] in STRONG or h.startswith("ci") and rule.topic in ("tests", "lint-types") for h in hits):
        rule.status = "enforced"
    else:
        rule.status = "partial"


def general_findings(repo: Path, mechs: list[Mechanism], findings: list[str]) -> None:
    pre_bash = [m for m in mechs if m.kind == "agent-hook" and ("pretooluse" in m.where.lower() or "beforeshell" in m.where.lower())]
    plugins = any("plugins are enabled" in f.lower() for f in findings)
    if not pre_bash and plugins:
        findings.append("No shell guard hook in the project settings. If a plugin provides one, measure it with "
                        "`aeb bench --plugin <dir>`; otherwise nothing inspects shell commands before they run.")
    elif not pre_bash:
        findings.append("No PreToolUse / beforeShellExecution hook: nothing inspects shell commands before they run. "
                        "Every rule about files the agent must not touch rests on the model's goodwill.")
    else:
        findings.append("A shell guard hook exists. Measure it: `aeb bench --claude .` reports how many of "
                        "123 known escape techniques get through.")
    if not any(m.kind == "ci" for m in mechs):
        findings.append("No CI configuration found: local checks can be skipped with --no-verify and nothing catches it later.")
    if not any(m.kind == "codeowners" for m in mechs):
        findings.append("No CODEOWNERS: changes to CI, migrations and agent settings do not require a specific reviewer.")
    if not (repo / ".gitignore").is_file() or ".env" not in _read(repo / ".gitignore"):
        findings.append(".env is not in .gitignore.")


def scan(repo: Path) -> ScanReport:
    repo = repo.resolve()
    files = _glob(repo, INSTRUCTION_GLOBS)
    findings: list[str] = []
    mechs = collect_mechanisms(repo, findings)
    rules, seen = [], set()
    for f in files:
        for r in extract_rules(f, repo):
            key = re.sub(r"\W+", " ", r.text.lower()).strip()
            if key not in seen:  # CLAUDE.md and AGENTS.md often repeat each other
                seen.add(key)
                rules.append(r)
    for r in rules:
        classify(r, mechs)
    if not files:
        findings.insert(0, "No agent instruction files found (CLAUDE.md, AGENTS.md, Cursor rules).")
    general_findings(repo, mechs, findings)
    return ScanReport(str(repo), [str(f.relative_to(repo)) for f in files], rules, mechs, findings)
