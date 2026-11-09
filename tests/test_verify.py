from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_escape_bench import hooks, perms, scan, verify  # noqa: E402

PY = sys.executable
R, H = "/r", "/home/u"


def rule(kind, raw):
    tool, _, spec = raw.partition("(")
    spec = spec[:-1] if spec else None
    return perms.PermRule(kind, tool, spec or None, "settings", raw, R)


class PermsTest(unittest.TestCase):
    def decide(self, rules, tool, **inp):
        return perms.decide(rules, tool, inp, R, H).decision

    def test_paths(self):
        rules = [rule("deny", "Read(./.env)"), rule("deny", "Edit(/.claude/**)"), rule("ask", "Edit(**/migrations/**)")]
        self.assertEqual(self.decide(rules, "Read", file_path="/r/.env"), "deny")
        self.assertEqual(self.decide(rules, "Edit", file_path="/r/.env"), "deny")  # a Read deny also blocks edits
        self.assertEqual(self.decide(rules, "Read", file_path="/r/sub/.env"), "allow")  # ./ anchors at the root
        self.assertEqual(self.decide(rules, "Write", file_path="/r/.claude/settings.json"), "deny")
        self.assertEqual(self.decide(rules, "Write", file_path="/r/db/migrations/1.sql"), "ask")
        self.assertEqual(self.decide([rule("deny", "Read(*.env)")], "Read", file_path="/r/a/b/x.env"), "deny")

    def test_write_path_rules_never_match(self):
        self.assertEqual(self.decide([rule("deny", "Write(**/.env)")], "Write", file_path="/r/.env"), "allow")
        self.assertEqual(self.decide([rule("deny", "Write")], "Write", file_path="/r/x"), "deny")

    def test_bash(self):
        rules = [rule("deny", "Bash(git push --force:*)"), rule("deny", "Bash(*--no-verify*)"), rule("deny", "Read(**/.env)"),
                 rule("deny", "Edit(./.github/**)")]
        self.assertEqual(self.decide(rules, "Bash", command="timeout 5 git push --force origin main"), "deny")
        self.assertEqual(self.decide(rules, "Bash", command="cd x && git commit --no-verify -m a"), "deny")
        self.assertEqual(self.decide(rules, "Bash", command="git push -f"), "allow")
        self.assertEqual(self.decide(rules, "Bash", command="cat .env | head"), "deny")
        self.assertEqual(self.decide(rules, "Bash", command="python3 -c \"open('.env').read()\""), "allow")
        self.assertEqual(self.decide(rules, "Bash", command="cd .github/workflows && echo x > ci.yml"), "deny")
        self.assertEqual(self.decide(rules, "Bash", command="echo x 2>&1 > /dev/null"), "allow")

    def test_builtin_protected(self):
        self.assertTrue(perms.builtin_protected(".claude/settings.json"))
        self.assertTrue(perms.builtin_protected(".husky/pre-commit"))
        self.assertFalse(perms.builtin_protected(".github/workflows/ci.yml"))


class RulesTest(unittest.TestCase):
    def test_items_under_a_prohibitive_heading_are_rules(self):
        d = Path(tempfile.mkdtemp())
        (d / "CLAUDE.md").write_text("## Forbidden\n\n- Editing `.github/workflows/ci.yml`.\n- `git push`.\n\n"
                                     "## Notes\n\n- Editing docs is fine.\n", encoding="utf-8")
        texts = [r.text for r in scan.scan(d).rules]
        self.assertIn("Editing `.github/workflows/ci.yml`.", texts)
        self.assertNotIn("Editing docs is fine.", texts)

    def test_tokens(self):
        self.assertEqual(verify._tokens("Never read `.env*` (keys live in `mobile/.env`).", "secrets"), [".env", "mobile/.env"])
        self.assertEqual(verify._tokens("immutable: api/migrations/**", "migrations"), ["api/migrations/"])
        self.assertEqual(verify._tokens("Do not touch .github/workflows.", "ci-config"), [".github/workflows"])
        self.assertEqual(verify._tokens("new folder `YYYYMMDD_name/migration.sql`", "migrations"), [])

    def test_named_commands(self):
        self.assertEqual(verify.named_commands("Never run `prisma migrate reset`, `db:reset`, `wipe.sh` or `--no-verify`."),
                         ["prisma migrate reset", "npm run db:reset", "bash wipe.sh"])


def make_repo(claude_md: str, settings: dict, files: dict | None = None) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
    (d / ".claude").mkdir()
    (d / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    for rel, text in (files or {}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return d


EDIT_GUARD = (f"{PY} -c \"import json,sys; d=json.load(sys.stdin); "
              "sys.exit(2 if 'migrations/' in d.get('tool_input', {}).get('file_path', '') and "
              "'aeb_new' not in d['tool_input']['file_path'] else 0)\"")


class VerifyRunTest(unittest.TestCase):
    def run_repo(self, d: Path):
        return verify.run(d, hooks.discover_claude(d, tool=None))

    def by_topic(self, rep):
        return {c.topic: c for c in rep.checks}

    def test_verdicts(self):
        d = make_repo(
            "# Rules\n\n- Never edit applied migrations in `db/migrations/`.\n- Never force push.\n"
            "- Do not edit `package-lock.json` by hand.\n- Never touch `.github/workflows`.\n",
            {"permissions": {"deny": ["Bash(git push:*)"]},
             "hooks": {"PreToolUse": [{"matcher": "Edit|Write", "hooks": [{"type": "command", "command": EDIT_GUARD}]}]}},
            {"db/migrations/001_init.sql": "x\n", "package-lock.json": "{}\n", ".github/workflows/ci.yml": "x\n",
             "CODEOWNERS": "/.github/ @acme/platform\n"})
        rep = self.run_repo(d)
        t = self.by_topic(rep)
        self.assertEqual(t["force-push"].verdict, "concrete")
        mig = t["migrations"]
        self.assertEqual(mig.target, "db/migrations/001_init.sql")
        self.assertEqual(mig.verdict, "partial")  # the Edit/Write hook stops the tools, the shell is open
        self.assertTrue(all(p.stopped for p in mig.probes if p.via in ("Edit tool", "Write tool")))
        self.assertFalse(any(p.stopped for p in mig.probes if p.control))
        self.assertEqual(t["lockfiles"].verdict, "obedience")
        self.assertEqual(t["ci-config"].verdict, "review")
        self.assertIn("@acme/platform", t["ci-config"].merge_gate)

    def test_only_through_is_not_a_forbidden_command(self):
        d = make_repo("- Add native modules only through `npx expo install`.\n", {})
        self.assertFalse(any(c.topic == "named" for c in self.run_repo(d).checks))

    def test_heading_rules_and_named_commands(self):
        d = make_repo("## Forbidden\n\n- `prisma migrate reset`, `db:reset`.\n",
                      {"permissions": {"deny": ["Bash(*migrate reset*)"]}})
        named = [c for c in self.run_repo(d).checks if c.topic == "named"]
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0].verdict, "partial")

    def test_write_rule_finding_and_judgment(self):
        d = make_repo("- Never read `.env`.\n- Never claim it works if you did not run it.\n",
                      {"permissions": {"deny": ["Write(**/.env)", "Read(**/.env)"]}})
        rep = self.run_repo(d)
        self.assertTrue(any("never matches" in f for f in rep.findings))
        self.assertTrue(any(r["why"] == "needs human judgment" for r in rep.not_probed))
        sec = self.by_topic(rep)["secrets"]
        self.assertEqual(sec.verdict, "partial")  # Read and cat are denied, python3 -c is not
        self.assertFalse(next(p for p in sec.probes if p.via == "shell: python3").stopped)


if __name__ == "__main__":
    unittest.main()
