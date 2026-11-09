import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_escape_bench import bench, hooks, scan  # noqa: E402

PY = sys.executable


class CorpusTest(unittest.TestCase):
    def test_shape(self):
        cases = bench.load_corpus()
        self.assertEqual(len(cases), 164)
        self.assertEqual(sum(c["expect"] == "block" for c in cases), 123)
        self.assertEqual(len({c["id"] for c in cases}), 164)
        for c in cases:
            self.assertIn(c["expect"], ("block", "allow"))
            self.assertTrue(c["why"])
            self.assertNotIn("egd", c["cmd"].lower())


class ParseTest(unittest.TestCase):
    def test_claude(self):
        self.assertEqual(hooks.parse("claude", 2, "", "no").decision, "deny")
        self.assertEqual(hooks.parse("claude", 0, "", "").decision, "allow")
        out = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}})
        self.assertEqual(hooks.parse("claude", 0, out, "").decision, "ask")
        self.assertEqual(hooks.parse("claude", 0, '{"decision": "block"}', "").decision, "deny")
        err = hooks.parse("claude", 1, "", "boom")
        self.assertEqual((err.decision, bool(err.error)), ("allow", True))

    def test_cursor(self):
        self.assertEqual(hooks.parse("cursor", 0, '{"permission": "deny"}', "").decision, "deny")
        self.assertEqual(hooks.parse("cursor", 0, '{"continue": false}', "").decision, "deny")
        self.assertEqual(hooks.parse("cursor", 3, "", "x").decision, "allow")

    def test_combine(self):
        a = [hooks.Answer("allow"), hooks.Answer("ask"), hooks.Answer("allow", error="e")]
        c = hooks.combine(a)
        self.assertEqual(c.decision, "ask")
        self.assertIn("e", c.error)

    def test_matcher(self):
        self.assertTrue(hooks._matcher_hits("Bash"))
        self.assertTrue(hooks._matcher_hits("Edit|Bash"))
        self.assertTrue(hooks._matcher_hits(None))
        self.assertFalse(hooks._matcher_hits("Edit|Write"))


class RunTest(unittest.TestCase):
    def run_with(self, cmd, protocol="claude"):
        return bench.run([hooks.Hook(cmd, protocol)], "test", ".claude/hooks", "guard.sh",
                         only={"direct-write", "normal-work"})

    def test_allow_all_escapes_everything(self):
        rep = self.run_with("cat >/dev/null")
        self.assertEqual(rep.escaped, len(rep.attacks))
        self.assertEqual(rep.false_blocks, 0)

    def test_deny_all_blocks_everything(self):
        rep = self.run_with("cat >/dev/null; exit 2")
        self.assertEqual(rep.escaped, 0)
        self.assertEqual(rep.false_blocks, len(rep.legit))

    def test_cursor_json(self):
        rep = self.run_with("cat >/dev/null; echo '{\"permission\": \"ask\"}'", "cursor")
        self.assertEqual(rep.escaped, 0)
        self.assertEqual(rep.count("friction"), len(rep.legit))

    def test_hook_sees_fixture(self):
        # A hook that blocks only when the guard file really exists in the sandbox repo.
        cmd = (f"{PY} -c \"import json,os,sys; p=json.load(sys.stdin); "
               "c=p['tool_input']['command']; sys.exit(2 if '.claude/hooks/guard.sh' in c and "
               "os.path.exists(os.path.join(os.environ['CLAUDE_PROJECT_DIR'], '.claude/hooks/guard.sh')) else 0)\"")
        rep = bench.run([hooks.Hook(cmd)], "test", ".claude/hooks", "guard.sh", only={"AEB-001"})
        self.assertEqual(rep.results[0].outcome, "blocked")

    def test_session_writes_materialized(self):
        cmd = (f"{PY} -c \"import json,sys,pathlib,re; c=json.load(sys.stdin)['tool_input']['command']; "
               "m=re.search(r'(?:bash|source|\\.) (/\\S+new\\.sh)', c); "
               "sys.exit(2 if m and 'guard.sh' in pathlib.Path(m.group(1)).read_text() else 0)\"")
        rep = bench.run([hooks.Hook(cmd)], "test", ".claude/hooks", "guard.sh", only={"indirection"})
        sess = [r for r in rep.results if "new.sh" in r.cmd]
        self.assertTrue(sess)
        self.assertTrue(all(r.outcome == "blocked" for r in sess), [(r.cmd, r.outcome) for r in sess])


class ExampleTest(unittest.TestCase):
    def test_naive_guard_example(self):
        repo = ROOT / "examples" / "naive-guard"
        hk = hooks.discover_claude(repo)
        self.assertEqual(len(hk), 1)
        rep = bench.run(hk, "naive", ".claude/hooks", "guard.sh", include=[(repo / ".claude", ".claude")])
        self.assertGreater(rep.escaped, 60)  # the point of the example
        self.assertLess(rep.escaped, len(rep.attacks))

    def test_scan_example(self):
        rep = scan.scan(ROOT / "examples" / "naive-guard")
        self.assertEqual(rep.instruction_files, ["CLAUDE.md"])
        status = {r.text[:20]: r.status for r in rep.rules}
        self.assertEqual(status["Do not edit package-"], "text-only")
        self.assertEqual(status["Always run the tests"], "enforced")
        self.assertEqual(status["Keep the change mini"], "judgment")


class MigrationsDirTest(unittest.TestCase):
    def test_custom_migrations_dir_is_used(self):
        # a hook that only protects api/migrations must catch the migration cases once the bench knows the path
        cmd = (f"{PY} -c \"import json,sys; c=json.load(sys.stdin)['tool_input']['command']; "
               "sys.exit(2 if 'api/migrations/001' in c and ('>>' in c or ' > ' in c) else 0)\"")
        rep = bench.run([hooks.Hook(cmd)], "test", ".claude/hooks", "guard.sh", only={"AEB-020", "AEB-021"},
                        migrations_dir="api/migrations")
        out = {r.id: r.outcome for r in rep.results}
        self.assertEqual(out["AEB-020"], "blocked")
        self.assertNotIn("{MIGRATIONS}", " ".join(r.cmd for r in rep.results))


class ScanPrecisionTest(unittest.TestCase):
    def make(self, claude_md, settings, files=None):
        import tempfile
        d = Path(tempfile.mkdtemp())
        (d / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
        (d / ".claude").mkdir()
        (d / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
        for rel, text in (files or {}).items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text, encoding="utf-8")
        return d

    def status(self, rep, start):
        return next(r.status for r in rep.rules if r.text.startswith(start))

    def test_honesty_rule_is_judgment(self):
        d = self.make("- Never claim it works if it was not run, and list what is not verified: no keys, no network.\n", {})
        self.assertEqual(self.status(scan.scan(d), "Never claim"), "judgment")

    def test_bash_permission_is_not_evidence_for_editing_migrations(self):
        d = self.make("- Never edit applied migrations.\n",
                      {"permissions": {"deny": ["Bash(*migrate reset*)"]}})
        self.assertEqual(self.status(scan.scan(d), "Never edit"), "text-only")

    def test_file_permission_is_evidence_for_secrets(self):
        d = self.make("- Never read .env files.\n", {"permissions": {"deny": ["Read(./.env)"]}})
        self.assertEqual(self.status(scan.scan(d), "Never read"), "enforced")

    def test_hook_script_path_is_not_evidence(self):
        hook = {"hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [
            {"type": "command", "command": ".claude/hooks/guard.sh"}]}]}}
        d = self.make("- Never edit the .claude settings.\n", hook, {".claude/hooks/guard.sh": "exit 0\n"})
        self.assertEqual(self.status(scan.scan(d), "Never edit the"), "text-only")

    def test_duplicate_rules_counted_once(self):
        d = self.make("- Never edit applied migrations.\n", {})
        (d / "AGENTS.md").write_text("- Never edit applied migrations.\n", encoding="utf-8")
        self.assertEqual(len(scan.scan(d).rules), 1)


if __name__ == "__main__":
    unittest.main()
