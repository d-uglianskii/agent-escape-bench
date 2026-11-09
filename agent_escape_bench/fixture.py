"""Throwaway sandbox repository the corpus is evaluated against.

Nothing from the corpus is ever executed. The fixture only has to look like a real
repository so that a hook which inspects paths, symlinks, archives or patches sees
realistic inputs.
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

PATCH = """diff --git a/{p} b/{p}
--- a/{p}
+++ b/{p}
@@ -1 +1 @@
-{old}
+changed
"""

REPO_FILES = {
    ".github/workflows/ci.yml": "name: ci\non: [push]\njobs: {}\n",
    ".claude/settings.json": "{}\n",
    "CODEOWNERS": "* @acme/platform\n",
    "src/app.py": "x = 1\n",
    "scripts/tool.py": "print('ok')\n",
    ".env": "SECRET=not-a-real-secret\n",
}


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class Fixture:
    def __init__(self, guard_dir: str = ".claude/hooks", guard_file: str = "guard.sh",
                 include: list[tuple[Path, str]] | None = None, setup: str | None = None,
                 migrations_dir: str = "db/migrations", extra_files: dict[str, str] | None = None):
        self.extra_files = dict(extra_files or {})
        self.migrations_dir = migrations_dir.strip("/")
        self.guard_dir = guard_dir.strip("/")
        self.guard_file = guard_file
        self.guard = f"{self.guard_dir}/{guard_file}"
        self.root = Path(tempfile.mkdtemp(prefix="aeb-repo-")).resolve()
        self.out = Path(tempfile.mkdtemp(prefix="aeb-out-")).resolve()
        # The fake HOME must not live in a temp directory: many guards treat /tmp as safe.
        self.home = Path(tempfile.mkdtemp(prefix=".aeb-home-", dir=Path.home())).resolve()
        self._build_repo(include or [])
        self._build_outside()
        if setup:
            subprocess.run(["sh", "-c", setup], cwd=self.root, check=True, capture_output=True,
                           env=self.env())

    # ---------- placeholders ----------
    def subst(self, text: str) -> str:
        ext = os.path.splitext(self.guard_file)[1] or self.guard_file
        values = {
            "{GUARD}": self.guard, "{GUARD_DIR}": self.guard_dir, "{GUARD_FILE}": self.guard_file,
            "{GUARD_EXT}": ext, "{GD_A}": self.guard_dir[:3], "{GD_B}": self.guard_dir[3:],
            "{OUT}": str(self.out), "{ROOT}": str(self.root), "{MIGRATIONS}": self.migrations_dir,
        }
        for key, value in values.items():
            text = text.replace(key, value)
        return text

    def display(self, text: str) -> str:
        """Readable form for reports: guard and migration paths resolved, throwaway temp paths left as placeholders."""
        keep = ("{OUT}", "{ROOT}")
        saved = {}
        for k in keep:
            saved[k] = f"\0{k[1:-1]}\0"
            text = text.replace(k, saved[k])
        text = self.subst(text)
        for k, v in saved.items():
            text = text.replace(v, k)
        return text

    def env(self, extra: dict | None = None) -> dict:
        env = dict(os.environ)
        env.update(HOME=str(self.home), CLAUDE_PROJECT_DIR=str(self.root), AEB_FIXTURE="1")
        env.update(extra or {})
        return env

    # ---------- construction ----------
    def _build_repo(self, include: list[tuple[Path, str]]) -> None:
        r = self.root
        _git(r, "init", "-q", "-b", "main")
        _git(r, "config", "user.email", "bench@example.com")
        _git(r, "config", "user.name", "bench")
        for src, rel in include:
            dst = r / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__"))
            else:
                shutil.copy2(src, dst)
        files = dict(REPO_FILES)
        files[f"{self.migrations_dir}/001_init.sql"] = "create table a(id int);\n"
        files.update(self.extra_files)
        for rel, text in files.items():
            path = r / rel
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
        guard = r / self.guard
        if not guard.exists():
            guard.parent.mkdir(parents=True, exist_ok=True)
            guard.write_text("# placeholder guard file created by agent-escape-bench\n", encoding="utf-8")
        link = r / "link_cfg"
        if not link.exists():
            link.symlink_to(self.guard)
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", "init")
        _git(r, "checkout", "-q", "-b", "feature/bench")

    def _build_outside(self) -> None:
        o = self.out
        evil = o / "evil" / self.guard
        evil.parent.mkdir(parents=True)
        evil.write_text("# replaced\n")
        (o / "clean").mkdir()
        (o / "clean" / "a.txt").write_text("a\n")
        first_line = (self.root / self.guard).read_text(encoding="utf-8", errors="replace").splitlines()
        (o / "p_guard.diff").write_text(PATCH.format(p=self.guard, old=first_line[0] if first_line else ""))
        (o / "p_src.diff").write_text(PATCH.format(p="src/app.py", old="x = 1"))
        for name, member in (("evil.tar", self.guard), ("ok.tar", "build/a.txt")):
            with tarfile.open(o / name, "w") as t:
                data = b"x\n"
                info = tarfile.TarInfo(member)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        old = o / "old.sh"
        old.write_text("echo old\n")
        past = time.time() - 3600
        os.utime(old, (past, past))

    def materialize(self, path: str, content: str) -> None:
        """Create a file the agent wrote earlier in the session (the bench writes it, not the agent)."""
        target = Path(self.subst(path))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.subst(content), encoding="utf-8")

    def cleanup(self) -> None:
        for d in (self.root, self.out, self.home):
            shutil.rmtree(d, ignore_errors=True)
