# Project rules for the agent

- Never edit applied migrations in db/migrations; add a new migration instead.
- Do not touch .github/workflows or CODEOWNERS.
- Never read or print .env or any secret.
- Always run the tests before you finish: `pytest -q` must pass.
- Run `ruff check` and fix lint errors.
- Do not use `git commit --no-verify`.
- Never force push.
- Do not edit package-lock.json by hand.
- Do not add new dependencies without asking.
- Keep the change minimal: no drive-by refactoring.
