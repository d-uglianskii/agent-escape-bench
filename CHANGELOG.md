# Changelog

## 0.2.0

- `aeb verify`: tries to break every path and command rule your instruction files state, through the Edit, Write and Read tools and shell forms of the same action, and reports per rule what stopped it: your hooks (run for real), your deny and ask rules (a model of the documented Claude Code rules) or CODEOWNERS at merge. Verdicts: concrete, partial, review, obedience.
- `aeb scan`: list items under headings like "Forbidden" or "Never" count as rules; `Write(path)` permission rules are reported, because Claude Code never matches them.
- Hooks are discovered for every tool, not only Bash, so `verify` runs Edit, Write and Read hooks too.

## 0.1.0

- `aeb bench`: 164 shell commands against your hook, nothing executed.
- `aeb scan`: a static map of which rules mention any mechanism.
