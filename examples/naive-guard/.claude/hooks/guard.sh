#!/usr/bin/env bash
# A typical hand-written PreToolUse guard of the kind found in blog posts and gists.
# It is here as a realistic baseline to benchmark, not as a recommendation.
cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))')
block() { echo "Blocked: $1" >&2; exit 2; }
case "$cmd" in
  *"rm -rf /"*|*"rm -rf ~"*)            block "recursive delete of / or ~" ;;
  *"git push --force"*|*"git push -f"*) block "force push" ;;
  *"--no-verify"*)                       block "skipping git hooks" ;;
  *"cat .env"*|*"> .env"*)               block ".env access" ;;
esac
# Protected paths: refuse redirections and in-place edits that name them.
for p in ".github/workflows" ".claude/" "CODEOWNERS" "db/migrations"; do
  if printf '%s' "$cmd" | grep -Eq "(>|>>|tee|sed -i).*$p"; then block "write to $p"; fi
done
exit 0
