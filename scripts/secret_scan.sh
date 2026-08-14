#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep is required for the public-safety scan." >&2
  exit 2
fi

patterns=(
  'gh[pousr]_[A-Za-z0-9_]{30,}'
  'sk-[A-Za-z0-9_-]{20,}'
  '-----BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----'
  '^[[:space:]]*SUDO_PASSWORD=(["'\'']?)[^"'\''].+'
  '^[[:space:]]*DISCORD_BOT_TOKEN=(["'\'']?)[^"'\''].+'
)

for pattern in "${patterns[@]}"; do
  set +e
  output="$(rg -n --hidden --glob '!.git' --glob '!__pycache__' --pcre2 -- "$pattern" .)"
  status="$?"
  set -e
  if [[ "$status" -eq 0 ]]; then
    printf '%s\n' "$output"
    echo "Potential secret-like value found. Review before publishing." >&2
    exit 1
  elif [[ "$status" -gt 1 ]]; then
    printf '%s\n' "$output" >&2
    echo "Secret scan failed while evaluating a pattern." >&2
    exit "$status"
  fi
done

echo "No obvious secret-like values found."
