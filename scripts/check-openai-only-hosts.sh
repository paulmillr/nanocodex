#!/usr/bin/env bash
# Fails when the release `nanocodex` binary embeds a URL for a host outside the
# OpenAI-only allowlist. Runtime enforcement lives in nanocodex-net-allowlist;
# this keeps unreviewed endpoints from being compiled in at all.
#
# Usage: scripts/check-openai-only-hosts.sh [path/to/nanocodex]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
binary=${1:-}
if [[ -z $binary ]]; then
  cargo build --locked --release --package nanocodex-bin --bin nanocodex \
    --manifest-path "$root/Cargo.toml" >&2
  binary=$root/target/release/nanocodex
fi
reviewed=$root/scripts/openai-only-hosts.allow

# Hosts the binary may contact: OpenAI domains and loopback. Must match
# ALLOWED_DOMAINS in crates/nanocodex-net-allowlist/src/lib.rs.
allowed='^(([a-z0-9-]+\.)*(openai\.com|chatgpt\.com|oaistatic\.com)|localhost|127\.[0-9.]+|\[::1\])$'

# Hosts that appear in the binary but are never contacted (documentation links
# in error messages, XML namespaces, test fixtures). One host per line.
reviewed_hosts=$(grep -vE '^\s*(#|$)' "$reviewed" | awk '{print $1}' || true)

# Rust string literals are not NUL-terminated, so a host can run straight into
# the next literal ("auth.openai.comtokenresponse"). Accept such a candidate
# when it starts with a known host and the remainder contains no "." and does
# not start with "-", so it cannot extend that host into a different domain.
# Optimized builds also split literals, leaving truncated fragments
# ("json-sch"); a candidate that is a prefix of a known host is one of those.
known_prefix() {
  local candidate=$1 host rest
  while read -r host; do
    [[ -z $host ]] && continue
    [[ $host == "$candidate"* ]] && return 0
    if [[ $candidate == "$host"* ]]; then
      rest=${candidate#"$host"}
      [[ $rest != *.* && $rest != -* ]] && return 0
    fi
  done
  return 1
}

candidates=$(
  strings -n 8 "$binary" |
    grep -oiE '\b(https?|wss?)://[a-z0-9.-]+' |
    sed -E 's#^[a-zA-Z]+://##; s#\.$##' |
    tr 'A-Z' 'a-z' |
    sort -u
)
unexpected=$(
  while read -r candidate; do
    [[ -z $candidate ]] && continue
    [[ $candidate =~ $allowed ]] && continue
    # Allowed domains (and subdomains) followed by glued text.
    [[ $candidate =~ ^([a-z0-9-]+\.)*(openai\.com|chatgpt\.com|oaistatic\.com)([^.]*)$ &&
      ${BASH_REMATCH[3]} != -* ]] && continue
    known_prefix "$candidate" < <(printf '%s\n' openai.com chatgpt.com oaistatic.com "$reviewed_hosts") &&
      continue
    echo "$candidate"
  done <<<"$candidates"
)

if [[ -n $unexpected ]]; then
  echo "error: $binary embeds URLs for hosts outside the OpenAI-only allowlist:" >&2
  sed 's/^/  /' <<<"$unexpected" >&2
  echo "Remove the endpoint, or if it is never contacted, add it to ${reviewed#"$root"/} with a reason." >&2
  exit 1
fi
echo "ok: $binary only embeds OpenAI, loopback, or reviewed non-contacted hosts"
