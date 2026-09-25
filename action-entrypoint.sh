#!/usr/bin/env bash
# action-entrypoint.sh — promptfirewall GitHub Action entrypoint
# Downloads the binary, runs the scan, parses score/grade, and optionally posts a PR comment.

set -euo pipefail

###############################################################################
# Inputs (set by action.yml via env vars)
###############################################################################
SCAN_PATHS="${INPUT_SCAN_PATHS:-.}"
INCLUDE="${INPUT_INCLUDE:-}"
EXCLUDE="${INPUT_EXCLUDE:-}"
DETECT_PII="${INPUT_DETECT_PII:-true}"
DETECT_INJECTION="${INPUT_DETECT_INJECTION:-true}"
INJECTION_THRESHOLD="${INPUT_INJECTION_THRESHOLD:-0.7}"
FAIL_ON_FINDINGS="${INPUT_FAIL_ON_FINDINGS:-true}"
THRESHOLD="${INPUT_THRESHOLD:-0}"
POST_COMMENT="${INPUT_POST_COMMENT:-false}"
BADGE_JSON="${INPUT_BADGE_JSON:-false}"
SARIF_UPLOAD="${INPUT_SARIF_UPLOAD:-true}"
BINARY_DIR="${RUNNER_TEMP:-/tmp}"
BINARY="${BINARY_DIR}/promptfirewall"

###############################################################################
# 1. Determine platform & download binary
###############################################################################
determine_target() {
  case "${RUNNER_OS:-Linux}-${RUNNER_ARCH:-X64}" in
    Linux-X64)    echo "x86_64-unknown-linux-musl" ;;
    Linux-ARM64)  echo "aarch64-unknown-linux-musl" ;;
    macOS-X64)    echo "x86_64-apple-darwin" ;;
    macOS-ARM64)  echo "aarch64-apple-darwin" ;;
    Windows-X64)  echo "x86_64-pc-windows-msvc" ;;
    *) echo "::error::Unsupported platform: ${RUNNER_OS}-${RUNNER_ARCH}"; exit 1 ;;
  esac
}

download_binary() {
  local target
  target=$(determine_target)

  local version="${GITHUB_ACTION_REF:-}"
  if [ -z "$version" ] || [ "$version" = "main" ]; then
    version=$(curl -sL https://api.github.com/repos/TimurRakhmatullin86/promptfirewall/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4)
  fi

  echo "::group::Download promptfirewall ${version} (${target})"
  local url="https://github.com/TimurRakhmatullin86/promptfirewall/releases/download/${version}/promptfirewall-${target}.tar.gz"

  if [ "${RUNNER_OS:-Linux}" = "Windows" ]; then
    url="https://github.com/TimurRakhmatullin86/promptfirewall/releases/download/${version}/promptfirewall-${target}.zip"
    curl -sL "$url" -o "${BINARY_DIR}/promptfirewall.zip"
    unzip -q "${BINARY_DIR}/promptfirewall.zip" -d "${BINARY_DIR}"
  else
    curl -sL "$url" | tar xz -C "${BINARY_DIR}"
    chmod +x "${BINARY}"
  fi
  echo "::endgroup::"
}

###############################################################################
# 2. Build CLI arguments
###############################################################################
build_args() {
  local args="${SCAN_PATHS}"

  if [ -n "$INCLUDE" ]; then
    args="$args --include $INCLUDE"
  fi
  if [ -n "$EXCLUDE" ]; then
    args="$args --exclude $EXCLUDE"
  fi
  if [ "$DETECT_PII" = "false" ]; then
    args="$args --no-pii"
  fi
  if [ "$DETECT_INJECTION" = "false" ]; then
    args="$args --no-injection"
  fi
  args="$args --injection-threshold $INJECTION_THRESHOLD"

  echo "$args"
}

###############################################################################
# 3. Run scan and capture outputs
###############################################################################
run_scan() {
  local args
  args=$(build_args)

  # Run with badge-json to get the score
  local badge_output
  badge_output=$("${BINARY}" $args --badge-json 2>/dev/null || true)

  # Parse score and grade from badge JSON
  local score grade color
  score=$(echo "$badge_output" | grep '"message"' | sed 's/.*"message": *"\([A-F]\) (\([0-9]*\)\/100)".*/\2/')
  grade=$(echo "$badge_output" | grep '"message"' | sed 's/.*"message": *"\([A-F]\).*/\1/')
  color=$(echo "$badge_output" | grep '"color"' | sed 's/.*"color": *"\([^"]*\)".*/\1/')

  # Fallback if parsing failed
  if [ -z "$score" ]; then score="100"; fi
  if [ -z "$grade" ]; then grade="A"; fi
  if [ -z "$color" ]; then color="brightgreen"; fi

  # Run text output for human-readable results
  local text_output
  text_output=$("${BINARY}" $args --format text 2>&1 || true)

  # Count findings
  local findings_count
  findings_count=$("${BINARY}" $args --format json 2>/dev/null \
    | grep -c '"entity_type"\|"injection_detected": true' || echo "0")

  # Generate SARIF if needed
  local sarif_file="${BINARY_DIR}/promptfirewall-results.sarif"
  "${BINARY}" $args --sarif-file "$sarif_file" 2>/dev/null || true

  # Set outputs
  echo "score=${score}" >> "$GITHUB_OUTPUT"
  echo "grade=${grade}" >> "$GITHUB_OUTPUT"
  echo "findings-count=${findings_count}" >> "$GITHUB_OUTPUT"
  echo "sarif-file=${sarif_file}" >> "$GITHUB_OUTPUT"

  if [ "$score" -ge "$THRESHOLD" ] 2>/dev/null && [ "$findings_count" = "0" -o "$FAIL_ON_FINDINGS" = "false" ]; then
    echo "is-safe=true" >> "$GITHUB_OUTPUT"
  else
    echo "is-safe=false" >> "$GITHUB_OUTPUT"
  fi

  # Badge JSON output
  if [ "$BADGE_JSON" = "true" ]; then
    echo "badge-json=${badge_output}" >> "$GITHUB_OUTPUT"
  fi

  # Print text results to workflow log
  echo "$text_output"

  # Return values for use by post_comment and threshold check
  SCAN_SCORE="$score"
  SCAN_GRADE="$grade"
  SCAN_COLOR="$color"
  SCAN_FINDINGS="$findings_count"
  SCAN_TEXT="$text_output"
  SCAN_BADGE="$badge_output"
  SCAN_SARIF_FILE="$sarif_file"
}

###############################################################################
# 4. Post PR comment
###############################################################################
post_comment() {
  if [ "$POST_COMMENT" != "true" ]; then
    return
  fi

  # Only post on pull_request events
  if [ -z "${GITHUB_EVENT_NAME:-}" ] || [ "$GITHUB_EVENT_NAME" != "pull_request" ]; then
    echo "::notice::Skipping PR comment (not a pull_request event)"
    return
  fi

  if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "::warning::Cannot post PR comment: GITHUB_TOKEN not set"
    return
  fi

  local pr_number
  pr_number=$(jq -r '.pull_request.number' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
  if [ -z "$pr_number" ] || [ "$pr_number" = "null" ]; then
    echo "::warning::Cannot post PR comment: unable to determine PR number"
    return
  fi

  # Build grade emoji
  local grade_emoji
  case "$SCAN_GRADE" in
    A) grade_emoji="🟢" ;;
    B) grade_emoji="🟡" ;;
    C) grade_emoji="🟠" ;;
    D) grade_emoji="🔴" ;;
    *) grade_emoji="⛔" ;;
  esac

  # Build comment body
  local body
  body="## ${grade_emoji} Promptfirewall Security Scan

**AI Safety Score: ${SCAN_GRADE} (${SCAN_SCORE}/100)** | Findings: ${SCAN_FINDINGS}

<details>
<summary>Scan Details</summary>

\`\`\`
${SCAN_TEXT}
\`\`\`

</details>

"

  # Threshold info
  if [ "$THRESHOLD" -gt 0 ] 2>/dev/null; then
    if [ "$SCAN_SCORE" -lt "$THRESHOLD" ] 2>/dev/null; then
      body="${body}> **Failed**: Score ${SCAN_SCORE} is below threshold ${THRESHOLD}

"
    else
      body="${body}> **Passed**: Score ${SCAN_SCORE} meets threshold ${THRESHOLD}

"
    fi
  fi

  body="${body}---
*Scanned by [promptfirewall](https://github.com/TimurRakhmatullin86/promptfirewall) — PII & prompt injection firewall for LLM apps*"

  # Find and update existing comment, or create new one
  local comment_id
  comment_id=$(curl -sL \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments" \
    | jq -r '.[] | select(.body | contains("Promptfirewall Security Scan")) | .id' \
    | head -1)

  if [ -n "$comment_id" ] && [ "$comment_id" != "null" ]; then
    # Update existing comment
    curl -sL -X PATCH \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/comments/${comment_id}" \
      -d "$(jq -n --arg body "$body" '{body: $body}')" > /dev/null
    echo "::notice::Updated existing PR comment"
  else
    # Create new comment
    curl -sL -X POST \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments" \
      -d "$(jq -n --arg body "$body" '{body: $body}')" > /dev/null
    echo "::notice::Posted PR comment with scan results"
  fi
}

###############################################################################
# 5. Threshold check
###############################################################################
check_threshold() {
  # Fail on findings if requested
  if [ "$FAIL_ON_FINDINGS" = "true" ] && [ "$SCAN_FINDINGS" -gt 0 ] 2>/dev/null; then
    echo "::error::Scan found ${SCAN_FINDINGS} finding(s). Set fail-on-findings to 'false' to allow."
    exit 1
  fi

  # Fail if score below threshold
  if [ "$THRESHOLD" -gt 0 ] 2>/dev/null; then
    if [ "$SCAN_SCORE" -lt "$THRESHOLD" ] 2>/dev/null; then
      echo "::error::AI Safety Score ${SCAN_SCORE} is below threshold ${THRESHOLD}"
      exit 1
    fi
  fi
}

###############################################################################
# Main
###############################################################################
download_binary
run_scan
post_comment
check_threshold
