---
title: "I added prompt injection scanning to my CI pipeline. Here's the GitHub Action."
published: false
tags: github, security, llm, devops
---

# I added prompt injection scanning to my CI pipeline. Here's the GitHub Action.

Last month I published [promptfirewall](https://github.com/TimurRakhmatullin86/promptfirewall) — a Rust library that detects PII and prompt injection in under 12μs. The [dev.to post](https://dev.to/timurrakhmatullin86/i-built-a-prompt-injection-firewall-in-rust-it-scans-in-12s-39l7) got solid feedback, and the most common request was: *"Can I run this in CI?"*

Now you can. One YAML line:

```yaml
- uses: TimurRakhmatullin86/promptfirewall@v1
```

## What it catches

The scanner walks your repo and flags two classes of issues:

**PII leaks** — hardcoded emails, SSNs, credit cards, phone numbers, API keys sitting in your source files. These get into prompts, prompts get sent to LLM providers, and now your users' PII is in someone else's training data.

**Prompt injection patterns** — `"ignore previous instructions"`, delimiter attacks (`[SYSTEM]:`, `<|im_start|>`), jailbreak attempts, encoded payloads. If you're building any LLM-powered feature, these patterns in your codebase are either test fixtures (fine) or production vulnerabilities (not fine).

## How it works

The action downloads a pre-built Rust binary (5 platforms: Linux x64/arm64, macOS x64/arm64, Windows). No `npm install`, no Docker, no Python — just a static binary.

It scans your code, outputs findings in text, and uploads a SARIF report to GitHub Code Scanning. Your findings show up as annotations right on the PR diff:

```
🛡️ promptfirewall scan results:
  src/config.py:12  PII: Email detected (confidence: 95%)
  src/agent.py:45   Injection: score 0.85 [role_manipulation, delimiter_attack]

2 findings, 1 file with injection risk
```

## Setup

### Basic (scan everything, fail on findings)

```yaml
name: Prompt Security
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: TimurRakhmatullin86/promptfirewall@v1
```

That's it. It respects `.gitignore`, scans common text extensions (py, ts, js, yaml, json, go, rs, java, etc.), and fails the check if anything is found.

### Advanced (tune for your project)

```yaml
- uses: TimurRakhmatullin86/promptfirewall@v1
  with:
    scan-paths: 'src/ prompts/ config/'
    include: '*.py,*.ts,*.yaml'
    exclude: '*.test.py,fixtures/*'
    threshold: 70
    post-comment: true
    sarif-upload: true
```

### PR Comments

Set `post-comment: true` and the action posts a comment on each PR with the safety score, grade, and detailed findings. It updates the same comment on subsequent pushes instead of creating duplicates.

### Inputs

| Input | Default | Description |
|---|---|---|
| `scan-paths` | `.` | Directories to scan |
| `include` | all text files | Glob patterns to include |
| `exclude` | none | Glob patterns to exclude |
| `detect-pii` | `true` | Enable PII scanning |
| `detect-injection` | `true` | Enable injection detection |
| `injection-threshold` | `0.7` | Score threshold (0.0-1.0) |
| `fail-on-findings` | `true` | Fail the step on findings |
| `threshold` | `0` | Minimum AI Safety Score (0-100); fails if below |
| `post-comment` | `false` | Post results as PR comment |
| `badge-json` | `false` | Output shields.io badge JSON |
| `sarif-upload` | `true` | Upload to Code Scanning |

### Outputs

| Output | Description |
|---|---|
| `score` | AI Safety Score (0-100) |
| `grade` | Grade (A-F) |
| `findings-count` | Total number of findings |
| `is-safe` | Whether the scan passed (true/false) |

```yaml
- uses: TimurRakhmatullin86/promptfirewall@v1
  id: scan
- run: echo "Grade ${{ steps.scan.outputs.grade }} — Score ${{ steps.scan.outputs.score }}/100"
```

## Performance

The binary is written in Rust with `RegexSet` for pattern matching. No ML model, no network calls, no startup cost.

| Metric | Value |
|---|---|
| Per-file scan time | < 2ms |
| 100-file repo | < 1 second |
| Binary size | ~3 MB |
| Dependencies at runtime | zero |

Compare this to running Presidio or LLM Guard in your pipeline. Those need Python, PyTorch, and 200ms+ per file.

## SARIF integration

The SARIF output follows the [2.1.0 spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and defines two rules:

- **PF001** (warning) — PII detected in source file
- **PF002** (error) — Prompt injection pattern detected

Once uploaded, findings appear in your repository's Security tab under Code Scanning alerts. They track across commits, so you can see when an issue was introduced and when it was fixed.

## Dogfooding

We run promptfirewall on its own repo. The CI workflow includes a self-scan step:

```yaml
- name: Build CLI
  run: cargo build --release --package promptfirewall-cli
- name: Self-scan
  run: ./target/release/promptfirewall . --format text --fail-on-findings
```

## What's next

- Custom regex rules via config file
- `.promptfirewallignore` for inline suppression
- Pre-commit hook integration

If you're building anything with LLMs, add the scan to your pipeline. It takes 30 seconds to set up and catches things code review misses.

---

[GitHub](https://github.com/TimurRakhmatullin86/promptfirewall) · [crates.io](https://crates.io/crates/promptfirewall) · [npm](https://www.npmjs.com/package/promptfirewall-rs) · [PyPI](https://pypi.org/project/promptfirewall/)
