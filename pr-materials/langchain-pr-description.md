# LangChain Integration: PR Description

> **Note**: As of 2025, LangChain no longer accepts new integrations into the monorepo.
> The process is now: (1) publish a standalone PyPI package, (2) file an Integration
> Submission issue on `langchain-ai/docs`. This document contains materials for both steps.

---

## Step 1: Integration Submission Issue (langchain-ai/docs)

Filed at: https://github.com/langchain-ai/docs/issues/new?template=06-integration-submission.yml

### Form fields

| Field | Value |
|-------|-------|
| Display or Class Name | `PromptFirewallHandler` |
| Language | Python |
| Component Type | callbacks |
| PyPI Package Name | `langchain-promptfirewall` |
| Docs URL | https://github.com/TimurRakhmatullin86/langchain-promptfirewall |
| Source Repository | `TimurRakhmatullin86/langchain-promptfirewall` |
| Short Provider Description | Sub-millisecond PII detection and prompt injection firewall for LLM applications (12us, zero network calls, zero GPU) |
| Package published checkbox | Yes |

---

## Step 2: Standalone Package README

This is the README for the `langchain-promptfirewall` PyPI package. It doubles as the
documentation that the LangChain integration listing will link to.

---

# langchain-promptfirewall

[![PyPI](https://img.shields.io/pypi/v/langchain-promptfirewall)](https://pypi.org/project/langchain-promptfirewall/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

LangChain callback handler for [promptfirewall](https://github.com/TimurRakhmatullin86/promptfirewall) -- PII detection and prompt injection firewall.

**Sub-millisecond latency. Zero network calls. Zero GPU. Zero ML models.**

## Installation

```bash
pip install langchain-promptfirewall
```

## Quick Start

```python
from langchain_promptfirewall import PromptFirewallHandler
from langchain_openai import ChatOpenAI

handler = PromptFirewallHandler()
llm = ChatOpenAI(callbacks=[handler])
llm.invoke("Hello, how are you?")  # passes through
llm.invoke("My SSN is 123-45-6789")  # PII redacted before reaching OpenAI
```

That's it. Three lines to add PII detection and prompt injection blocking to any LangChain chain.

## What It Does

The handler intercepts prompts in `on_llm_start` and `on_chat_model_start` before they reach the LLM:

| Input | Action | Result |
|-------|--------|--------|
| Safe prompt | Pass through | Unchanged |
| Contains PII | Redact in-place | `"My SSN is 123-45-6789"` becomes `"My SSN is [SSN]"` |
| Injection attempt | Block | Raises `PromptInjectionError` |
| PII + injection | Block first | Injection takes precedence |

### Supported PII types

SSN, credit card (Luhn-validated), IBAN (ISO 7064), email, phone, IP address, AWS keys, API keys (sk-, ghp_, etc.)

### Injection detection

Three-layer detection: 35+ heuristic patterns, TF-IDF statistical classifier, Shannon entropy analysis. Catches instruction override, role hijacking, jailbreak attempts, system prompt extraction, and encoded payloads.

## Configuration

```python
handler = PromptFirewallHandler(
    block_injection=True,        # raise on injection (default: True)
    redact_pii=True,             # redact PII before sending (default: True)
    block_pii=False,             # raise on PII instead of redacting (default: False)
    injection_threshold=0.7,     # score threshold (default: 0.7)
    redact_with="placeholder",   # "placeholder" | "mask" | "hash"
    pii_types=["ssn", "email"],  # None = all types
    on_scan=lambda e: print(e),  # optional scan event callback
)
```

## Usage with Chains

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_promptfirewall import PromptFirewallHandler

handler = PromptFirewallHandler()
prompt = ChatPromptTemplate.from_template("Answer: {question}")
llm = ChatOpenAI()
chain = prompt | llm

# Handler scans every prompt before it reaches the LLM
result = chain.invoke(
    {"question": "What is 2+2?"},
    config={"callbacks": [handler]},
)
```

## Scan History

Every scan is recorded for audit:

```python
for event in handler.scan_history:
    print(f"{event.action_taken}: score={event.injection_score}, "
          f"pii={len(event.pii_findings)}, latency={event.latency_us}us")
```

## Performance

| Metric | Value |
|--------|-------|
| Full scan (PII + injection) | **12 us** |
| vs Presidio | 15,000x faster |
| vs LLM Guard | 25,000x faster |
| Network calls | Zero |
| GPU required | No |
| Binary size | ~2 MB |

Measured on Apple M-series, Rust 1.88, release mode. The Rust core is exposed to Python via PyO3.

## Why Not Alternatives?

| Tool | Status | Latency | Local? |
|------|--------|---------|--------|
| **promptfirewall** | **Active** | **12 us** | **Yes** |
| Rebuff | Archived | -- | -- |
| Lakera | Acquired (Check Point) | ~100ms | No (cloud API) |
| Promptfoo | Acquired (OpenAI) | -- | -- |
| Presidio | Active | ~180ms | Yes |
| LLM Guard | Active | ~300ms | Yes |

promptfirewall is the only active, local solution that does both PII detection and injection blocking in sub-millisecond time.

## Requirements

- Python >= 3.9
- `langchain-core >= 1.6.4`
- `promptfirewall-rs >= 0.1.0`

## License

MIT

---

## Alternate: PR to awesome-langchain or Cookbook

If the docs listing is slow, a parallel path is to submit to:

1. **awesome-langchain** (https://github.com/kyrolabs/awesome-langchain, 8k+ stars) -- add promptfirewall to the Security / Safety section
2. **LangChain Cookbook** (https://github.com/langchain-ai/langchain/tree/master/cookbook) -- submit a Jupyter notebook demonstrating the callback handler with a real chain
