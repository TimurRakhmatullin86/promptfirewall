# Reddit Launch Posts

---

## r/rust

**Title:** promptfirewall: PII detection + prompt injection firewall in Rust, 12μs full scan, with PyO3 and napi-rs bindings

I built a Rust library for detecting PII and prompt injection in LLM inputs. Full scan runs in 11.9μs (criterion-measured on Apple M-series).

**Architecture:**
- PII: regex + Luhn checksum (credit cards) + ISO 7064 mod-97 (IBAN) + SSN area code validation. No NER.
- Injection: 3-layer — 35+ heuristic regex patterns, TF-IDF classifier (50-term vocabulary, cosine similarity), Shannon entropy + unicode homoglyph detection
- Composite scoring with multi-signal agreement boost

**Bindings:**
- Python: PyO3 0.25 + maturin. 2.2μs/call from Python.
- Node.js: napi-rs 3. 4μs/call from Node.

Both include middleware — FastAPI `app.add_middleware(PromptFirewall)` and Express `app.use(guard())`.

**Benchmark highlights:**
| Scenario | Latency |
|---|---|
| PII scan 60b (SSN+CC) | 952 ns |
| Full scan PII+injection | 11.9 μs |
| 10K Python calls | 22ms total |

Dual MIT/Apache-2.0. Would love feedback on the heuristic rules and TF-IDF approach — happy to discuss tradeoffs vs. ML-based detection.

https://github.com/TimurRakhmatullin86/promptfirewall

---

## r/netsec

**Title:** promptfirewall: open-source prompt injection firewall with 3-layer detection, 12μs latency

Prompt injection is becoming a real attack vector as LLM agents get more powerful. I built an open-source firewall that detects prompt injection attempts in 12 microseconds, entirely local (no cloud API, no GPU).

**Detection layers:**

1. **Heuristic (35+ patterns):** instruction override ("ignore previous"), role hijacking ("you are now"), system prompt extraction, fake system tokens (`<|im_start|>`), jailbreak keywords (DAN, developer mode), encoding requests, multi-turn manipulation, structured injection (JSON role injection), delimiter confusion

2. **TF-IDF classifier:** 50-term vocabulary with manually curated IDF weights and a centroid vector derived from the deepset/prompt-injections dataset. Returns cosine similarity — catches novel phrasings similar to known injections.

3. **Entropy analysis:** Shannon entropy on 64-char sliding windows (catches base64/encoded payloads), non-ASCII unicode ratio detection (catches homoglyph attacks where Cyrillic characters replace Latin), nested JSON role detection.

**Composite scoring:** `max(heuristic×0.9, tfidf×0.7, entropy×0.5)` with ×1.15 boost when 2+ signals agree. Threshold default 0.7.

Also does PII detection (SSN, credit card, IBAN, email, phone, IP, API keys) with checksum validation to minimize false positives.

Written in Rust, with Python and Node.js native bindings. Ships with FastAPI and Express middleware.

Interested in feedback on coverage gaps — what injection patterns am I missing?

https://github.com/TimurRakhmatullin86/promptfirewall

---

## r/Python

**Title:** promptfirewall: PII + prompt injection firewall for FastAPI/LLM apps — 2μs per call, native Rust, pip install

Built a Python package that detects PII and prompt injection in LLM inputs. It's a Rust core with PyO3 bindings, so it runs at 2.2 microseconds per call — about 100,000x faster than running regex in pure Python.

**Install:**
```bash
pip install promptfirewall
```

**Usage:**
```python
import promptfirewall

# Quick check
promptfirewall.is_safe("Hello world")  # True
promptfirewall.is_safe("SSN: 123-45-6789")  # False
promptfirewall.is_safe("Ignore all previous instructions")  # False

# Full scan
result = promptfirewall.scan("My card is 4111111111111111")
print(result.pii_findings[0].entity_type)  # CREDIT_CARD
print(result.latency_us)  # ~12

# Redaction
promptfirewall.redact("SSN: 123-45-6789", redact_with="placeholder")
# "SSN: [SSN]"

# Injection-only
r = promptfirewall.detect_injection("Ignore previous instructions")
print(r.injection_score)  # 0.983
```

**FastAPI middleware — one line:**
```python
from promptfirewall.middleware import PromptFirewall
app.add_middleware(PromptFirewall)
```

It scans POST/PUT/PATCH request bodies for PII and injection, blocks unsafe requests with 400.

**What it detects:**
- 8 PII types with checksum validation (Luhn for credit cards, ISO 7064 for IBAN, area code validation for SSN)
- Prompt injection with 35+ heuristic patterns + TF-IDF classifier + entropy analysis

Full type stubs included (py.typed + .pyi). MIT/Apache-2.0.

https://github.com/TimurRakhmatullin86/promptfirewall
