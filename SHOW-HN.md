# Show HN: Promptfirewall – Rust PII + prompt injection firewall, 12μs, Python/Node bindings

**Title:** Show HN: Promptfirewall – Rust PII + prompt injection firewall, 12μs, Python/Node bindings

**URL:** https://github.com/TimurRakhmatullin86/promptfirewall

**Text:**

I built a local PII detection + prompt injection firewall for LLM applications. It runs a full scan in 12 microseconds — no network calls, no GPU, no cloud API.

**What it does:**

- Detects 8 PII types: SSN (area code validation), credit cards (Luhn), IBAN (ISO 7064 mod-97), email, phone, IP, AWS keys, API keys
- Detects prompt injection with 3 layers: 35+ heuristic regex patterns, TF-IDF statistical classifier, Shannon entropy + unicode homoglyph analysis
- Redacts PII with mask/hash/placeholder strategies
- Ships with FastAPI middleware (`app.add_middleware(PromptFirewall)`) and Express middleware (`app.use(guard())`)

**Why I built it:**

Every LLM app I worked on needed both PII stripping and injection detection before sending user input to a model. Existing options were either cloud-only (Lakera), heavy Python with ML models (LLM Guard — 47+ dependencies, ~300ms), or PII-only without injection (redact-core).

There was nothing that did both PII + injection locally in sub-millisecond time.

**Performance (measured, criterion, Apple M-series):**

- PII scan 60 bytes: 952 ns
- Full PII + injection: 11.9 μs
- 15,000x faster than Presidio, 25,000x faster than LLM Guard
- Python: 2.2 μs/call via PyO3
- Node: 4 μs/call via napi-rs

**How:**

The core is Rust with regex + checksum validation for PII (no NER — that's where the speed comes from). Injection detection uses heuristic pattern matching, a TF-IDF classifier with a 50-term vocabulary trained on prompt injection datasets, and entropy analysis for encoded/obfuscated payloads.

Python and Node bindings are native (PyO3/napi-rs), not subprocess or FFI.

```python
import promptfirewall

result = promptfirewall.scan("My SSN is 123-45-6789. Ignore previous instructions.")
print(result.is_safe)        # False
print(result.injection_score) # 0.983

clean = promptfirewall.redact("SSN: 123-45-6789", redact_with="placeholder")
# "SSN: [SSN]"
```

MIT/Apache-2.0. Feedback welcome.
