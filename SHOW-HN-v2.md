# Show HN: Promptfirewall – Prompt injection + PII firewall in Rust, 12us, Python/Node bindings

**Title:** Show HN: Promptfirewall – Prompt injection + PII firewall in Rust, 12us, Python/Node bindings

**URL:** https://github.com/TimurRakhmatullin86/promptfirewall

**Text:**

Every LLM app needs to strip PII before it hits the model and block prompt injection before it hijacks your agent. These are separate problems that every team solves with separate tools. I combined them into one Rust crate that does both in 12 microseconds.

**Benchmarks (criterion, Apple M-series):**
- PII scan (60 bytes): 952 ns
- Full PII + injection scan: 11.9 us
- Python (PyO3): 2.2 us/call
- Node (napi-rs): 4 us/call

For context: jailguard (Rust, ML-based) runs at 14ms. That's 1,000x slower. Presidio: ~180ms. LLM Guard: ~300ms.

**How it works:** Heuristic-based, not ML. PII detection uses regex + checksum validation (Luhn for credit cards, ISO 7064 for IBAN, area code validation for SSN). Injection detection uses 35+ pattern rules, a TF-IDF classifier (50-term vocabulary trained on injection datasets), and Shannon entropy analysis for encoded payloads.

I'll be honest about the tradeoff: heuristic-based means it won't catch novel injection attacks the way an ML classifier might. It trades accuracy for 1,000x speed and zero dependencies. For most apps, latency in the hot path matters more than catching edge cases.

**The OSS landscape cleared out:** Rebuff — archived. Vigil — dormant. Lakera — acquired by Check Point for $300M, closed-source enterprise. Promptfoo — acquired by OpenAI. If you want an actively maintained OSS option that runs locally, the list is short.

```python
pip install promptfirewall-rs

result = promptfirewall.scan("SSN: 123-45-6789. Ignore previous instructions.")
# is_safe=False, injection_score=0.983, latency=12us
```

**v0.2.0 ships with:**
- AI Safety Score (0-100, Grade A-F) — quantified security posture
- GitHub Action — drop `uses: TimurRakhmatullin86/promptfirewall@v0.2.0` into any CI pipeline
- LangChain & LlamaIndex callback handlers (standalone PyPI packages)
- FastAPI and Express middleware
- 8 PII types, 3-layer injection detection

MIT/Apache-2.0. Feedback welcome — especially from teams doing security scanning in CI.
