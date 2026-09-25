# PR Strategy: LangChain & LlamaIndex Integrations

## Critical Finding: Both Ecosystems Have Changed

**Neither LangChain nor LlamaIndex accepts new integrations into their monorepos.**

- **LangChain**: `langchain-community` is officially sunset and archived (June 2025). All new integrations must be **standalone PyPI packages** published independently. Listing on the LangChain docs happens via an issue template on `langchain-ai/docs`.
- **LlamaIndex**: The `llama_index` monorepo also stopped accepting new integration packages. New integrations should be standalone PyPI packages.

This means: **we are NOT submitting code PRs to langchain-ai/langchain or run-llama/llama_index.** Instead, we publish standalone packages and request documentation listings.

---

## Part 1: LangChain Integration

### Target: Standalone Package `langchain-promptfirewall`

**What we build:**
- A standalone PyPI package: `langchain-promptfirewall`
- GitHub repo: `TimurRakhmatullin86/langchain-promptfirewall`
- Contains the callback handler (already written at `integrations/langchain_handler.py`)
- Published to PyPI independently

**Package structure:**
```
langchain-promptfirewall/
  pyproject.toml          # hatchling build, deps: langchain-core>=1.6, promptfirewall-rs>=0.1
  langchain_promptfirewall/
    __init__.py            # exports PromptFirewallHandler
    _handler.py            # the callback handler code
    py.typed               # PEP 561 marker
  tests/
    test_handler.py        # unit tests (mock promptfirewall.scan)
    test_integration.py    # integration tests (optional, requires promptfirewall-rs)
  README.md
  LICENSE
  Makefile                 # lint, test, format targets
```

**Dependencies:**
```toml
[project]
name = "langchain-promptfirewall"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "langchain-core>=1.6.4,<2.0.0",
    "promptfirewall-rs>=0.1.0",
]
```

**Build system:** `hatchling` (matches LangChain partner packages)

### Step-by-step execution

1. **Create the standalone package repo** on GitHub
2. **Publish to PyPI** as `langchain-promptfirewall`
3. **File an integration listing issue** on `langchain-ai/docs` using template `06-integration-submission.yml`
   - Display name: `PromptFirewallHandler`
   - Language: Python
   - Component type: `callbacks`
   - PyPI package: `langchain-promptfirewall`
   - Docs URL: GitHub README
   - Description: "Sub-millisecond PII detection and prompt injection firewall for LLM applications. Scans prompts before they reach the model with 12us latency, zero network calls."
   - Source repo: `TimurRakhmatullin86/langchain-promptfirewall`
4. **A maintainer reviews** and applies `integration-run` label, triggering automation that creates a docs PR

### Listing type

We will get an **external listing** (YAML entry linking to our README). The hosted docs option requires 50,000+ monthly PyPI downloads, which we don't have.

### Important: Callbacks are Discouraged

The LangChain integration contributing page explicitly lists "Callbacks" under "Not these" (discouraged component types). The preferred pattern for cross-cutting concerns is now **middleware** (see `langchain.agents.middleware`). However, this applies to integrations seeking listing within the main docs. A standalone callback handler package on PyPI is still viable and will work with any LangChain application.

**Recommendation**: Publish the callback handler package first (it works, it's useful). If maintainers push back on the listing, consider refactoring as a middleware component. The handler code can support both patterns.

### Test requirements

- Unit tests with mocked `promptfirewall.scan()` calls
- Must pass `make lint` (ruff) and `make test` (pytest)
- Code coverage is good to have but no minimum threshold specified for external packages

---

## Part 2: LlamaIndex Integration

### Target: Standalone Package `llama-index-callbacks-promptfirewall`

**What we build:**
- A standalone PyPI package: `llama-index-callbacks-promptfirewall`
- GitHub repo: same as LangChain or under `langchain-promptfirewall` monorepo
- Contains the callback handler (already written at `integrations/llamaindex_handler.py`)

**Package structure (following existing pattern):**
```
llama-index-callbacks-promptfirewall/
  pyproject.toml          # hatchling build, llamahub config
  llama_index/
    callbacks/
      promptfirewall/
        __init__.py       # exports PromptFirewallHandler
        base.py           # the callback handler code
  tests/
    test_handler.py
  README.md
  LICENSE
  Makefile
```

**Dependencies:**
```toml
[project]
name = "llama-index-callbacks-promptfirewall"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "llama-index-core>=0.13.0,<0.15",
    "promptfirewall-rs>=0.1.0",
]
```

**LlamaHub configuration (in pyproject.toml):**
```toml
[tool.llamahub]
import_path = "llama_index.callbacks.promptfirewall"
contains_example = false
```

### Step-by-step execution

1. **Create the standalone package** (repo or subdirectory)
2. **Publish to PyPI** as `llama-index-callbacks-promptfirewall`
3. **Open a docs PR** or GitHub issue on `run-llama/llama_index` to add to the callbacks listing
4. LlamaIndex has no formal submission template; a GitHub issue or discussion is the path

### Key differences from LangChain handler

1. LlamaIndex callbacks **cannot mutate payloads in-place**. Our handler logs warnings for PII (or blocks) but cannot redact inline. This is documented in the handler already.
2. **The callback system is being deprecated** in favor of the new Instrumentation system (`llama-index-instrumentation`). The docs state: "The instrumentation module is meant to replace the legacy callbacks module." New integrations should consider using `BaseEventHandler` from `llama_index.core.instrumentation` instead.

### Instrumentation alternative

Consider also shipping a `BaseEventHandler` variant alongside the legacy callback:

```python
from llama_index.core.instrumentation.event_handlers import BaseEventHandler
from llama_index.core.instrumentation.events.llm import LLMStartEvent

class PromptFirewallEventHandler(BaseEventHandler):
    def handle(self, event: BaseEvent, **kwargs):
        if isinstance(event, LLMStartEvent):
            # scan the prompt
            ...
```

This future-proofs the integration. Both can be exported from the same package.

---

## Part 3: Timeline & Priority

### Recommended order

1. **LangChain first** (100k+ stars, higher visibility, clear submission process)
2. **LlamaIndex second** (40k+ stars, less formal process)

### Timeline

| Step | Target | Duration |
|------|--------|----------|
| Create `langchain-promptfirewall` repo | Week 1 | 1 day |
| Write tests, Makefile, pyproject.toml | Week 1 | 1 day |
| Publish to PyPI | Week 1 | Same day |
| File LangChain docs integration issue | Week 1 | Same day |
| Create `llama-index-callbacks-promptfirewall` | Week 2 | 1 day |
| Publish to PyPI | Week 2 | Same day |
| Open LlamaIndex docs issue/PR | Week 2 | Same day |
| Follow up on listing reviews | Week 3-4 | Patience |

### Prerequisites

- `promptfirewall-rs` must be published on PyPI (already done: v0.1.0)
- Handler code must work with current `langchain-core` and `llama-index-core` APIs
- Tests must pass

---

## Part 4: What Gets Listed

### LangChain docs listing (expected)

An entry in `integration_external_docs.yaml`:
```yaml
- name: PromptFirewallHandler
  pypi: langchain-promptfirewall
  docs_url: https://github.com/TimurRakhmatullin86/langchain-promptfirewall
  description: "Sub-millisecond PII detection and prompt injection firewall"
  component: callbacks
```

This appears on the LangChain integrations page under Callbacks.

### LlamaIndex docs listing (expected)

An entry in the callbacks section of the integrations page, linking to the PyPI package.

---

## Part 5: Realistic Assessment

### What will likely be accepted

- **LangChain external listing**: HIGH probability. The process is automated; if the package is on PyPI and works, the listing should go through. LangChain explicitly encourages community packages.
- **LlamaIndex listing**: MEDIUM probability. Less formal process, may require more back-and-forth.

### What will NOT happen

- We will NOT get code merged into `langchain-ai/langchain` -- the community package is archived
- We will NOT get a hosted docs page -- requires 50k+ monthly downloads
- We will NOT get featured integration status -- requires partner relationship or high traction

### Competitive advantage for the listing

- **Unique niche**: No security/safety callback handler exists in either ecosystem. Zero. The LangChain community had 28 callback handlers (aim, wandb, mlflow, etc.) -- all observability/tracing. None did PII or injection detection. Two issues requesting security callbacks (#40425, #40223) were closed as NOT_PLANNED.
- **LlamaIndex**: The only security-adjacent integration is `llama-index-postprocessor-presidio` (PII only, ~180ms, no injection detection). No callback-level security exists.
- **Performance**: 12us is unmatched -- every alternative is 100-10,000x slower
- **Zero dependencies**: No ML models, no GPU, no network calls
- **Already working**: Handler code exists and covers both `on_llm_start` and `on_chat_model_start`

---

## Part 6: Alternative PR Targets (Higher Impact)

If the goal is to get merged PRs into major repos for EB-1A evidence, consider these additional targets that DO accept contributions:

1. **LangChain main repo** (`langchain-ai/langchain`): Bug fixes, doc improvements, or enhancements to existing code (not new integrations)
2. **LlamaIndex main repo** (`run-llama/llama_index`): Same -- fixes and improvements to core code
3. **awesome-langchain** or similar curated lists: Add promptfirewall to community tool lists
4. **LangChain cookbook/examples**: Submit example notebooks showing the integration
