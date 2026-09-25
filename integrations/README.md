# promptfirewall integrations

Framework integrations for [promptfirewall](https://github.com/TimurRakhmatullin86/promptfirewall) -- PII detection and prompt injection firewall for LLM applications.

## LangChain

### Install

```bash
pip install promptfirewall-rs langchain-core
```

### Usage

```python
from promptfirewall.integrations.langchain_handler import PromptFirewallHandler
from langchain_openai import ChatOpenAI

handler = PromptFirewallHandler()
llm = ChatOpenAI(callbacks=[handler])
llm.invoke("Hello, how are you?")
```

#### Configuration

```python
handler = PromptFirewallHandler(
    block_injection=True,       # raise on injection (default: True)
    redact_pii=True,            # redact PII before sending (default: True)
    block_pii=False,            # raise on PII instead of redacting (default: False)
    injection_threshold=0.7,    # score threshold (default: 0.7)
    redact_with="placeholder",  # "placeholder" | "mask" | "hash"
    pii_types=["ssn", "email"], # None = all types
)
```

#### What happens

- **Safe prompt** -- passes through unchanged.
- **PII detected** -- PII is redacted in-place before the prompt reaches the LLM. `"My SSN is 123-45-6789"` becomes `"My SSN is [SSN]"`.
- **Injection detected** -- raises `PromptInjectionError` (if `block_injection=True`) or logs a warning.
- **Both** -- injection check runs first. If it passes, PII is redacted.

#### Scan history

```python
for event in handler.scan_history:
    print(event.action_taken, event.injection_score, event.pii_findings)
```

## LlamaIndex

### Install

```bash
pip install promptfirewall-rs llama-index-core
```

### Usage

```python
from promptfirewall.integrations.llamaindex_handler import PromptFirewallHandler
from llama_index.core.callbacks import CallbackManager
from llama_index.core import Settings

handler = PromptFirewallHandler()
Settings.callback_manager = CallbackManager([handler])
```

Configuration options are the same as the LangChain handler. Note: LlamaIndex callbacks cannot mutate payloads in-place, so PII redaction logs a warning rather than modifying the text. Use `block_pii=True` to reject prompts containing PII.

## Vercel AI SDK (TypeScript)

### Install

```bash
npm install promptfirewall-rs ai
```

### Usage

```typescript
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';
import { promptFirewall } from './vercel_ai_middleware';

const model = promptFirewall(openai('gpt-4o'));
const { text } = await generateText({
  model,
  prompt: 'Hello, how are you?',
});
```

#### Configuration

```typescript
const model = promptFirewall(openai('gpt-4o'), {
  blockInjection: true,
  redactPii: true,
  injectionThreshold: 0.7,
  redactWith: 'placeholder',
  onScan: (event) => console.log(event.actionTaken),
});
```

## Example output

### Injection blocked

```
PromptInjectionError: Prompt injection detected (score=0.92, labels=['instruction_override'])
```

### PII redacted (LangChain)

```
INFO:promptfirewall.langchain:Redacted 2 PII finding(s) in prompt
# Prompt sent to LLM: "Contact me at [EMAIL], SSN [SSN]"
```

### Scan event

```python
ScanEvent(
    prompt="My SSN is 123-45-6789",
    is_safe=False,
    injection_score=0.05,
    pii_findings=[{"entity_type": "SSN", "text": "123-45-6789", ...}],
    redacted_text="My SSN is [SSN]",
    action_taken="redacted",
    latency_us=42,
)
```

## License

MIT OR Apache-2.0
