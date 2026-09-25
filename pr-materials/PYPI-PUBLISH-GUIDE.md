# PyPI Publishing Guide — Standalone Integration Packages

## Prerequisites

1. PyPI account: https://pypi.org/account/register/
2. API token: https://pypi.org/manage/account/token/
3. `hatch` installed: `pip install hatch`

## Package 1: langchain-promptfirewall

```bash
cd ~/eb1-portfolio/own/langchain-promptfirewall

# Build
hatch build

# Test locally
pip install dist/langchain_promptfirewall-0.1.0-py3-none-any.whl

# Publish to PyPI
hatch publish
# Enter: __token__ as username, pypi-XXXXX as password
```

### After publishing — File LangChain listing issue:

1. Go to: https://github.com/langchain-ai/docs/issues/new?template=06-integration-submission.yml
2. Fill form:
   - Display Name: `PromptFirewallHandler`
   - Language: Python
   - Component Type: callbacks
   - PyPI Package: `langchain-promptfirewall`
   - Docs URL: https://github.com/TimurRakhmatullin86/langchain-promptfirewall
   - Source Repo: `TimurRakhmatullin86/langchain-promptfirewall`
   - Description: Sub-millisecond PII detection and prompt injection firewall for LLM applications (12μs, zero network calls, zero GPU)
   - Package published: Yes

## Package 2: llama-index-callbacks-promptfirewall

```bash
cd ~/eb1-portfolio/own/llama-index-callbacks-promptfirewall

# Build
hatch build

# Test locally
pip install dist/llama_index_callbacks_promptfirewall-0.1.0-py3-none-any.whl

# Publish to PyPI
hatch publish
```

### After publishing — File LlamaIndex docs PR:

1. Fork `run-llama/llama_index`
2. Add entry to integrations listing (callback handlers section)
3. PR title: `docs: add promptfirewall callback integration to integrations listing`
4. PR body: see `llamaindex-pr-description.md`

## GitHub Repos to Create First

```bash
# Create repos
gh repo create TimurRakhmatullin86/langchain-promptfirewall --public --description "LangChain callback handler for promptfirewall — PII detection & prompt injection firewall" --clone=false
gh repo create TimurRakhmatullin86/llama-index-callbacks-promptfirewall --public --description "LlamaIndex callback handler for promptfirewall — PII detection & prompt injection firewall" --clone=false

# Push langchain package
cd ~/eb1-portfolio/own/langchain-promptfirewall
git remote add origin https://github.com/TimurRakhmatullin86/langchain-promptfirewall.git
git push -u origin main

# Push llamaindex package
cd ~/eb1-portfolio/own/llama-index-callbacks-promptfirewall
git remote add origin https://github.com/TimurRakhmatullin86/llama-index-callbacks-promptfirewall.git
git push -u origin main
```

## Verification After Publishing

```bash
# Test installation from PyPI
pip install langchain-promptfirewall llama-index-callbacks-promptfirewall

# Verify imports
python -c "from langchain_promptfirewall import PromptFirewallHandler; print('LangChain OK')"
python -c "from llama_index_callbacks_promptfirewall import PromptFirewallHandler; print('LlamaIndex OK')"
```
