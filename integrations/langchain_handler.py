"""LangChain callback handler for promptfirewall.

Scans LLM inputs for PII and prompt injection before they reach the model.
Optionally redacts PII in-place and blocks detected injection attempts.

Usage:
    from promptfirewall_integrations.langchain_handler import PromptFirewallHandler

    handler = PromptFirewallHandler()
    llm = ChatOpenAI(callbacks=[handler])
    llm.invoke("Hello, my SSN is 123-45-6789")
    # Raises PromptInjectionError or redacts PII before sending

    # Or attach to a chain:
    chain = prompt | llm | parser
    chain.invoke({"input": "..."}, config={"callbacks": [handler]})
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from langchain_core.callbacks import BaseCallbackHandler

import promptfirewall

logger = logging.getLogger("promptfirewall.langchain")


class PromptInjectionError(Exception):
    """Raised when a prompt injection attempt is detected."""

    def __init__(
        self,
        message: str,
        injection_score: float,
        injection_labels: list[str],
    ) -> None:
        super().__init__(message)
        self.injection_score = injection_score
        self.injection_labels = injection_labels


class PiiDetectedError(Exception):
    """Raised when PII is detected and blocking mode is enabled."""

    def __init__(
        self,
        message: str,
        pii_findings: list[dict[str, Any]],
    ) -> None:
        super().__init__(message)
        self.pii_findings = pii_findings


@dataclass
class ScanEvent:
    """Record of a single prompt scan."""

    prompt: str
    is_safe: bool
    injection_score: float
    injection_labels: list[str]
    pii_findings: list[dict[str, Any]]
    redacted_text: Optional[str]
    action_taken: str  # "passed", "redacted", "blocked_injection", "blocked_pii"
    latency_us: int


class PromptFirewallHandler(BaseCallbackHandler):
    """LangChain callback handler that scans prompts with promptfirewall.

    Args:
        block_injection: If True, raise PromptInjectionError when injection
            is detected. If False, log a warning and continue.
        redact_pii: If True, redact PII in prompts before they reach the LLM.
            Uses in-place mutation of the prompts list.
        block_pii: If True, raise PiiDetectedError instead of redacting.
            Takes precedence over redact_pii.
        injection_threshold: Score threshold (0.0-1.0) above which a prompt
            is considered an injection attempt. Default 0.7.
        redact_with: Redaction strategy - "placeholder" (e.g. [SSN]),
            "mask" (e.g. ***-**-****), or "hash". Default "placeholder".
        pii_types: List of PII types to detect. None means all types.
            Valid types: "ssn", "credit_card", "email", "phone", "iban".
        on_scan: Optional callback invoked with each ScanEvent.
    """

    # LangChain uses this to decide callback ordering
    raise_error = True

    def __init__(
        self,
        *,
        block_injection: bool = True,
        redact_pii: bool = True,
        block_pii: bool = False,
        injection_threshold: float = 0.7,
        redact_with: str = "placeholder",
        pii_types: Optional[list[str]] = None,
        on_scan: Optional[Any] = None,
    ) -> None:
        super().__init__()
        self.block_injection = block_injection
        self.redact_pii = redact_pii
        self.block_pii = block_pii
        self.injection_threshold = injection_threshold
        self.redact_with = redact_with
        self.pii_types = pii_types
        self.on_scan = on_scan
        self._scan_history: list[ScanEvent] = []

    @property
    def scan_history(self) -> list[ScanEvent]:
        """Access the history of all scan events."""
        return list(self._scan_history)

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Scan each prompt before it reaches the LLM.

        This method is called by LangChain before sending prompts to the model.
        It mutates the prompts list in-place when redacting PII.
        """
        for i, prompt in enumerate(prompts):
            result = promptfirewall.scan(
                prompt,
                detect_pii=True,
                detect_injection=True,
                pii_types=self.pii_types,
                injection_threshold=self.injection_threshold,
                redact=self.redact_pii or self.block_pii,
                redact_with=self.redact_with,
            )

            pii_dicts = [f.to_dict() for f in result.pii_findings]
            action = "passed"

            # Check injection first (higher severity)
            if result.injection_score >= self.injection_threshold:
                action = "blocked_injection"
                event = ScanEvent(
                    prompt=prompt,
                    is_safe=False,
                    injection_score=result.injection_score,
                    injection_labels=list(result.injection_labels),
                    pii_findings=pii_dicts,
                    redacted_text=result.redacted_text,
                    action_taken=action,
                    latency_us=result.latency_us,
                )
                self._scan_history.append(event)
                if self.on_scan:
                    self.on_scan(event)

                if self.block_injection:
                    raise PromptInjectionError(
                        f"Prompt injection detected (score={result.injection_score:.2f}, "
                        f"labels={result.injection_labels})",
                        injection_score=result.injection_score,
                        injection_labels=list(result.injection_labels),
                    )
                else:
                    logger.warning(
                        "Prompt injection detected (score=%.2f, labels=%s) "
                        "but blocking is disabled",
                        result.injection_score,
                        result.injection_labels,
                    )

            # Check PII
            if result.pii_findings:
                if self.block_pii:
                    action = "blocked_pii"
                    event = ScanEvent(
                        prompt=prompt,
                        is_safe=False,
                        injection_score=result.injection_score,
                        injection_labels=list(result.injection_labels),
                        pii_findings=pii_dicts,
                        redacted_text=result.redacted_text,
                        action_taken=action,
                        latency_us=result.latency_us,
                    )
                    self._scan_history.append(event)
                    if self.on_scan:
                        self.on_scan(event)

                    types_found = [f["entity_type"] for f in pii_dicts]
                    raise PiiDetectedError(
                        f"PII detected in prompt: {types_found}",
                        pii_findings=pii_dicts,
                    )

                if self.redact_pii and result.redacted_text is not None:
                    action = "redacted"
                    prompts[i] = result.redacted_text
                    logger.info(
                        "Redacted %d PII finding(s) in prompt",
                        len(result.pii_findings),
                    )

            event = ScanEvent(
                prompt=prompt,
                is_safe=result.is_safe,
                injection_score=result.injection_score,
                injection_labels=list(result.injection_labels),
                pii_findings=pii_dicts,
                redacted_text=result.redacted_text,
                action_taken=action,
                latency_us=result.latency_us,
            )
            self._scan_history.append(event)
            if self.on_scan:
                self.on_scan(event)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        **kwargs: Any,
    ) -> None:
        """Scan chat messages before they reach the LLM.

        Extracts text content from BaseMessage objects and scans them.
        Mutates message content in-place when redacting.
        """
        for message_group in messages:
            for message in message_group:
                # Extract text content from the message
                content = getattr(message, "content", None)
                if not content or not isinstance(content, str):
                    continue

                result = promptfirewall.scan(
                    content,
                    detect_pii=True,
                    detect_injection=True,
                    pii_types=self.pii_types,
                    injection_threshold=self.injection_threshold,
                    redact=self.redact_pii or self.block_pii,
                    redact_with=self.redact_with,
                )

                pii_dicts = [f.to_dict() for f in result.pii_findings]
                action = "passed"

                if result.injection_score >= self.injection_threshold:
                    action = "blocked_injection"
                    self._record_event(
                        content, result, pii_dicts, action,
                    )
                    if self.block_injection:
                        raise PromptInjectionError(
                            f"Prompt injection detected in chat message "
                            f"(score={result.injection_score:.2f})",
                            injection_score=result.injection_score,
                            injection_labels=list(result.injection_labels),
                        )
                    else:
                        logger.warning(
                            "Prompt injection in chat message "
                            "(score=%.2f) - blocking disabled",
                            result.injection_score,
                        )

                if result.pii_findings:
                    if self.block_pii:
                        action = "blocked_pii"
                        self._record_event(
                            content, result, pii_dicts, action,
                        )
                        types_found = [f["entity_type"] for f in pii_dicts]
                        raise PiiDetectedError(
                            f"PII detected in chat message: {types_found}",
                            pii_findings=pii_dicts,
                        )

                    if self.redact_pii and result.redacted_text is not None:
                        action = "redacted"
                        message.content = result.redacted_text

                self._record_event(content, result, pii_dicts, action)

    def _record_event(
        self,
        prompt: str,
        result: Any,
        pii_dicts: list[dict[str, Any]],
        action: str,
    ) -> None:
        event = ScanEvent(
            prompt=prompt,
            is_safe=result.is_safe,
            injection_score=result.injection_score,
            injection_labels=list(result.injection_labels),
            pii_findings=pii_dicts,
            redacted_text=result.redacted_text,
            action_taken=action,
            latency_us=result.latency_us,
        )
        self._scan_history.append(event)
        if self.on_scan:
            self.on_scan(event)
