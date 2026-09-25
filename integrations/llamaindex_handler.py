"""LlamaIndex callback handler for promptfirewall.

Scans queries and LLM inputs for PII and prompt injection.

Usage:
    from promptfirewall_integrations.llamaindex_handler import PromptFirewallHandler
    from llama_index.core.callbacks import CallbackManager

    handler = PromptFirewallHandler()
    callback_manager = CallbackManager([handler])

    # Attach to Settings (global)
    from llama_index.core import Settings
    Settings.callback_manager = callback_manager

    # Or attach to a specific index/query engine
    index = VectorStoreIndex.from_documents(docs, callback_manager=callback_manager)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from llama_index.core.callbacks import CBEventType, EventPayload
from llama_index.core.callbacks.base_handler import BaseCallbackHandler

import promptfirewall

logger = logging.getLogger("promptfirewall.llamaindex")


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
    """Record of a single scan."""

    text: str
    event_type: str
    is_safe: bool
    injection_score: float
    pii_findings: list[dict[str, Any]]
    action_taken: str
    latency_us: int


class PromptFirewallHandler(BaseCallbackHandler):
    """LlamaIndex callback handler that scans inputs with promptfirewall.

    Intercepts LLM and query events, scanning text for PII and injection.

    Args:
        block_injection: If True, raise PromptInjectionError on detection.
        redact_pii: If True, log a warning when PII is found (LlamaIndex
            callbacks cannot mutate payloads, so redaction happens at the
            scan level for logging purposes).
        block_pii: If True, raise PiiDetectedError when PII is found.
        injection_threshold: Score threshold for injection detection.
        pii_types: List of PII types to detect. None means all.
        on_scan: Optional callback invoked with each ScanEvent.
    """

    def __init__(
        self,
        *,
        block_injection: bool = True,
        redact_pii: bool = True,
        block_pii: bool = False,
        injection_threshold: float = 0.7,
        pii_types: Optional[list[str]] = None,
        on_scan: Optional[Any] = None,
    ) -> None:
        # LlamaIndex BaseCallbackHandler requires event_starts_to_ignore
        # and event_ends_to_ignore
        super().__init__(
            event_starts_to_ignore=[],
            event_ends_to_ignore=[],
        )
        self.block_injection = block_injection
        self.redact_pii = redact_pii
        self.block_pii = block_pii
        self.injection_threshold = injection_threshold
        self.pii_types = pii_types
        self.on_scan = on_scan
        self._scan_history: list[ScanEvent] = []

    @property
    def scan_history(self) -> list[ScanEvent]:
        """Access the history of all scan events."""
        return list(self._scan_history)

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        """Called when a trace starts. No-op."""

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """Called when a trace ends. No-op."""

    def on_event_start(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Scan text when LLM or query events start."""
        if payload is None:
            return event_id

        texts_to_scan: list[str] = []

        # Extract text based on event type
        if event_type == CBEventType.LLM:
            # LLM events carry prompts or messages
            if EventPayload.PROMPT in payload:
                prompt = payload[EventPayload.PROMPT]
                if isinstance(prompt, str) and prompt:
                    texts_to_scan.append(prompt)

            if EventPayload.MESSAGES in payload:
                messages = payload[EventPayload.MESSAGES]
                if isinstance(messages, list):
                    for msg in messages:
                        content = getattr(msg, "content", None)
                        if isinstance(content, str) and content:
                            texts_to_scan.append(content)
                        elif isinstance(msg, str) and msg:
                            texts_to_scan.append(msg)

        elif event_type == CBEventType.QUERY:
            if EventPayload.QUERY_STR in payload:
                query = payload[EventPayload.QUERY_STR]
                if isinstance(query, str) and query:
                    texts_to_scan.append(query)

        for text in texts_to_scan:
            self._scan_text(text, event_type.name)

        return event_id

    def on_event_end(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Called when an event ends. No-op for scanning."""

    def _scan_text(self, text: str, event_type_name: str) -> None:
        """Scan a single text and take action based on configuration."""
        result = promptfirewall.scan(
            text,
            detect_pii=True,
            detect_injection=True,
            pii_types=self.pii_types,
            injection_threshold=self.injection_threshold,
        )

        pii_dicts = [f.to_dict() for f in result.pii_findings]
        action = "passed"

        # Check injection
        if result.injection_score >= self.injection_threshold:
            action = "blocked_injection"
            self._record_event(text, event_type_name, result, pii_dicts, action)

            if self.block_injection:
                raise PromptInjectionError(
                    f"Prompt injection detected in {event_type_name} "
                    f"(score={result.injection_score:.2f})",
                    injection_score=result.injection_score,
                    injection_labels=list(result.injection_labels),
                )
            else:
                logger.warning(
                    "Prompt injection detected in %s (score=%.2f) "
                    "- blocking disabled",
                    event_type_name,
                    result.injection_score,
                )

        # Check PII
        if result.pii_findings:
            if self.block_pii:
                action = "blocked_pii"
                self._record_event(text, event_type_name, result, pii_dicts, action)
                types_found = [f["entity_type"] for f in pii_dicts]
                raise PiiDetectedError(
                    f"PII detected in {event_type_name}: {types_found}",
                    pii_findings=pii_dicts,
                )

            if self.redact_pii:
                action = "warned_pii"
                logger.warning(
                    "PII detected in %s: %d finding(s)",
                    event_type_name,
                    len(result.pii_findings),
                )

        self._record_event(text, event_type_name, result, pii_dicts, action)

    def _record_event(
        self,
        text: str,
        event_type_name: str,
        result: Any,
        pii_dicts: list[dict[str, Any]],
        action: str,
    ) -> None:
        event = ScanEvent(
            text=text,
            event_type=event_type_name,
            is_safe=result.is_safe,
            injection_score=result.injection_score,
            pii_findings=pii_dicts,
            action_taken=action,
            latency_us=result.latency_us,
        )
        self._scan_history.append(event)
        if self.on_scan:
            self.on_scan(event)
