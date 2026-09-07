"""FastAPI middleware for promptfirewall.

Usage:
    from fastapi import FastAPI
    from promptfirewall.middleware import PromptFirewall

    app = FastAPI()
    app.add_middleware(PromptFirewall)

    # Or with options:
    app.add_middleware(
        PromptFirewall,
        injection_threshold=0.8,
        redact=True,
        redact_with="placeholder",
        on_unsafe="reject",      # "reject" | "flag"
        scan_fields=["prompt", "message", "content", "query", "input"],
    )
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional, Sequence

from promptfirewall._internal import scan as _scan


class PromptFirewall:
    def __init__(
        self,
        app: Any,
        *,
        detect_pii: bool = True,
        detect_injection: bool = True,
        pii_types: Optional[list[str]] = None,
        injection_threshold: float = 0.7,
        redact: bool = False,
        redact_with: str = "mask",
        on_unsafe: str = "reject",
        scan_fields: Sequence[str] = (
            "prompt",
            "message",
            "content",
            "query",
            "input",
            "text",
        ),
        on_scan: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.app = app
        self.detect_pii = detect_pii
        self.detect_injection = detect_injection
        self.pii_types = list(pii_types) if pii_types else None
        self.injection_threshold = injection_threshold
        self.redact = redact
        self.redact_with = redact_with
        self.on_unsafe = on_unsafe
        self.scan_fields = list(scan_fields)
        self.on_scan = on_scan

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        body_parts: list[bytes] = []
        request_complete = False

        async def receive_wrapper() -> dict:
            nonlocal request_complete
            message = await receive()
            if message["type"] == "http.request":
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    request_complete = True
            return message

        first_message = await receive_wrapper()

        while not request_complete:
            await receive_wrapper()

        body = b"".join(body_parts)
        texts_to_scan = self._extract_texts(body)

        for text in texts_to_scan:
            result = _scan(
                text,
                detect_pii=self.detect_pii,
                detect_injection=self.detect_injection,
                pii_types=self.pii_types,
                injection_threshold=self.injection_threshold,
                redact=self.redact,
                redact_with=self.redact_with,
            )

            if self.on_scan is not None:
                self.on_scan(result)

            if not result.is_safe and self.on_unsafe == "reject":
                response_body = json.dumps(
                    {
                        "error": "Request blocked by promptfirewall",
                        "injection_score": result.injection_score,
                        "pii_count": len(result.pii_findings),
                    }
                ).encode()

                await send(
                    {
                        "type": "http.response.start",
                        "status": 400,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [
                                b"content-length",
                                str(len(response_body)).encode(),
                            ],
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": response_body,
                    }
                )
                return

        message_to_replay = {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }
        replayed = False

        async def replay_receive() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                return message_to_replay
            return await receive()

        await self.app(scope, replay_receive, send)

    def _extract_texts(self, body: bytes) -> list[str]:
        if not body:
            return []

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        texts: list[str] = []

        if isinstance(data, dict):
            self._walk_dict(data, texts)
        elif isinstance(data, str):
            texts.append(data)

        return texts

    def _walk_dict(self, data: dict, texts: list[str]) -> None:
        for field in self.scan_fields:
            value = data.get(field)
            if isinstance(value, str) and value:
                texts.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk_dict(item, texts)
                    elif isinstance(item, str) and item:
                        texts.append(item)

        if "messages" in data and isinstance(data["messages"], list):
            for msg in data["messages"]:
                if isinstance(msg, dict):
                    self._walk_dict(msg, texts)
