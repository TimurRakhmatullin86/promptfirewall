# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in promptfirewall, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **timur.rakhmatullin86@gmail.com**

You should receive a response within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

This project handles sensitive data detection (PII) and prompt injection classification. Security issues in the detection logic (false negatives that allow PII leakage or injection bypass) are in scope.

## Telemetry

This library has **zero telemetry**. No data is collected, transmitted, or logged outside of your process. All processing happens locally on your CPU.
