/**
 * Vercel AI SDK middleware for promptfirewall.
 *
 * Wraps any language model to scan inputs for PII and prompt injection
 * before they reach the provider.
 *
 * @example
 * ```ts
 * import { openai } from '@ai-sdk/openai';
 * import { generateText } from 'ai';
 * import { promptFirewall } from './vercel_ai_middleware';
 *
 * const model = promptFirewall(openai('gpt-4o'));
 * const { text } = await generateText({
 *   model,
 *   prompt: 'Hello, how are you?',
 * });
 * ```
 */

import { scan, type JsScanResult, type JsScanOptions } from 'promptfirewall-rs';
import {
  type Experimental_LanguageModelV1Middleware as LanguageModelV1Middleware,
  experimental_wrapLanguageModel as wrapLanguageModel,
  type LanguageModelV1,
  type LanguageModelV1CallOptions,
} from 'ai';

export class PromptInjectionError extends Error {
  readonly injectionScore: number;
  readonly injectionLabels: string[];

  constructor(score: number, labels: string[]) {
    super(
      `Prompt injection detected (score=${score.toFixed(2)}, labels=${JSON.stringify(labels)})`
    );
    this.name = 'PromptInjectionError';
    this.injectionScore = score;
    this.injectionLabels = labels;
  }
}

export class PiiDetectedError extends Error {
  readonly piiFindings: Array<{ entityType: string; text: string }>;

  constructor(findings: Array<{ entityType: string; text: string }>) {
    const types = findings.map((f) => f.entityType);
    super(`PII detected in prompt: ${JSON.stringify(types)}`);
    this.name = 'PiiDetectedError';
    this.piiFindings = findings;
  }
}

export interface ScanEvent {
  text: string;
  isSafe: boolean;
  injectionScore: number;
  piiFindings: Array<{ entityType: string; text: string }>;
  actionTaken: 'passed' | 'redacted' | 'blocked_injection' | 'blocked_pii';
  latencyUs: number;
}

export interface PromptFirewallOptions {
  /** Block requests when injection is detected. Default: true */
  blockInjection?: boolean;
  /** Redact PII in prompts before sending. Default: true */
  redactPii?: boolean;
  /** Block requests when PII is detected (overrides redactPii). Default: false */
  blockPii?: boolean;
  /** Injection score threshold (0.0-1.0). Default: 0.7 */
  injectionThreshold?: number;
  /** Redaction strategy: "placeholder", "mask", or "hash". Default: "placeholder" */
  redactWith?: 'placeholder' | 'mask' | 'hash';
  /** PII types to detect. Undefined means all. */
  piiTypes?: string[];
  /** Callback invoked after each scan. */
  onScan?: (event: ScanEvent) => void;
}

/**
 * Extract text content from a Vercel AI SDK message part.
 */
function extractTextFromPart(part: unknown): string | null {
  if (typeof part === 'object' && part !== null && 'type' in part) {
    const typed = part as { type: string; text?: string };
    if (typed.type === 'text' && typeof typed.text === 'string') {
      return typed.text;
    }
  }
  return null;
}

/**
 * Create middleware that scans prompts with promptfirewall.
 */
function createPromptFirewallMiddleware(
  options: PromptFirewallOptions = {}
): LanguageModelV1Middleware {
  const {
    blockInjection = true,
    redactPii = true,
    blockPii = false,
    injectionThreshold = 0.7,
    redactWith = 'placeholder',
    piiTypes,
    onScan,
  } = options;

  const scanOpts: JsScanOptions = {
    detectPii: true,
    detectInjection: true,
    injectionThreshold,
    redact: redactPii || blockPii,
    redactWith,
  };
  if (piiTypes) {
    scanOpts.piiTypes = piiTypes;
  }

  function scanText(text: string): {
    result: JsScanResult;
    action: ScanEvent['actionTaken'];
  } {
    const result = scan(text, scanOpts);
    let action: ScanEvent['actionTaken'] = 'passed';

    if (result.injectionScore >= injectionThreshold) {
      action = 'blocked_injection';
      emitEvent(text, result, action);

      if (blockInjection) {
        throw new PromptInjectionError(
          result.injectionScore,
          result.injectionLabels
        );
      }
    }

    if (result.piiFindings.length > 0) {
      if (blockPii) {
        action = 'blocked_pii';
        emitEvent(text, result, action);
        throw new PiiDetectedError(
          result.piiFindings.map((f) => ({
            entityType: f.entityType,
            text: f.text,
          }))
        );
      }

      if (redactPii && result.redactedText) {
        action = 'redacted';
      }
    }

    emitEvent(text, result, action);
    return { result, action };
  }

  function emitEvent(
    text: string,
    result: JsScanResult,
    action: ScanEvent['actionTaken']
  ): void {
    if (onScan) {
      onScan({
        text,
        isSafe: result.isSafe,
        injectionScore: result.injectionScore,
        piiFindings: result.piiFindings.map((f) => ({
          entityType: f.entityType,
          text: f.text,
        })),
        actionTaken: action,
        latencyUs: result.latencyUs,
      });
    }
  }

  return {
    transformParams: async ({ params }: { params: LanguageModelV1CallOptions }) => {
      const newPrompt = params.prompt.map((message) => {
        if (message.role === 'user' || message.role === 'system') {
          const newContent = message.content.map((part) => {
            const text = extractTextFromPart(part);
            if (text === null) return part;

            const { result, action } = scanText(text);

            if (action === 'redacted' && result.redactedText) {
              return { ...part, text: result.redactedText };
            }
            return part;
          });
          return { ...message, content: newContent };
        }
        return message;
      });

      return { ...params, prompt: newPrompt };
    },
  };
}

/**
 * Wrap a language model with promptfirewall scanning.
 *
 * @example
 * ```ts
 * import { openai } from '@ai-sdk/openai';
 * import { promptFirewall } from './vercel_ai_middleware';
 *
 * const model = promptFirewall(openai('gpt-4o'));
 * ```
 */
export function promptFirewall(
  model: LanguageModelV1,
  options?: PromptFirewallOptions
): LanguageModelV1 {
  return wrapLanguageModel({
    model,
    middleware: createPromptFirewallMiddleware(options),
  });
}

export { createPromptFirewallMiddleware };
