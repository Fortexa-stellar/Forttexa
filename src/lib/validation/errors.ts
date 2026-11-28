import type { ZodError } from "zod";

import type { LogContext } from "@/lib/observability/logger";
import { logWarn } from "@/lib/observability/logger";
import { redactSensitiveFields } from "@/lib/observability/redact";
import { MEMO_TOO_LONG_CODE } from "@/lib/stellar/memo";

export const SENSITIVE_FIELD_KEYS = new Set([
  "api_key",
  "apikey",
  "authorization",
  "cookie",
  "fortexa_session",
  "groq_api_key",
  "password",
  "secret",
  "signature",
  "signed_xdr",
  "signedxdr",
  "token",
  "xdr",
]);

const PUBLIC_SENSITIVE_FIELD_MESSAGE = "Invalid value.";

// Stable codes that carry none of the submitted value, so they can be shown even
// for a field whose other messages are hidden (the memo is free-form user text).
const PUBLIC_SAFE_FIELD_CODES = new Set<string>([MEMO_TOO_LONG_CODE]);

// Memo values carry free-text user content; never log them (issue #205).
SENSITIVE_FIELD_KEYS.add("memo");

function fieldPathHasSensitiveKey(fieldPath: string): boolean {
  return fieldPath.split(".").some((segment) => SENSITIVE_FIELD_KEYS.has(segment.toLowerCase()));
}

export type PublicValidationDetails = {
  formErrors: string[];
  fieldErrors: Record<string, string[]>;
};

export function toPublicValidationDetails(error: ZodError): PublicValidationDetails {
  const flattened = error.flatten();
  const fieldErrors: Record<string, string[]> = {};

  for (const [field, messages] of Object.entries(flattened.fieldErrors) as Array<
    [string, string[] | undefined]
  >) {
    if (fieldPathHasSensitiveKey(field)) {
      fieldErrors[field] = [
        ...new Set(
          ((messages as string[]) ?? []).map((message) =>
            PUBLIC_SAFE_FIELD_CODES.has(message) ? message : PUBLIC_SENSITIVE_FIELD_MESSAGE,
          ),
        ),
      ];
    } else {
      fieldErrors[field] = (messages as string[]) ?? [];
    }
  }

  return {
    formErrors: flattened.formErrors,
    fieldErrors,
  };
}

const HORIZON_RESULT_CODE_PATTERN = /\btx_[a-z0-9_]+\b|\bop_[a-z0-9_]+\b/gi;

export function logValidationFailure(
  message: string,
  context: LogContext,
  error: ZodError,
  rawBody?: unknown,
): void {
  logWarn(
    message,
    redactSensitiveFields({
      ...context,
      validation: error.flatten(),
      body: rawBody,
    }) as unknown as LogContext,
  );
}
