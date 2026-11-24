import { ZodError } from "zod";

import { toPublicValidationDetails } from "@/lib/validation/errors";
import type { PublicValidationDetails } from "@/lib/validation/errors";

/** Stable machine-readable code returned with a 400 for unrecognized request fields. */
export const UNKNOWN_FIELDS_CODE = "UNKNOWN_FIELDS";

/** Most field names echoed back in one response; the rest are only counted. */
export const MAX_REPORTED_UNKNOWN_FIELDS = 10;

/**
 * A field name is echoed only when it is a plain identifier. Anything else
 * (long strings, whitespace, markup, secret-looking blobs) is counted in
 * `omittedUnknownFieldCount` instead, so a hostile key can never be reflected
 * back. Values are never included.
 */
const SAFE_FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

export type UnknownFieldsBody = {
  error: string;
  code: typeof UNKNOWN_FIELDS_CODE;
  unknownFields: string[];
  omittedUnknownFieldCount: number;
  /** Remaining (non-unknown-field) validation problems, if any. */
  details?: PublicValidationDetails;
};

function isUnrecognizedKeysIssue(
  issue: ZodError["issues"][number],
): issue is ZodError["issues"][number] & { code: "unrecognized_keys"; keys: string[] } {
  return issue.code === "unrecognized_keys";
}

/**
 * Build the 400 body for a request that carried fields the schema does not
 * define, or `null` when the validation failure has no unknown fields (the
 * caller then keeps its existing response). Nested paths are reported with dot
 * notation, e.g. `decisionReceipt.destinaton`.
 */
export function buildUnknownFieldsBody(
  error: ZodError,
  message: string,
): UnknownFieldsBody | null {
  const names: string[] = [];
  let omitted = 0;
  const remaining: ZodError["issues"] = [];

  for (const issue of error.issues) {
    if (!isUnrecognizedKeysIssue(issue)) {
      remaining.push(issue);
      continue;
    }
    const prefix = issue.path.map(String);
    for (const key of issue.keys) {
      const segments = [...prefix, key];
      if (segments.every((segment) => SAFE_FIELD_NAME.test(segment))) {
        names.push(segments.join("."));
      } else {
        omitted += 1;
      }
    }
  }

  if (names.length === 0 && omitted === 0) return null;

  const sorted = [...new Set(names)].sort();
  const reported = sorted.slice(0, MAX_REPORTED_UNKNOWN_FIELDS);
  omitted += sorted.length - reported.length;

  const body: UnknownFieldsBody = {
    error: message,
    code: UNKNOWN_FIELDS_CODE,
    unknownFields: reported,
    omittedUnknownFieldCount: omitted,
  };
  if (remaining.length > 0) {
    body.details = toPublicValidationDetails(new ZodError(remaining));
  }
  return body;
}
