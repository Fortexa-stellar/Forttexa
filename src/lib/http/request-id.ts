/**
 * Inbound `x-request-id` sanitization.
 *
 * Oversized or control-character request IDs inflate logs and can corrupt
 * audit correlation. Callers must resolve ids through {@link resolveRequestId}
 * so responses and logs never echo an unsafe client value.
 */

/** Request/response header carrying the correlation id. */
export const REQUEST_ID_HEADER = "x-request-id";

/**
 * Documented maximum length for an inbound `x-request-id` header value.
 * Values longer than this are rejected and replaced with a server-generated id.
 */
export const MAX_REQUEST_ID_LENGTH = 128;

/** Safe-by-construction charset: alphanumerics, dot, underscore, dash. */
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]+$/;

/**
 * Whether a value is safe to reuse as a request id.
 *
 * Accepted ids are 1–{@link MAX_REQUEST_ID_LENGTH} characters from
 * `[A-Za-z0-9._-]`, which covers UUIDs and common tracing formats while
 * rejecting whitespace, control characters, and header-injection attempts.
 */
export function isValidRequestId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_REQUEST_ID_LENGTH &&
    REQUEST_ID_PATTERN.test(value)
  );
}

/**
 * Resolve the correlation id for a request: reuse a safe inbound
 * `x-request-id`, otherwise mint a server UUID.
 */
export function resolveRequestId(request: { headers: Headers }): string {
  const incoming = request.headers.get(REQUEST_ID_HEADER);
  return isValidRequestId(incoming) ? incoming : crypto.randomUUID();
}
