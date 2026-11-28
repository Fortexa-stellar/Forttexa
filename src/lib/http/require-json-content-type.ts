/** Message returned with the `415` for a request that is not JSON. */
export const JSON_CONTENT_TYPE_ERROR =
  "Content-Type must be application/json.";

export type RequireJsonContentTypeResult =
  | { ok: true }
  | { ok: false; status: 415; error: string };

/**
 * Accepts `application/json` and structured-syntax variants such as
 * `application/problem+json`, with or without parameters (`; charset=utf-8`),
 * matched case-insensitively. Anything else, including a missing header, is
 * refused so a route returns one stable `415` instead of a generic parse error.
 */
export function requireJsonContentType(
  request: Request,
): RequireJsonContentTypeResult {
  const header = request.headers.get("content-type");
  const mediaType = header?.split(";", 1)[0]?.trim().toLowerCase() ?? "";

  if (mediaType === "application/json" || /^application\/[\w.+-]+\+json$/.test(mediaType)) {
    return { ok: true };
  }

  return { ok: false, status: 415, error: JSON_CONTENT_TYPE_ERROR };
}
