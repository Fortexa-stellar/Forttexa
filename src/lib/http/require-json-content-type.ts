export type JsonContentTypeResult =
  | { ok: true }
  | { ok: false; error: string };

/**
 * Rejects requests that do not declare a JSON body. `application/json` with
 * optional parameters (such as charset) and structured syntax suffixes
 * (`application/ld+json`) are accepted; anything else, including a missing
 * header, is a stable 415 rather than a parse failure.
 */
export function requireJsonContentType(request: Request): JsonContentTypeResult {
  const header = request.headers.get("content-type");
  if (!header) {
    return { ok: false, error: "Content-Type must be application/json." };
  }

  const mediaType = header.split(";")[0]?.trim().toLowerCase() ?? "";
  const isJson = mediaType === "application/json" || mediaType.endsWith("+json");

  if (!isJson) {
    return { ok: false, error: "Content-Type must be application/json." };
  }

  return { ok: true };
}
