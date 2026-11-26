export type RequireJsonContentTypeResult =
  | { ok: true }
  | { ok: false; error: string };

/**
 * Rejects mutating requests that do not declare a JSON body.
 *
 * The check is deliberately narrow: a missing or non-JSON `content-type`
 * cannot be parsed as a JSON request body, so the route returns a stable
 * 415 instead of surfacing a generic parse failure.
 */
export function requireJsonContentType(request: {
  headers: { get(name: string): string | null };
}): RequireJsonContentTypeResult {
  const raw = request.headers.get("content-type");
  if (!raw) {
    return {
      ok: false,
      error: "Content-Type must be application/json.",
    };
  }

  const mediaType = raw.split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    return {
      ok: false,
      error: "Content-Type must be application/json.",
    };
  }

  return { ok: true };
}
