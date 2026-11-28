/** enforces that the request has an application/json content type
  * - accepts "application/json" with optional "; charset=..." parameter
  * - returns a stable 415 JSON error if the content type is missing or not JSON
  */
export function requireJsonContentType(request: Request) {
  const contentType = request.headers.get("content-type") ?? "";

  // match "application/json" with optional charset parameter
  const isJson = contentType.includes("application/json");

  if (!isJson) {
    return {
      ok: false,
      error: "Unsupported media type. Expected application/json.",
      code: "UNSUPPORTED_MEDIA_TYPE",
    };
  }

  return { ok: true };
}