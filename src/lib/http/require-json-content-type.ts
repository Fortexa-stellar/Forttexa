export function requireJsonContentType(
  request: Request,
): { ok: true } | { ok: false; error: string } {
  const header = request.headers.get("content-type");
  if (!header) {
    return { ok: false, error: "Content-Type must be application/json." };
  }

  const [mediaType] = header.split(";").map((part) => part.trim().toLowerCase());
  if (mediaType !== "application/json") {
    return { ok: false, error: "Content-Type must be application/json." };
  }

  return { ok: true };
}
