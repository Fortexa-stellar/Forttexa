export const MAX_REQUEST_ID_LENGTH = 128;
const requestIds = new WeakMap<object, string>();

export function requestIdFor(request: { headers: Headers }): string {
  const existing = requestIds.get(request);
  if (existing) return existing;

  const incoming = request.headers.get("x-request-id");
  const safe = incoming !== null &&
    incoming.length > 0 &&
    incoming.length <= MAX_REQUEST_ID_LENGTH &&
    !/[^A-Za-z0-9._-]/.test(incoming);
  const result = safe ? incoming : crypto.randomUUID();
  requestIds.set(request, result);
  return result;
}
