/**
 * Marks an already-built response as uncacheable.
 *
 * Audit exports and integrity results carry sensitive operational evidence, so
 * no response from those routes may be stored by a shared cache. Responses the
 * routes build themselves pass `noStore: true` to `jsonWithRequestContext`;
 * this covers the ones they only forward, such as the 401 from `requireAuth`.
 */
export function markNoStore<T extends { headers: Headers }>(response: T): T {
  response.headers.set("Cache-Control", "no-store");
  return response;
}
