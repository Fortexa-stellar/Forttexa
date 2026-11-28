import { NextRequest } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { AUDIT_PAGE_MAX_OFFSET, parseAuditPagination } from "@/lib/audit/pagination";
import { jsonWithRequestContext } from "@/lib/observability/http";
import { listAuditEntries } from "@/lib/storage/audit-store";

export async function GET(request: NextRequest) {
  const startedAtMs = Date.now();
  const auth = requireAuth(request);

  if (!auth.ok) {
    return auth.response;
  }

  const parsedPagination = parseAuditPagination(request.nextUrl.searchParams);
  if (!parsedPagination.ok) {
    return jsonWithRequestContext(request, {
      route: "/api/audit",
      startedAtMs,
      status: 400,
      body: {
        error: "Invalid audit pagination parameters.",
        code: parsedPagination.code,
      },
    });
  }

  const userId = auth.session.userId;
  const { limit, offset } = parsedPagination.pagination;
  const page = await listAuditEntries(userId, undefined, { limit: limit + 1, offset });
  const hasMore = page.length > limit;
  const nextCursor = hasMore && offset + limit <= AUDIT_PAGE_MAX_OFFSET
    ? String(offset + limit)
    : null;

  return jsonWithRequestContext(request, {
    route: "/api/audit",
    startedAtMs,
    status: 200,
    body: {
      entries: page.slice(0, limit),
      userId,
      pagination: { limit, offset, nextCursor },
    },
  });
}
