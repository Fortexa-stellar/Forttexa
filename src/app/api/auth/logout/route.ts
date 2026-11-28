import { NextRequest, NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { clearSessionCookie } from "@/lib/auth/session-cookie";
import { revokeSession } from "@/lib/auth/session-revocation";
import { securityHeadersForRequest } from "@/lib/security/headers";

export async function POST(request: NextRequest) {
  // Clearing the cookie only affects this browser. Revoking the session id
  // server-side kills every token generation of this login, including copies.
  const session = getSessionFromRequest(request);
  if (session) {
    await revokeSession(session);
  }

  const response = NextResponse.json(
    { ok: true },
    // Clearing the session cookie must never be cached.
    { headers: securityHeadersForRequest(request, { noStore: true }) },
  );
  clearSessionCookie(response);
  return response;
}
