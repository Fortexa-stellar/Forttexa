import { NextRequest, NextResponse } from "next/server";

import { AUTH_COOKIE_KEY, verifySessionToken } from "@/lib/auth/session";
import { clearSessionCookie } from "@/lib/auth/session-cookie";
import { revokeSession } from "@/lib/auth/session-revocation";

export async function POST(request: NextRequest) {
  // Clearing the cookie only affects this browser. Revoking the session id
  // server-side kills every token generation of this login, including copies.
  const token = request.cookies.get(AUTH_COOKIE_KEY)?.value;
  const session = token ? verifySessionToken(token, { allowStaleGeneration: true }) : null;
  if (session) {
    await revokeSession(session);
  }

  const response = NextResponse.json({ ok: true });
  clearSessionCookie(response);
  return response;
}
