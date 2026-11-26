import { NextRequest, NextResponse } from "next/server";

import { AUTH_COOKIE_KEY, getSessionFromRequest } from "@/lib/auth/session";
import { revokeSession } from "@/lib/auth/session-revocation";
import { revokeCurrentSessionGeneration } from "@/lib/auth/session-store";
import { securityHeadersForRequest } from "@/lib/security/headers";

export async function POST(request: NextRequest) {
  // Clearing the cookie only affects this browser. Revoking the session id
  // server-side kills every token generation of this login, including copies.
  // A stale generation from an old tab must still be able to log this session
  // out, so verify without the generation check; only the current generation
  // also retires the generation record itself.
  const session = getSessionFromRequest(request, { allowStaleGeneration: true });
  if (session) {
    await revokeSession(session);
    revokeCurrentSessionGeneration({
      userId: session.userId,
      sessionId: session.sid,
      generation: session.gen,
    });
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(AUTH_COOKIE_KEY, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });
  return response;
}
