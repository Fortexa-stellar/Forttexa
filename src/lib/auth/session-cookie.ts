import type { NextResponse } from "next/server";

import { AUTH_COOKIE_KEY, DEFAULT_SESSION_TTL_SECONDS } from "@/lib/auth/session";

type CookieEnv = Readonly<Record<string, string | undefined>>;
export type SessionCookieOptions = {
  httpOnly: true;
  sameSite: "lax" | "strict";
  secure: boolean;
  path: string;
  maxAge: number;
};

export function getSessionCookieOptions(env: CookieEnv = process.env): SessionCookieOptions {
  const production = env.NODE_ENV === "production";
  const rawSecure = env.FORTEXA_SESSION_COOKIE_SECURE?.trim().toLowerCase();
  if (rawSecure && rawSecure !== "true" && rawSecure !== "false") {
    throw new Error("FORTEXA_SESSION_COOKIE_SECURE must be true or false");
  }
  if (production && rawSecure === "false") {
    throw new Error("Production session cookies must use Secure");
  }

  const sameSite = env.FORTEXA_SESSION_COOKIE_SAMESITE?.trim().toLowerCase() || "lax";
  if (sameSite !== "lax" && sameSite !== "strict") {
    throw new Error("FORTEXA_SESSION_COOKIE_SAMESITE must be lax or strict");
  }
  return {
    httpOnly: true,
    sameSite,
    secure: production || rawSecure === "true",
    path: "/",
    maxAge: DEFAULT_SESSION_TTL_SECONDS,
  };
}

export function assertSafeSessionCookieConfig(env: CookieEnv = process.env): void {
  getSessionCookieOptions(env);
}

export function getClearSessionCookieOptions(env: CookieEnv = process.env): SessionCookieOptions {
  return { ...getSessionCookieOptions(env), maxAge: 0 };
}

export function setSessionCookie(response: NextResponse, token: string, env: CookieEnv = process.env) {
  response.cookies.set(AUTH_COOKIE_KEY, token, getSessionCookieOptions(env));
}

export function clearSessionCookie(response: NextResponse, env: CookieEnv = process.env) {
  response.cookies.set(AUTH_COOKIE_KEY, "", getClearSessionCookieOptions(env));
}
