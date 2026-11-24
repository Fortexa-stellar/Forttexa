import type { NextResponse } from "next/server";

import { AUTH_COOKIE_KEY, DEFAULT_SESSION_TTL_SECONDS } from "@/lib/auth/session";

export type SessionCookieSameSite = "lax" | "strict" | "none";

export type SessionCookieOptions = {
  httpOnly: boolean;
  sameSite: SessionCookieSameSite;
  secure: boolean;
  path: string;
  maxAge: number;
};

type CookieEnv = Readonly<Record<string, string | undefined>>;

/**
 * Optional Secure override: `true` / `false`.
 * When unset, Secure follows NODE_ENV (on in production, off for local HTTP).
 */
export const SESSION_COOKIE_SECURE_ENV = "FORTEXA_SESSION_COOKIE_SECURE";

/**
 * Optional SameSite override: `lax` | `strict` | `none`.
 * When unset, SameSite is explicitly `lax`.
 */
export const SESSION_COOKIE_SAMESITE_ENV = "FORTEXA_SESSION_COOKIE_SAMESITE";

function normalizeFlag(value: string | undefined): "true" | "false" | null {
  const trimmed = value?.trim().toLowerCase();
  if (trimmed === "true" || trimmed === "1" || trimmed === "yes") {
    return "true";
  }
  if (trimmed === "false" || trimmed === "0" || trimmed === "no") {
    return "false";
  }
  return null;
}

function resolveSecure(env: CookieEnv): boolean {
  const override = normalizeFlag(env[SESSION_COOKIE_SECURE_ENV]);
  if (override === "true") {
    return true;
  }
  if (override === "false") {
    return false;
  }
  return env.NODE_ENV === "production";
}

function resolveSameSite(env: CookieEnv): SessionCookieSameSite {
  const raw = env[SESSION_COOKIE_SAMESITE_ENV]?.trim().toLowerCase();
  if (raw === "lax" || raw === "strict" || raw === "none") {
    return raw;
  }
  // Explicit default — never leave SameSite unspecified.
  return "lax";
}

export function getSessionCookieOptions(env: CookieEnv = process.env): SessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: resolveSameSite(env),
    secure: resolveSecure(env),
    path: "/",
    maxAge: DEFAULT_SESSION_TTL_SECONDS,
  };
}

export function getClearSessionCookieOptions(env: CookieEnv = process.env): SessionCookieOptions {
  return {
    ...getSessionCookieOptions(env),
    maxAge: 0,
  };
}

export function setSessionCookie(response: NextResponse, token: string, env: CookieEnv = process.env) {
  response.cookies.set(AUTH_COOKIE_KEY, token, getSessionCookieOptions(env));
}

export function clearSessionCookie(response: NextResponse, env: CookieEnv = process.env) {
  response.cookies.set(AUTH_COOKIE_KEY, "", getClearSessionCookieOptions(env));
}

export type SessionCookieSafetyIssue = {
  setting: string;
  message: string;
  remediation: string;
};

/**
 * Production must always emit Secure + HttpOnly cookies with an explicit
 * SameSite policy. An env override that drops Secure (or pairs SameSite=None
 * with Secure=false) is rejected so misconfigured deploys fail closed.
 */
export function findUnsafeSessionCookieOverrides(
  env: CookieEnv = process.env
): SessionCookieSafetyIssue[] {
  if (env.NODE_ENV !== "production") {
    return [];
  }

  const issues: SessionCookieSafetyIssue[] = [];
  const options = getSessionCookieOptions(env);

  if (!options.httpOnly) {
    issues.push({
      setting: "session cookie HttpOnly",
      message: "Production session cookies must be HttpOnly.",
      remediation: "Do not disable HttpOnly on fortexa_session cookies.",
    });
  }

  if (!options.secure) {
    issues.push({
      setting: SESSION_COOKIE_SECURE_ENV,
      message: "Production session cookies must set the Secure attribute.",
      remediation: `Unset ${SESSION_COOKIE_SECURE_ENV} or set it to true. Local HTTP may omit Secure only when NODE_ENV is not production.`,
    });
  }

  if (!options.sameSite) {
    issues.push({
      setting: SESSION_COOKIE_SAMESITE_ENV,
      message: "Production session cookies must declare an explicit SameSite policy.",
      remediation: `Set ${SESSION_COOKIE_SAMESITE_ENV} to lax, strict, or none (defaults to lax).`,
    });
  }

  if (options.sameSite === "none" && !options.secure) {
    issues.push({
      setting: `${SESSION_COOKIE_SAMESITE_ENV}, ${SESSION_COOKIE_SECURE_ENV}`,
      message: "SameSite=None requires the Secure attribute.",
      remediation: `Use SameSite=lax/strict, or set ${SESSION_COOKIE_SECURE_ENV}=true with HTTPS.`,
    });
  }

  return issues;
}

export function assertSafeSessionCookieConfig(env: CookieEnv = process.env): void {
  const issues = findUnsafeSessionCookieOverrides(env);
  if (issues.length === 0) {
    return;
  }

  const detail = issues.map((issue) => `${issue.setting}: ${issue.message}`).join(" ");
  throw new Error(`Unsafe session cookie configuration for production. ${detail}`);
}
