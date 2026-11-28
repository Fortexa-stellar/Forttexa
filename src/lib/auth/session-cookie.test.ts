import { NextResponse } from "next/server";
import { describe, expect, it } from "vitest";

import {
  assertSafeSessionCookieConfig,
  clearSessionCookie,
  getSessionCookieOptions,
  setSessionCookie,
} from "./session-cookie";

describe("session cookie protections", () => {
  it("requires Secure and HttpOnly with an explicit SameSite policy in production", () => {
    const env = { NODE_ENV: "production", FORTEXA_SESSION_COOKIE_SAMESITE: "strict" };
    const response = NextResponse.json({});
    setSessionCookie(response, "fixture", env);
    expect(response.headers.get("set-cookie")).toMatch(/HttpOnly/);
    expect(response.headers.get("set-cookie")).toMatch(/Secure/);
    expect(response.headers.get("set-cookie")).toMatch(/SameSite=strict/);

    clearSessionCookie(response, env);
    expect(response.headers.get("set-cookie")).toMatch(/Max-Age=0/);
    expect(response.headers.get("set-cookie")).toMatch(/HttpOnly/);
    expect(response.headers.get("set-cookie")).toMatch(/Secure/);
    expect(response.headers.get("set-cookie")).toMatch(/SameSite=strict/);
  });

  it("supports local HTTP and rejects unsafe production overrides", () => {
    expect(getSessionCookieOptions({ NODE_ENV: "development" }))
      .toMatchObject({ secure: false, httpOnly: true, sameSite: "lax" });
    expect(() => assertSafeSessionCookieConfig({
      NODE_ENV: "production",
      FORTEXA_SESSION_COOKIE_SECURE: "false",
    })).toThrow("Production session cookies must use Secure");
    expect(() => assertSafeSessionCookieConfig({
      NODE_ENV: "production",
      FORTEXA_SESSION_COOKIE_SAMESITE: "none",
    })).toThrow("FORTEXA_SESSION_COOKIE_SAMESITE");
  });
});
