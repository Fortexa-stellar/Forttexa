import { afterEach, describe, expect, it } from "vitest";

import {
  SESSION_COOKIE_SAMESITE_ENV,
  SESSION_COOKIE_SECURE_ENV,
  assertSafeSessionCookieConfig,
  findUnsafeSessionCookieOverrides,
  getSessionCookieOptions,
} from "@/lib/auth/session-cookie";

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  delete process.env[SESSION_COOKIE_SECURE_ENV];
  delete process.env[SESSION_COOKIE_SAMESITE_ENV];
});

describe("session cookie attribute policy", () => {
  it("uses Secure+HttpOnly+explicit SameSite=lax in production by default", () => {
    const options = getSessionCookieOptions({ NODE_ENV: "production" });

    expect(options.httpOnly).toBe(true);
    expect(options.secure).toBe(true);
    expect(options.sameSite).toBe("lax");
    expect(options.path).toBe("/");
  });

  it("keeps Secure off for local development so HTTP localhost works", () => {
    const options = getSessionCookieOptions({ NODE_ENV: "development" });

    expect(options.httpOnly).toBe(true);
    expect(options.secure).toBe(false);
    expect(options.sameSite).toBe("lax");
  });

  it("honors an explicit SameSite override", () => {
    const options = getSessionCookieOptions({
      NODE_ENV: "production",
      [SESSION_COOKIE_SAMESITE_ENV]: "strict",
    });

    expect(options.sameSite).toBe("strict");
    expect(options.secure).toBe(true);
  });

  it("flags an unsafe production Secure=false override", () => {
    const issues = findUnsafeSessionCookieOverrides({
      NODE_ENV: "production",
      [SESSION_COOKIE_SECURE_ENV]: "false",
    });

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          setting: SESSION_COOKIE_SECURE_ENV,
          message: expect.stringContaining("Secure"),
        }),
      ])
    );
  });

  it("fails startup assert on an unsafe production override", () => {
    expect(() =>
      assertSafeSessionCookieConfig({
        NODE_ENV: "production",
        [SESSION_COOKIE_SECURE_ENV]: "false",
      })
    ).toThrow(/Unsafe session cookie configuration/);
  });

  it("allows local development without Secure", () => {
    expect(() =>
      assertSafeSessionCookieConfig({
        NODE_ENV: "development",
        [SESSION_COOKIE_SECURE_ENV]: "false",
      })
    ).not.toThrow();
  });
});
