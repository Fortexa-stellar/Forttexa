import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  clearLoginFailures,
  isLoginLocked,
  readClientIp,
  registerLoginFailure,
  resetLoginLockoutClock,
  resetLoginLockoutStore,
  setLoginLockoutClock,
} from "@/lib/auth/login-lockout";

function fakeClock(startMs: number) {
  let current = startMs;
  return {
    now: () => current,
    advance: (ms: number) => {
      current += ms;
    },
  };
}

describe("login lockout", () => {
  beforeEach(async () => {
    process.env.FORTEXA_AUTH_MAX_ATTEMPTS = "2";
    process.env.FORTEXA_AUTH_LOCK_MINUTES = "1";
    resetLoginLockoutClock();
    await resetLoginLockoutStore();
  });

  it("increments failed login attempt counters", async () => {
    const email = "operator@fortexa.local";
    const ip = "127.0.0.1";

    expect((await isLoginLocked(email, ip)).locked).toBe(false);

    const first = await registerLoginFailure(email, ip);
    const second = await registerLoginFailure(email, ip);

    expect(first.attempts).toBeGreaterThanOrEqual(1);
    expect(second.attempts).toBeGreaterThan(first.attempts);
  });

  it("clears lockout state on success", async () => {
    const email = "viewer@fortexa.local";
    const ip = "127.0.0.2";

    await registerLoginFailure(email, ip);
    await registerLoginFailure(email, ip);

    expect((await isLoginLocked(email, ip)).locked).toBe(true);

    await clearLoginFailures(email, ip);
    expect((await isLoginLocked(email, ip)).locked).toBe(false);
  });

  it("records failures against the user id across wallet addresses", async () => {
    const userId = "wallet:GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";
    const ip = "10.0.0.5";

    await registerLoginFailure(userId, ip);
    await registerLoginFailure(userId, ip);

    expect((await isLoginLocked(userId, ip)).locked).toBe(true);
  });

  it("keeps the lock in force until the configured expiry", async () => {
    const clock = fakeClock(1000);
    setLoginLockoutClock(clock.now);

    const email = "operator@fortexa.local";
    const ip = "10.0.0.6";

    await registerLoginFailure(email, ip);
    await registerLoginFailure(email, ip);

    expect((await isLoginLocked(email, ip)).locked).toBe(true);

    clock.advance(30_000);
    expect((await isLoginLocked(email, ip)).locked).toBe(true);

    clock.advance(61_000);
    expect((await isLoginLocked(email, ip)).locked).toBe(false);
  });
});

describe("login lockout client IP trust", () => {
  afterEach(() => {
    delete process.env.FORTEXA_TRUSTED_PROXY;
  });

  it("ignores spoofed Forwarded headers by default", () => {
    const headers = new Headers({
      "x-forwarded-for": "198.51.100.9",
      forwarded: "for=198.51.100.9",
      "x-real-ip": "203.0.113.40",
    });

    expect(readClientIp(headers)).toBe("203.0.113.40");
  });

  it("honors X-Forwarded-For when FORTEXA_TRUSTED_PROXY is enabled", () => {
    process.env.FORTEXA_TRUSTED_PROXY = "true";

    const headers = new Headers({
      "x-forwarded-for": "198.51.100.9, 10.0.0.1",
      "x-real-ip": "203.0.113.40",
    });

    expect(readClientIp(headers)).toBe("198.51.100.9");
  });
});
