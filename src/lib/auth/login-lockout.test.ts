import { beforeEach, describe, expect, it } from "vitest";

import {
  clearLoginFailures,
  isLoginLocked,
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

  it("derives retryAfterSeconds from the remaining lock window at boundaries", async () => {
    const clock = fakeClock(1_000_000);
    setLoginLockoutClock(clock.now);

    const email = "boundary@fortexa.local";
    const ip = "10.0.0.7";

    await registerLoginFailure(email, ip);
    await registerLoginFailure(email, ip);

    const locked = await isLoginLocked(email, ip);
    expect(locked.locked).toBe(true);
    expect(locked.retryAfterSeconds).toBe(60);

    clock.advance(30_000);
    const midWindow = await isLoginLocked(email, ip);
    expect(midWindow.locked).toBe(true);
    expect(midWindow.retryAfterSeconds).toBe(30);

    // 1ms remaining still rounds up to a 1-second Retry-After delay.
    clock.advance(29_999);
    const nearExpiry = await isLoginLocked(email, ip);
    expect(nearExpiry.locked).toBe(true);
    expect(nearExpiry.retryAfterSeconds).toBe(1);

    clock.advance(1);
    const expired = await isLoginLocked(email, ip);
    expect(expired.locked).toBe(false);
    expect(expired.retryAfterSeconds).toBe(0);
  });
});
