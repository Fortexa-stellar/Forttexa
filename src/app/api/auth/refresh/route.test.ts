import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { POST } from "@/app/api/auth/refresh/route";
import {
  registerLoginFailure,
  resetLoginLockoutClock,
  resetLoginLockoutStore,
  setLoginLockoutClock,
} from "@/lib/auth/login-lockout";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import { buildSecurityHeaders } from "@/lib/security/headers";
import { upsertUserWallet } from "@/lib/storage/user-wallet-store";

const WALLET = "GCDEFAULTTESTWALLET123";
const CLIENT_IP = "203.0.113.10";

function operatorCookie() {
  process.env.FORTEXA_AUTH_SECRET = "integration-test-secret";
  const token = createSessionToken({
    email: "operator@fortexa.local",
    role: "operator",
    userId: "refresh-operator",
    publicKey: WALLET,
    expiresInSeconds: 120,
  });

  return `${AUTH_COOKIE_KEY}=${token}`;
}

function refreshRequest(cookie?: string) {
  return new NextRequest("http://localhost/api/auth/refresh", {
    method: "POST",
    headers: {
      ...(cookie ? { cookie } : {}),
      "x-real-ip": CLIENT_IP,
    },
  });
}

describe("/api/auth/refresh route", () => {
  beforeEach(async () => {
    process.env.FORTEXA_AUTH_SECRET = "integration-test-secret";
    process.env.FORTEXA_AUTH_MAX_ATTEMPTS = "1";
    process.env.FORTEXA_AUTH_LOCK_MINUTES = "1";
    delete process.env.REDIS_URL;
    delete process.env.FORTEXA_SHARED_STATE_PATH;
    resetLoginLockoutClock();
    await resetLoginLockoutStore();
  });

  afterEach(async () => {
    resetLoginLockoutClock();
    await resetLoginLockoutStore();
    delete process.env.FORTEXA_AUTH_MAX_ATTEMPTS;
    delete process.env.FORTEXA_AUTH_LOCK_MINUTES;
  });

  it("returns 401 when unauthenticated", async () => {
    const response = await POST(refreshRequest());

    expect(response.status).toBe(401);
    for (const [key, value] of Object.entries(buildSecurityHeaders())) {
      expect(response.headers.get(key)).toBe(value);
    }
  });

  it("returns 200 and rotates for authenticated user", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: WALLET, source: "external" });
    const response = await POST(refreshRequest(operatorCookie()));

    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      user: { userId: string; role: string };
    };

    expect(payload.ok).toBe(true);
    expect(payload.user.userId).toBe("refresh-operator");
    expect(payload.user.role).toBe("operator");

    for (const [key, value] of Object.entries(buildSecurityHeaders())) {
      expect(response.headers.get(key)).toBe(value);
    }
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("does not issue a session while the account is locked out", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: WALLET, source: "external" });
    const start = Date.parse("2024-01-01T00:00:00.000Z");
    setLoginLockoutClock(() => start);
    await registerLoginFailure(WALLET, CLIENT_IP);

    const response = await POST(refreshRequest(operatorCookie()));
    expect(response.status).toBe(401);

    const payload = (await response.json()) as { error?: string };
    expect(payload.error).toMatch(/locked/i);
    expect(response.headers.get("set-cookie") ?? "").not.toContain(AUTH_COOKIE_KEY);
  });

  it("issues a session again after the lock expires", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: WALLET, source: "external" });
    const start = Date.parse("2024-01-01T00:00:00.000Z");
    setLoginLockoutClock(() => start);
    await registerLoginFailure(WALLET, CLIENT_IP);
    setLoginLockoutClock(() => start + 61_000);

    const response = await POST(refreshRequest(operatorCookie()));
    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      user: { userId: string };
    };

    expect(payload.ok).toBe(true);
    expect(payload.user.userId).toBe("refresh-operator");
  });
});
