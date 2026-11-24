import { Keypair } from "@stellar/stellar-sdk";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { AUTH_COOKIE_KEY, createSessionToken, verifySessionToken } from "@/lib/auth/session";
import {
  getClearSessionCookieOptions,
  getSessionCookieOptions,
} from "@/lib/auth/session-cookie";
import { resetLoginLockoutStore } from "@/lib/auth/login-lockout";
import { isSessionRevoked, resetSessionRevocationStore, revokeSession } from "@/lib/auth/session-revocation";
import { resetSessionStore } from "@/lib/auth/session-store";
import { hashSep53Message, resetWalletChallengeStore } from "@/lib/auth/wallet-challenge";
import { POST as createChallenge } from "@/app/api/auth/challenge/route";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { POST as refresh } from "@/app/api/auth/refresh/route";
import { proxy } from "@/proxy";
import { upsertUserWallet } from "@/lib/storage/user-wallet-store";

const AUTHORIZED_SECRET = "SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW";
const AUTHORIZED_PUBLIC_KEY = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";

const COOKIE_USER_ID = `wallet:${AUTHORIZED_PUBLIC_KEY}`;

function issueToken(overrides?: { userId?: string; expiresInSeconds?: number; publicKey?: string }) {
  return createSessionToken({
    email: "test@example.com",
    role: "operator",
    userId: COOKIE_USER_ID,
    publicKey: AUTHORIZED_PUBLIC_KEY,
    expiresInSeconds: 120,
    ...overrides,
  });
}

function cookieHeader(token: string) {
  return `${AUTH_COOKIE_KEY}=${token}`;
}

function refreshRequest(token: string) {
  return new NextRequest("http://localhost/api/auth/refresh", {
    method: "POST",
    headers: { cookie: cookieHeader(token) },
  });
}

function logoutRequest(token: string) {
  return new NextRequest("http://localhost/api/auth/logout", {
    method: "POST",
    headers: { cookie: cookieHeader(token) },
  });
}

function dashboardRequest(token: string) {
  return new NextRequest("http://localhost/dashboard", {
    headers: { cookie: cookieHeader(token) },
  });
}

function signSep53Message(secret: string, message: string) {
  const keypair = Keypair.fromSecret(secret);
  return keypair.sign(hashSep53Message(message)).toString("base64");
}

async function issueChallenge(publicKey: string) {
  const request = new NextRequest("http://localhost/api/auth/challenge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKey }),
  });

  const response = await createChallenge(request);
  expect(response.status).toBe(200);

  return (await response.json()) as {
    challengeId: string;
    message: string;
  };
}

function expectSecureCookieAttributes(
  cookie: { httpOnly?: boolean; sameSite?: string; secure?: boolean; path?: string; maxAge?: number } | undefined,
  options: ReturnType<typeof getSessionCookieOptions> | ReturnType<typeof getClearSessionCookieOptions>
) {
  expect(cookie).toBeDefined();
  expect(cookie?.httpOnly).toBe(options.httpOnly);
  expect(cookie?.sameSite).toBe(options.sameSite);
  expect(cookie?.secure).toBe(options.secure);
  expect(cookie?.path).toBe(options.path);
  expect(cookie?.maxAge).toBe(options.maxAge);
}

async function rotateToken(token: string) {
  const response = await refresh(refreshRequest(token));
  expect(response.status).toBe(200);
  const rotated = response.cookies.get(AUTH_COOKIE_KEY)?.value;
  expect(rotated).toBeTruthy();
  expect(rotated).not.toBe(token);
  return rotated as string;
}

describe("Session & Cookie Security Regression Tests", () => {
  beforeEach(async () => {
    process.env.FORTEXA_AUTH_SECRET = "test-secret-key-123";
    process.env.FORTEXA_OPERATOR_WALLETS = AUTHORIZED_PUBLIC_KEY;
    delete process.env.FORTEXA_SESSION_COOKIE_SECURE;
    delete process.env.FORTEXA_SESSION_COOKIE_SAMESITE;
    resetSessionStore();
    await resetSessionRevocationStore();
    await resetWalletChallengeStore();
    await resetLoginLockoutStore();
    await upsertUserWallet(COOKIE_USER_ID, {
      publicKey: AUTHORIZED_PUBLIC_KEY,
      source: "external",
    });
  });

  afterEach(async () => {
    delete process.env.FORTEXA_OPERATOR_WALLETS;
    delete process.env.FORTEXA_SESSION_COOKIE_SECURE;
    delete process.env.FORTEXA_SESSION_COOKIE_SAMESITE;
    await resetSessionRevocationStore();
    await resetWalletChallengeStore();
    await resetLoginLockoutStore();
  });

  describe("Cookie Security Flags", () => {
    it("issues Secure+HttpOnly+SameSite attributes on login", async () => {
      const previousNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      try {
        const challenge = await issueChallenge(AUTHORIZED_PUBLIC_KEY);
        const signature = signSep53Message(AUTHORIZED_SECRET, challenge.message);
        const response = await login(
          new NextRequest("http://localhost/api/auth/login", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              publicKey: AUTHORIZED_PUBLIC_KEY,
              challengeId: challenge.challengeId,
              signature,
            }),
          })
        );

        expect(response.status).toBe(200);
        expectSecureCookieAttributes(
          response.cookies.get(AUTH_COOKIE_KEY),
          getSessionCookieOptions({ NODE_ENV: "production" })
        );
      } finally {
        process.env.NODE_ENV = previousNodeEnv;
      }
    });

    it("should use secure cookies in production environment on refresh", async () => {
      const previousNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      try {
        const response = await refresh(refreshRequest(issueToken()));
        expect(response.status).toBe(200);
        expectSecureCookieAttributes(
          response.cookies.get(AUTH_COOKIE_KEY),
          getSessionCookieOptions({ NODE_ENV: "production" })
        );
      } finally {
        process.env.NODE_ENV = previousNodeEnv;
      }
    });

    it("should keep the secure flag tied to the environment", () => {
      const options = getSessionCookieOptions();

      expect(options.secure).toBe(process.env.NODE_ENV === "production");
      expect(options.httpOnly).toBe(true);
      expect(options.sameSite).toBe("lax");
      expect(options.path).toBe("/");
      expect(options.maxAge).toBe(604800);
    });
  });

  describe("Refresh Rotation", () => {
    it("should issue a new cookie that keeps the same session id", async () => {
      const original = issueToken();
      const originalSession = verifySessionToken(original);
      const rotated = await rotateToken(original);
      const rotatedSession = verifySessionToken(rotated);

      expect(originalSession).not.toBeNull();
      expect(rotatedSession).not.toBeNull();
      expect(rotatedSession?.sid).toBe(originalSession?.sid);

      const previousNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";
      try {
        const response = await refresh(refreshRequest(rotated));
        expect(response.status).toBe(200);
        expectSecureCookieAttributes(
          response.cookies.get(AUTH_COOKIE_KEY),
          getSessionCookieOptions({ NODE_ENV: "production" })
        );
      } finally {
        process.env.NODE_ENV = previousNodeEnv;
      }
    });

    it("should keep a refreshed cookie usable in the proxy", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);

      const current = proxy(dashboardRequest(rotated));
      expect(current.headers.get("location")).toBeNull();

      const previous = proxy(dashboardRequest(original));
      expect(previous.headers.get("location")).toBeNull();
    });
  });

  describe("Logout Behavior", () => {
    it("should clear the fortexa_session cookie upon logout with secure attributes", async () => {
      const previousNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      try {
        const response = await logout(logoutRequest(issueToken()));
        expect(response.status).toBe(200);

        const cookie = response.cookies.get(AUTH_COOKIE_KEY);
        const options = getClearSessionCookieOptions({ NODE_ENV: "production" });

        expect(cookie?.value).toBe("");
        expectSecureCookieAttributes(cookie, options);
        expect(options.maxAge).toBe(0);
      } finally {
        process.env.NODE_ENV = previousNodeEnv;
      }
    });

    it("should invalidate the newest cookie on logout", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);
      const rotatedSession = verifySessionToken(rotated);
      expect(rotatedSession).not.toBeNull();

      const response = await logout(logoutRequest(rotated));
      expect(response.status).toBe(200);

      // Signature still verifies; the revocation store is what blocks reuse.
      expect(verifySessionToken(rotated)).not.toBeNull();
      expect(await isSessionRevoked(rotatedSession!.sid)).toBe(true);

      const replay = await refresh(refreshRequest(rotated));
      expect(replay.status).toBe(401);
    });
  });

  describe("Session Revocation", () => {
    it("should block refresh after the shared session id is revoked", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);
      const session = verifySessionToken(rotated);
      expect(session).not.toBeNull();

      await revokeSession(session!);

      expect(await isSessionRevoked(session!.sid)).toBe(true);
      expect((await refresh(refreshRequest(original))).status).toBe(401);
      expect((await refresh(refreshRequest(rotated))).status).toBe(401);
    });
  });

  describe("Token Hardening", () => {
    it("should safely reject an expired session token", () => {
      const expiredToken = createSessionToken({
        email: "test@example.com",
        role: "viewer",
        userId: "user-1",
        expiresInSeconds: -3600,
      });

      const session = verifySessionToken(expiredToken);
      expect(session).toBeNull();
    });

    it("should safely reject a tampered session token signature", () => {
      const validToken = createSessionToken({
        email: "test@example.com",
        role: "operator",
        userId: "user-2",
      });

      const parts = validToken.split(".");
      const tamperedToken = `${parts[0]}.invalid_signature_here`;

      const session = verifySessionToken(tamperedToken);
      expect(session).toBeNull();
    });

    it("should safely reject malformed session tokens", () => {
      expect(verifySessionToken("not.a.real.token")).toBeNull();
      expect(verifySessionToken("just_one_part")).toBeNull();
      expect(verifySessionToken("")).toBeNull();
    });
  });
});
