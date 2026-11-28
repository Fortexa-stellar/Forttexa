import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { POST as createChallenge } from "@/app/api/auth/challenge/route";
import { isLoginLocked, resetLoginLockoutStore } from "@/lib/auth/login-lockout";
import {
  createWalletChallenge,
  InvalidWalletPublicKeyError,
  resetWalletChallengeStore,
  walletChallengeStoreSize,
} from "@/lib/auth/wallet-challenge";
import { resetRateLimitStore } from "@/lib/security/rate-limit";

const VALID_PUBLIC_KEY = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";
// 56 characters in the Stellar alphabet, so it passes a shape regex, but the
// base32 payload's CRC16 checksum does not match a real account.
const BAD_CHECKSUM_KEY = `G${"A".repeat(55)}`;
const IP = "203.0.113.7";

function challengeRequest(body: unknown, ip = IP) {
  return new NextRequest("http://localhost/api/auth/challenge", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: JSON.stringify(body),
  });
}

describe("/api/auth/challenge wallet validation", () => {
  beforeEach(async () => {
    await resetWalletChallengeStore();
    await resetLoginLockoutStore();
    await resetRateLimitStore();
  });

  afterEach(async () => {
    delete process.env.FORTEXA_AUTH_MAX_ATTEMPTS;
    await resetWalletChallengeStore();
    await resetLoginLockoutStore();
    await resetRateLimitStore();
  });

  it("issues a challenge for a valid Stellar account and stores exactly one record", async () => {
    const response = await createChallenge(challengeRequest({ publicKey: VALID_PUBLIC_KEY }));

    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      challengeId: string;
      message: string;
      publicKey: string;
      expiresAt: string;
    };

    expect(payload.publicKey).toBe(VALID_PUBLIC_KEY);
    expect(payload.challengeId).toMatch(/^[0-9a-f-]{36}$/u);
    expect(payload.message).toContain(`Wallet: ${VALID_PUBLIC_KEY}`);
    expect(payload.message).toContain(`Challenge: ${payload.challengeId}`);
    expect(Number.isFinite(Date.parse(payload.expiresAt))).toBe(true);
    expect(walletChallengeStoreSize()).toBe(1);
  });

  it("validates encoding case-insensitively and stores the normalized key", async () => {
    const response = await createChallenge(
      challengeRequest({ publicKey: VALID_PUBLIC_KEY.toLowerCase() }),
    );

    expect(response.status).toBe(200);

    const payload = (await response.json()) as { publicKey: string; message: string };
    expect(payload.publicKey).toBe(VALID_PUBLIC_KEY);
    expect(payload.message).toContain(`Wallet: ${VALID_PUBLIC_KEY}`);
  });

  it.each<[string, unknown]>([
    ["a value that is too short", "GBXFXNDLV4LSWA4VB7YIL5"],
    ["characters outside the Stellar alphabet", "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP0L"],
    ["a 56-character key with a bad checksum", BAD_CHECKSUM_KEY],
    ["a non-string value", 42],
    ["a missing value", undefined],
  ])("rejects %s with a stable 400 and no stored record", async (_label, publicKey) => {
    const response = await createChallenge(challengeRequest({ publicKey }));
    const raw = await response.text();

    expect(response.status).toBe(400);
    expect(JSON.parse(raw)).toEqual({
      error: "Invalid wallet public key.",
      code: "invalid_wallet_public_key",
    });
    // The rejected value is never echoed back, whatever the body contained.
    if (typeof publicKey === "string") {
      expect(raw).not.toContain(publicKey);
    }
    expect(walletChallengeStoreSize()).toBe(0);
  });

  it("does not create challenge or lockout state for repeated malformed keys", async () => {
    process.env.FORTEXA_AUTH_MAX_ATTEMPTS = "2";

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await createChallenge(
        challengeRequest({ publicKey: BAD_CHECKSUM_KEY }),
      );
      expect(response.status).toBe(400);
    }

    expect(walletChallengeStoreSize()).toBe(0);
    expect((await isLoginLocked(BAD_CHECKSUM_KEY, IP)).locked).toBe(false);
    expect((await isLoginLocked(`wallet:${BAD_CHECKSUM_KEY}`, IP)).locked).toBe(false);

    // A valid request after the malformed burst is unaffected.
    const valid = await createChallenge(challengeRequest({ publicKey: VALID_PUBLIC_KEY }));
    expect(valid.status).toBe(200);
    expect(walletChallengeStoreSize()).toBe(1);
  });

  it("keeps the store guard in the challenge module itself", async () => {
    await expect(createWalletChallenge(BAD_CHECKSUM_KEY)).rejects.toBeInstanceOf(
      InvalidWalletPublicKeyError,
    );
    expect(walletChallengeStoreSize()).toBe(0);
  });
});
