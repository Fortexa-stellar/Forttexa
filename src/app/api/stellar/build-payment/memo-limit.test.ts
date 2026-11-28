import { Keypair } from "@stellar/stellar-sdk";
import { beforeAll, describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  const tmpDir = `/tmp/fortexa-build-payment-memo-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  process.env.FORTEXA_STORE_DIR = tmpDir;
  process.env.FORTEXA_AUTH_SECRET = "build-payment-memo-test-secret";
  process.env.STELLAR_HORIZON_URL = "https://horizon-mock.test";
  delete process.env.DATABASE_URL;
});

import { NextRequest } from "next/server";

import { POST as buildPaymentPost } from "@/app/api/stellar/build-payment/route";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import { MEMO_TOO_LONG_CODE } from "@/lib/stellar/memo";
import { upsertUserWallet } from "@/lib/storage/user-wallet-store";

// The memo byte limit through the normal route: the request goes through the
// real handler, auth, wallet lookup and schema, and must come back as the same
// stable field error whatever the memo is made of.

const USER_ID = "build-payment-memo-signer";
const sourceKeypair = Keypair.random();
const destinationKeypair = Keypair.random();

function signerCookie() {
  const token = createSessionToken({
    email: "memo-signer@fortexa.local",
    role: "signer",
    userId: USER_ID,
    expiresInSeconds: 300,
  });
  return `${AUTH_COOKIE_KEY}=${token}`;
}

function buildRequest(memo: string) {
  return new NextRequest("http://localhost/api/stellar/build-payment", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: signerCookie() },
    body: JSON.stringify({
      auditEntryId: "",
      destination: destinationKeypair.publicKey(),
      amountXLM: "1.0000000",
      asset: "native",
      memo,
      network: "testnet",
    }),
  });
}

beforeAll(async () => {
  await upsertUserWallet(USER_ID, {
    publicKey: sourceKeypair.publicKey(),
    source: "external",
    provider: "freighter",
  });
});

describe("POST /api/stellar/build-payment memo byte limit", () => {
  it.each([
    ["29 ASCII bytes", "a".repeat(29)],
    ["15 two-byte characters (15 long, 30 bytes)", "é".repeat(15)],
    ["10 three-byte characters (10 long, 30 bytes)", "€".repeat(10)],
    ["8 emoji (8 code points, 32 bytes)", "😀".repeat(8)],
  ])("rejects %s with the stable memo_too_long field error", async (_label, memo) => {
    const response = await buildPaymentPost(buildRequest(memo));
    const body = (await response.json()) as {
      error: string;
      details: { fieldErrors: Record<string, string[]> };
    };

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid payment build request.");
    expect(body.details.fieldErrors.memo).toEqual([MEMO_TOO_LONG_CODE]);
    // The memo text itself is never echoed back.
    expect(JSON.stringify(body)).not.toContain(memo);
  });

  it("does not report a memo error for a memo of exactly 28 bytes", async () => {
    const response = await buildPaymentPost(buildRequest("a".repeat(28)));
    const body = (await response.json()) as { details?: { fieldErrors?: Record<string, string[]> } };

    expect(body.details?.fieldErrors?.memo).toBeUndefined();
  });
});
