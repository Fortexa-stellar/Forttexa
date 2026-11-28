import { rmSync } from "node:fs";

import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

const storeDir = vi.hoisted(() => {
  const base = process.env.TEMP ?? process.env.TMPDIR ?? "/tmp";
  const dir = `${base}/fortexa-console-contract-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  process.env.FORTEXA_STORE_DIR = dir;
  process.env.FORTEXA_AUTH_SECRET = "console-contract-test-secret-0123456789";
  process.env.STELLAR_HORIZON_URL = "https://horizon-testnet.stellar.org";
  delete process.env.DATABASE_URL;
  return dir;
});

const horizonMocks = vi.hoisted(() => ({
  loadAccount: vi.fn(),
  fetchBaseFee: vi.fn(),
  submitTransaction: vi.fn(),
}));

const storeMocks = vi.hoisted(() => ({
  getAuditEntryById: vi.fn(),
  getUserWallet: vi.fn(),
}));

vi.mock("@stellar/stellar-sdk", async () => {
  const actual = await vi.importActual<typeof import("@stellar/stellar-sdk")>(
    "@stellar/stellar-sdk",
  );

  class MockServer {
    loadAccount(accountId: string) {
      return horizonMocks.loadAccount(accountId);
    }
    fetchBaseFee() {
      return horizonMocks.fetchBaseFee();
    }
    submitTransaction(tx: unknown) {
      return horizonMocks.submitTransaction(tx);
    }
  }

  return { ...actual, Horizon: { ...actual.Horizon, Server: MockServer } };
});

vi.mock("@/lib/storage/audit-store", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/storage/audit-store")>()),
  getAuditEntryById: storeMocks.getAuditEntryById,
}));

vi.mock("@/lib/storage/user-wallet-store", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/storage/user-wallet-store")>()),
  getUserWallet: storeMocks.getUserWallet,
}));

import { Account, Keypair, Networks, TransactionBuilder } from "@stellar/stellar-sdk";
import { NextRequest } from "next/server";

import { POST as buildPaymentPost } from "@/app/api/stellar/build-payment/route";
import { POST as submitSignedPost } from "@/app/api/stellar/submit-signed/route";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import { resetRateLimitStore } from "@/lib/security/rate-limit";
import { resetSubmitIdempotencyState } from "@/lib/storage/submit-idempotency-store";

import { makeAuthorizedSubmission } from "./submit-signed/test-fixtures";

const USER_ID = "console-contract-user";
const wallet = Keypair.random();
const txHash = "e".repeat(64);

function signerCookie() {
  const token = createSessionToken({
    email: "console-contract@fortexa.local",
    role: "signer",
    userId: USER_ID,
    publicKey: wallet.publicKey(),
    expiresInSeconds: 300,
  });
  return `${AUTH_COOKIE_KEY}=${token}`;
}

function post(url: string, body: unknown) {
  return new NextRequest(`http://localhost${url}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: signerCookie() },
    body: JSON.stringify(body),
  });
}

beforeEach(async () => {
  vi.clearAllMocks();
  await resetRateLimitStore();
  await resetSubmitIdempotencyState(USER_ID);
  horizonMocks.loadAccount.mockImplementation(async (id: string) => new Account(id, "100"));
  horizonMocks.fetchBaseFee.mockResolvedValue(100);
  horizonMocks.submitTransaction.mockResolvedValue({
    hash: txHash,
    ledger: 7,
    successful: true,
    result_xdr: "AAAAAAAAAGQAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAA=",
  });
  storeMocks.getUserWallet.mockResolvedValue({
    userId: USER_ID,
    publicKey: wallet.publicKey(),
    source: "external",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
});

afterAll(() => {
  rmSync(storeDir, { recursive: true, force: true });
});

describe("console contract: build-payment then submit-signed", () => {
  it("submits what the console builds, sends and signs, with no decisionReceipt", async () => {
    const { auditEntry, quote } = makeAuthorizedSubmission({
      userId: USER_ID,
      signer: wallet,
      amount: "5.0000000",
    });
    storeMocks.getAuditEntryById.mockImplementation(async (userId: string, id: string) =>
      userId === USER_ID && id === auditEntry.id ? auditEntry : undefined,
    );

    // 1. Build: the console asks for an unsigned transaction.
    const built = await buildPaymentPost(
      post("/api/stellar/build-payment", {
        auditEntryId: auditEntry.id,
        destination: quote.destination,
        amountXLM: quote.amountXLM,
        asset: quote.asset,
        memo: quote.memo,
        network: quote.network,
      }),
    );
    const buildPayload = await built.json();

    expect(built.status).toBe(200);
    // Every field the console checks before it will sign (decision-console.tsx).
    expect(buildPayload).toMatchObject({
      decisionId: auditEntry.id,
      quoteExpiresAt: quote.expiresAt,
    });
    expect(typeof buildPayload.buildAuthorization).toBe("string");
    expect(buildPayload.buildAuthorization.length).toBeGreaterThan(0);

    // 2. Sign the unsigned XDR with the linked wallet.
    const transaction = TransactionBuilder.fromXDR(buildPayload.xdr, Networks.TESTNET);
    transaction.sign(wallet);

    // 3. Submit exactly the four fields the console sends.
    const submitted = await submitSignedPost(
      post("/api/stellar/submit-signed", {
        signedXdr: transaction.toXDR(),
        decisionId: buildPayload.decisionId,
        quoteExpiresAt: buildPayload.quoteExpiresAt,
        buildAuthorization: buildPayload.buildAuthorization,
      }),
    );
    const result = await submitted.json();

    expect(submitted.status).toBe(200);
    expect(result).toMatchObject({ ok: true, transactionHash: txHash });
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("refuses to submit a different transaction under the build authorization it was issued for", async () => {
    const { auditEntry, quote } = makeAuthorizedSubmission({ userId: USER_ID, signer: wallet });
    storeMocks.getAuditEntryById.mockResolvedValue(auditEntry);

    const built = await buildPaymentPost(
      post("/api/stellar/build-payment", {
        auditEntryId: auditEntry.id,
        destination: quote.destination,
        amountXLM: quote.amountXLM,
        asset: quote.asset,
        memo: quote.memo,
        network: quote.network,
      }),
    );
    const buildPayload = await built.json();

    // Same decision, but the wallet signs a transaction paying someone else.
    const swapped = makeAuthorizedSubmission({
      userId: USER_ID,
      signer: wallet,
      decisionId: auditEntry.id,
      destination: quote.destination,
      transactionDestination: Keypair.random().publicKey(),
    });

    const submitted = await submitSignedPost(
      post("/api/stellar/submit-signed", {
        signedXdr: swapped.signedXdr,
        decisionId: buildPayload.decisionId,
        quoteExpiresAt: buildPayload.quoteExpiresAt,
        buildAuthorization: buildPayload.buildAuthorization,
      }),
    );

    expect(submitted.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });
});
