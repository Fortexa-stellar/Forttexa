import { rmSync } from "node:fs";

import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

const storeDir = vi.hoisted(() => {
  const base = process.env.TEMP ?? process.env.TMPDIR ?? "/tmp";
  const dir = `${base}/fortexa-submit-signed-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  process.env.FORTEXA_STORE_DIR = dir;
  process.env.FORTEXA_AUTH_SECRET = "submit-signed-route-test-secret-0123456789";
  process.env.STELLAR_HORIZON_URL = "https://horizon-testnet.stellar.org";
  delete process.env.DATABASE_URL;
  return dir;
});

const horizonMocks = vi.hoisted(() => ({
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

import { Keypair } from "@stellar/stellar-sdk";
import { NextRequest } from "next/server";

import { POST } from "@/app/api/stellar/submit-signed/route";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import { getStellarSubmitResultCounts, resetMetrics } from "@/lib/observability/metrics";
import { resetRateLimitStore } from "@/lib/security/rate-limit";
import { resetSubmitIdempotencyState } from "@/lib/storage/submit-idempotency-store";

import {
  makeAuthorizedSubmission,
  type AuthorizedSubmission,
  type AuthorizedSubmissionOptions,
} from "./test-fixtures";

const USER_ID = "submit-signed-route-user";
const txHash = "c".repeat(64);
const wallet = Keypair.random();

function sessionCookie(publicKey = wallet.publicKey(), role: "signer" | "operator" = "signer") {
  const token = createSessionToken({
    email: "submit-signed@fortexa.local",
    role,
    userId: USER_ID,
    publicKey,
    expiresInSeconds: 300,
  });
  return `${AUTH_COOKIE_KEY}=${token}`;
}

function submit(
  body: unknown,
  headers: Record<string, string> = {},
  rawBody?: string,
) {
  return new NextRequest("http://localhost/api/stellar/submit-signed", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: sessionCookie(), ...headers },
    body: rawBody ?? JSON.stringify(body),
  });
}

function authorized(
  overrides: Partial<Omit<AuthorizedSubmissionOptions, "userId" | "signer">> = {},
): AuthorizedSubmission {
  return makeAuthorizedSubmission({ userId: USER_ID, signer: wallet, ...overrides });
}

/** Serves `submission` as the decision the server stored for this user. */
function storeDecision(submission: AuthorizedSubmission) {
  storeMocks.getAuditEntryById.mockImplementation(async (userId: string, id: string) =>
    userId === USER_ID && id === submission.auditEntry.id ? submission.auditEntry : undefined,
  );
}

beforeEach(async () => {
  vi.clearAllMocks();
  resetMetrics();
  await resetRateLimitStore();
  await resetSubmitIdempotencyState(USER_ID);
  horizonMocks.submitTransaction.mockResolvedValue({
    hash: txHash,
    ledger: 42,
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

describe("POST /api/stellar/submit-signed - console request contract", () => {
  it("accepts exactly what the console sends, with no decisionReceipt, and submits once", async () => {
    const submission = authorized();
    storeDecision(submission);

    // The console's body: signedXdr + the three build-response fields only.
    expect(Object.keys(submission.body).sort()).toEqual(
      ["buildAuthorization", "decisionId", "quoteExpiresAt", "signedXdr"].sort(),
    );

    const response = await POST(submit(submission.body));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      ok: true,
      userId: USER_ID,
      transactionHash: txHash,
      payment: { mode: "real", hash: txHash },
    });
    expect(body.explorerUrl).toContain(txHash);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
    expect(getStellarSubmitResultCounts().get("success")).toBe(1);
  });

  it("still accepts the build response's decisionReceipt echoed back unchanged", async () => {
    const submission = authorized();
    storeDecision(submission);

    // `build-payment` returns the stored quote as `decisionReceipt`, including
    // `expiresAt` and (for decisions made through /api/decision) `amountStroops`.
    const decisionReceipt = { ...submission.quote, amountStroops: "10000000" };
    const response = await POST(submit({ ...submission.body, decisionReceipt }));

    expect(response.status).toBe(200);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("rejects a decisionReceipt that disagrees with the quote the server stored", async () => {
    const submission = authorized();
    storeDecision(submission);

    const forged = {
      ...submission.quote,
      destination: Keypair.random().publicKey(),
      receiptHash: undefined,
    };
    const response = await POST(submit({ ...submission.body, decisionReceipt: forged }));
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body.field).toBe("destination");
    expect(body.error).toMatch(/does not match the authorized payment decision/i);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a decisionReceipt whose hash was tampered with", async () => {
    const submission = authorized();
    storeDecision(submission);

    const tampered = { ...submission.quote, receiptHash: "f".repeat(64) };
    const response = await POST(submit({ ...submission.body, decisionReceipt: tampered }));

    expect(response.status).toBe(403);
    expect((await response.json()).error).toMatch(/corrupted or tampered/i);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a body that omits the build-response fields", async () => {
    const submission = authorized();
    storeDecision(submission);

    for (const missing of ["decisionId", "quoteExpiresAt", "buildAuthorization"] as const) {
      const { [missing]: _omitted, ...rest } = submission.body;
      void _omitted;
      const response = await POST(submit(rest));
      const body = await response.json();

      expect(response.status, missing).toBe(400);
      expect(body.details?.fieldErrors ?? body.details, missing).toBeTruthy();
    }
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects an unknown field with the stable code and never submits", async () => {
    const submission = authorized();
    storeDecision(submission);

    const response = await POST(submit({ ...submission.body, destinaton: "typo" }));
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body).toMatchObject({
      code: "UNKNOWN_FIELDS",
      unknownFields: ["destinaton"],
    });
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a non-JSON content type with 415 before reading anything", async () => {
    const submission = authorized();
    const response = await POST(
      submit(submission.body, { "content-type": "text/plain" }),
    );

    expect(response.status).toBe(415);
    expect(await response.json()).toMatchObject({ code: "UNSUPPORTED_MEDIA_TYPE" });
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });
});

describe("POST /api/stellar/submit-signed - server-side validation of the approved decision", () => {
  it("rejects a transaction whose amount differs from the approved quote", async () => {
    const submission = authorized({ amount: "1.0000000", transactionAmount: "999.0000000" });
    storeDecision(submission);

    const response = await POST(submit(submission.body));
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body.field).toBe("amountStroops");
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a transaction whose destination differs from the approved quote", async () => {
    const submission = authorized({ transactionDestination: Keypair.random().publicKey() });
    storeDecision(submission);

    const response = await POST(submit(submission.body));

    expect(response.status).toBe(403);
    expect((await response.json()).field).toBe("destination");
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a build authorization issued for a different transaction", async () => {
    const approved = authorized();
    const other = authorized({ decisionId: approved.auditEntry.id });
    storeDecision(approved);

    const response = await POST(
      submit({ ...approved.body, buildAuthorization: other.body.buildAuthorization }),
    );

    expect(response.status).toBe(403);
    expect((await response.json()).error).toMatch(/does not match the authorized payment build/i);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects an expired quote", async () => {
    const submission = authorized({ expiresInMs: -1_000 });
    storeDecision(submission);

    const response = await POST(submit(submission.body));

    expect(response.status).toBe(403);
    expect((await response.json()).error).toMatch(/no longer valid/i);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a decision that does not authorize execution", async () => {
    const submission = authorized({ decision: "BLOCK" });
    storeDecision(submission);

    const response = await POST(submit(submission.body));

    expect(response.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a decision id the server never issued for this user", async () => {
    const submission = authorized();
    storeMocks.getAuditEntryById.mockResolvedValue(undefined);

    const response = await POST(submit(submission.body));

    expect(response.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a quote expiry that differs from the one the server stored", async () => {
    const submission = authorized();
    storeDecision(submission);

    const response = await POST(
      submit({
        ...submission.body,
        quoteExpiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      }),
    );

    expect(response.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });
});

describe("POST /api/stellar/submit-signed - wallet and session checks", () => {
  it("rejects a transaction whose source account is not the session wallet", async () => {
    const submission = authorized();
    storeDecision(submission);
    storeMocks.getUserWallet.mockResolvedValue({
      userId: USER_ID,
      publicKey: Keypair.random().publicKey(),
      source: "external",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    const response = await POST(submit(submission.body));

    expect(response.status).toBe(403);
    expect((await response.json()).error).toMatch(/source account does not match/i);
    expect(getStellarSubmitResultCounts().get("source_wallet_mismatch")).toBe(1);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a transaction signed by someone other than the session wallet", async () => {
    // Same source account, but the session belongs to a different key.
    const submission = authorized();
    storeDecision(submission);

    const response = await POST(
      new NextRequest("http://localhost/api/stellar/submit-signed", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: sessionCookie(Keypair.random().publicKey()),
        },
        body: JSON.stringify(submission.body),
      }),
    );

    expect(response.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects malformed XDR with a 400", async () => {
    const submission = authorized();
    storeDecision(submission);

    const response = await POST(
      submit({ ...submission.body, signedXdr: "not-valid-xdr-but-long-enough" }),
    );

    expect(response.status).toBe(400);
    expect((await response.json()).error).toMatch(/could not be decoded/i);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("returns 401 when there is no session wallet mapping", async () => {
    const submission = authorized();
    storeDecision(submission);
    storeMocks.getUserWallet.mockResolvedValue(null);

    const response = await POST(submit(submission.body));

    expect(response.status).toBe(401);
    expect((await response.json()).error).toMatch(/no session wallet mapping/i);
  });

  it("returns 401 when unauthenticated", async () => {
    const submission = authorized();
    const response = await POST(
      new NextRequest("http://localhost/api/stellar/submit-signed", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(submission.body),
      }),
    );

    expect(response.status).toBe(401);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("returns 403 for an operator session (signer-only route)", async () => {
    const submission = authorized();
    const response = await POST(
      new NextRequest("http://localhost/api/stellar/submit-signed", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: sessionCookie(wallet.publicKey(), "operator"),
        },
        body: JSON.stringify(submission.body),
      }),
    );

    expect(response.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });
});

describe("POST /api/stellar/submit-signed - submission failures", () => {
  it("returns a 500 with the Horizon result codes when the network rejects the transaction", async () => {
    const submission = authorized();
    storeDecision(submission);
    const horizonError = Object.assign(new Error("Request failed with status code 400"), {
      response: {
        data: { extras: { result_codes: { transaction: "tx_bad_seq" } } },
      },
    });
    horizonMocks.submitTransaction.mockRejectedValueOnce(horizonError);

    const response = await POST(submit(submission.body));
    const body = await response.json();

    expect(response.status).toBe(500);
    expect(body.resultCode).toBe("tx_bad_seq");
    expect(body.explanation).toMatch(/sequence number/i);
    expect(getStellarSubmitResultCounts().get("horizon_failure")).toBe(1);
  });

  it("re-checks the decision right before submitting and refuses when it expired meanwhile", async () => {
    const submission = authorized();
    let calls = 0;
    storeMocks.getAuditEntryById.mockImplementation(async () => {
      calls += 1;
      // Valid for the first read, expired by the pre-submit re-check.
      return calls === 1
        ? submission.auditEntry
        : {
            ...submission.auditEntry,
            paymentQuote: { ...submission.quote, expiresAt: new Date(Date.now() - 1).toISOString() },
          };
    });

    const response = await POST(
      submit(submission.body, { "idempotency-key": "recheck-key-0001" }),
    );

    expect(response.status).toBe(403);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });
});
