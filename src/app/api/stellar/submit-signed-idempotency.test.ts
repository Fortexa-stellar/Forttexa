import { promises as fs } from "node:fs";

import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  const tmpDir = `/tmp/fortexa-idem-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  process.env.FORTEXA_STORE_DIR = tmpDir;
  process.env.FORTEXA_AUTH_SECRET = "idem-test-secret";
  process.env.STELLAR_HORIZON_URL = "https://horizon-mock.test";
  delete process.env.DATABASE_URL;
});

const horizonMocks = vi.hoisted(() => ({
  submitTransaction: vi.fn(),
  getAuditEntry: vi.fn(),
  verifyQuote: vi.fn(),
}));

const storeMocks = vi.hoisted(() => ({
  failComplete: false,
}));

const readStoreMocks = vi.hoisted(() => ({
  getAuditEntryById: vi.fn(),
  getUserWallet: vi.fn(),
}));

vi.mock("@/lib/storage/audit-store", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/storage/audit-store")>()),
  getAuditEntryById: readStoreMocks.getAuditEntryById,
}));

vi.mock("@/lib/storage/user-wallet-store", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/storage/user-wallet-store")>()),
  getUserWallet: readStoreMocks.getUserWallet,
}));

vi.mock("@/lib/storage/submit-idempotency-store", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@/lib/storage/submit-idempotency-store")>();

  return {
    ...actual,
    completeIdempotentSubmit: async (
      ...args: Parameters<typeof actual.completeIdempotentSubmit>
    ) => {
      if (storeMocks.failComplete) {
        throw new Error("idempotency store unavailable");
      }

      return actual.completeIdempotentSubmit(...args);
    },
  };
});

vi.mock("@stellar/stellar-sdk", async () => {
  const actual = await vi.importActual<typeof import("@stellar/stellar-sdk")>(
    "@stellar/stellar-sdk",
  );

  class MockServer {
    submitTransaction(tx: unknown) {
      return horizonMocks.submitTransaction(tx);
    }
  }

  return {
    ...actual,
    Horizon: {
      ...actual.Horizon,
      Server: MockServer,
    },
  };
});

import { Keypair, Networks, TransactionBuilder } from "@stellar/stellar-sdk";
import { NextRequest } from "next/server";

import { POST as submitSignedPost } from "@/app/api/stellar/submit-signed/route";
import {
  makeAuthorizedSubmission,
  type AuthorizedSubmission,
} from "@/app/api/stellar/submit-signed/test-fixtures";
import { buildDecisionReceipt } from "@/lib/stellar/verify-payment-quote";
import { IDEMPOTENCY_KEY_ERROR } from "@/lib/validation/schemas";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import { resetRateLimitStore } from "@/lib/security/rate-limit";
import { getAuditEntryById } from "@/lib/storage/audit-store";
import {
  getIdempotencyRecord,
  resetSubmitIdempotencyState,
} from "@/lib/storage/submit-idempotency-store";

const OPERATOR_USER_ID = "idem-operator-id";
const OPERATOR_WALLET_KEYPAIR = Keypair.random();
const mockTxHash = "b".repeat(64);
const OTHER_TX_HASH = "d".repeat(64);

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function slowSuccess(ms: number, hash = mockTxHash) {
  return new Promise<ReturnType<typeof horizonAccepted>>((resolve) => {
    setTimeout(() => resolve(horizonAccepted(hash)), ms);
  });
}

/** Every signed XDR this file builds, with the decision the server "stored" for it. */
const submissions = new Map<string, AuthorizedSubmission>();

function horizonAccepted(hash = mockTxHash) {
  return {
    hash,
    ledger: 42,
    successful: true,
    result_xdr: "AAAAAAAAAGQAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAA=",
  };
}

function operatorCookie() {
  const token = createSessionToken({
    email: "idem-operator@fortexa.local",
    role: "signer",
    userId: OPERATOR_USER_ID,
    publicKey: OPERATOR_WALLET_KEYPAIR.publicKey(),
    expiresInSeconds: 300,
  });

  return `${AUTH_COOKIE_KEY}=${token}`;
}

/**
 * Adds the build-response fields the console always sends alongside the signed
 * XDR (decisionId, quoteExpiresAt, buildAuthorization).
 */
function withAuthorization(body: Record<string, unknown>): Record<string, unknown> {
  const submission = submissions.get(String(body.signedXdr));
  if (!submission) return body;
  const { signedXdr, ...authorization } = submission.body;
  void signedXdr;
  return { ...authorization, ...body };
}

function submitRequest(
  body: Record<string, unknown>,
  extraHeaders: Record<string, string> = {},
) {
  return new NextRequest("http://localhost/api/stellar/submit-signed", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: operatorCookie(),
      ...extraHeaders,
    },
    body: JSON.stringify(withAuthorization(body)),
  });
}

function buildSignedXdr(amount: string, destination?: string) {
  const submission = makeAuthorizedSubmission({
    userId: OPERATOR_USER_ID,
    signer: OPERATOR_WALLET_KEYPAIR,
    amount,
    destination,
    memo: "fortexa:idem",
  });
  submissions.set(submission.signedXdr, submission);
  return submission.signedXdr;
}

function makeDecisionReceiptForXdr(signedXdr: string, amount: string) {
  const decoded = TransactionBuilder.fromXDR(signedXdr, Networks.TESTNET);
  const paymentOp = decoded.operations[0] as (typeof decoded.operations)[0] & {
    destination?: string;
  };
  return buildDecisionReceipt({
    destination: paymentOp.destination ?? OPERATOR_WALLET_KEYPAIR.publicKey(),
    amountXLM: amount,
    asset: "native",
    memo: "fortexa:idem",
    network: "testnet",
  });
}

beforeEach(async () => {
  vi.mocked(getAuditEntryById).mockImplementation(async (userId: string, id: string) => {
    if (userId !== OPERATOR_USER_ID) return undefined;
    for (const submission of submissions.values()) {
      if (submission.auditEntry.id === id) return submission.auditEntry;
    }
    return undefined;
  });
  readStoreMocks.getUserWallet.mockResolvedValue({
    userId: OPERATOR_USER_ID,
    publicKey: OPERATOR_WALLET_KEYPAIR.publicKey(),
    source: "external",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  storeMocks.failComplete = false;
  horizonMocks.submitTransaction.mockReset();
  horizonMocks.submitTransaction.mockResolvedValue(horizonAccepted());
  horizonMocks.getAuditEntry.mockResolvedValue({
    id: "00000000-0000-4000-8000-000000000000",
    paymentQuote: { memo: "fortexa:idempotency-test" },
  });
  horizonMocks.verifyQuote.mockReturnValue({ ok: true, quote: {} });

  await resetRateLimitStore();
  await resetSubmitIdempotencyState(OPERATOR_USER_ID);
});

afterAll(async () => {
  const storeDir = process.env.FORTEXA_STORE_DIR;
  if (storeDir && storeDir.startsWith("/tmp/fortexa-idem-")) {
    await fs
      .rm(storeDir, { recursive: true, force: true })
      .catch(() => undefined);
  }
});

describe("submit-signed idempotency", () => {
  it("replays the cached result for the same key + same XDR without resubmitting", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-replay-001";

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    const first = await submitSignedPost(
      submitRequest({ signedXdr, decisionReceipt, idempotencyKey: key }),
    );
    expect(first.status).toBe(200);
    const firstBody = await first.json();

    const second = await submitSignedPost(
      submitRequest({ signedXdr, decisionReceipt, idempotencyKey: key }),
    );
    expect(second.status).toBe(200);
    expect(second.headers.get("Idempotency-Replayed")).toBe("true");
    const secondBody = await second.json();

    expect(secondBody).toEqual(firstBody);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("returns 409 for the same key with a different signed XDR", async () => {
    const key = "idem-key-conflict-001";
    const firstXdr = buildSignedXdr("1.0000000");
    const secondXdr = buildSignedXdr("2.0000000");

    const firstDecisionReceipt = makeDecisionReceiptForXdr(
      firstXdr,
      "1.0000000",
    );
    const first = await submitSignedPost(
      submitRequest({
        signedXdr: firstXdr,
        decisionReceipt: firstDecisionReceipt,
        idempotencyKey: key,
      }),
    );
    expect(first.status).toBe(200);

    const secondDecisionReceipt = makeDecisionReceiptForXdr(
      secondXdr,
      "2.0000000",
    );
    const conflict = await submitSignedPost(
      submitRequest({
        signedXdr: secondXdr,
        decisionReceipt: secondDecisionReceipt,
        idempotencyKey: key,
      }),
    );
    expect(conflict.status).toBe(409);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("preserves current behavior when no idempotency key is provided", async () => {
    const signedXdr = buildSignedXdr("1.0000000");

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    const first = await submitSignedPost(
      submitRequest({ signedXdr, decisionReceipt }),
    );
    expect(first.status).toBe(200);

    const second = await submitSignedPost(
      submitRequest({ signedXdr, decisionReceipt }),
    );
    expect(second.status).toBe(200);

    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(2);
  });

  it("accepts the idempotency key via the Idempotency-Key header", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-header-001";

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    const first = await submitSignedPost(
      submitRequest({ signedXdr, decisionReceipt }, { "Idempotency-Key": key }),
    );
    expect(first.status).toBe(200);

    const second = await submitSignedPost(
      submitRequest({ signedXdr, decisionReceipt }, { "Idempotency-Key": key }),
    );
    expect(second.status).toBe(200);
    expect(second.headers.get("Idempotency-Replayed")).toBe("true");
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("treats a header key and a body key for the same payment as the same request", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-header-body-01";

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    for (const idempotencyKey of [
      "short",
      "a".repeat(256),
      "invalid key!",
      "bad/key",
    ]) {
      const response = await submitSignedPost(
        submitRequest({ signedXdr, decisionReceipt, idempotencyKey }),
      );
      expect(response.status).toBe(400);
      const body = await response.json();
      if (body.error === IDEMPOTENCY_KEY_ERROR) {
        expect(body.error).toBe(IDEMPOTENCY_KEY_ERROR);
      } else {
        expect(body.details?.fieldErrors?.idempotencyKey?.[0]).toBe(
          IDEMPOTENCY_KEY_ERROR,
        );
      }
    }

    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("returns 400 for too-short idempotency keys via header", async () => {
    const signedXdr = buildSignedXdr("1.0000000");

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    const response = await submitSignedPost(
      submitRequest(
        { signedXdr, decisionReceipt },
        { "Idempotency-Key": "short" },
      ),
    );
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toBe(IDEMPOTENCY_KEY_ERROR);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("returns 400 for malformed idempotency keys in the header", async () => {
    const signedXdr = buildSignedXdr("1.0000000");

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    const response = await submitSignedPost(
      submitRequest(
        { signedXdr, decisionReceipt },
        { "Idempotency-Key": "bad-key!" },
      ),
    );
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toBe(IDEMPOTENCY_KEY_ERROR);
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("returns 400 for oversized idempotency keys", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const oversizedKey = "a".repeat(256);

    const decisionReceipt = makeDecisionReceiptForXdr(signedXdr, "1.0000000");
    const response = await submitSignedPost(
      submitRequest({
        signedXdr,
        decisionReceipt,
        idempotencyKey: oversizedKey,
      }),
    );
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.details?.fieldErrors?.idempotencyKey?.[0]).toBe(
      IDEMPOTENCY_KEY_ERROR,
    );
    expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
  });
});

describe("submit-signed idempotency - one outcome per key", () => {
  it("creates a single payment outcome for two identical concurrent submits", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-concurrent-01";
    horizonMocks.submitTransaction.mockImplementation(() => slowSuccess(120));

    const [first, second] = await Promise.all([
      submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key })),
      submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key })),
    ]);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);

    const replayed = [first, second].filter(
      (response) => response.headers.get("Idempotency-Replayed") === "true"
    );
    expect(replayed).toHaveLength(1);

    const bodies = await Promise.all([first.json(), second.json()]);
    expect(bodies[0]).toEqual(bodies[1]);

    const stored = await getIdempotencyRecord(OPERATOR_USER_ID, key);
    expect(stored?.transactionId).toBe(mockTxHash);
    expect(stored?.statusCode).toBe(200);
    expect(stored?.state).toBe("settled");
  });

  it("creates a single payment outcome for three identical concurrent submits", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-concurrent-03";
    horizonMocks.submitTransaction.mockImplementation(() => slowSuccess(150));

    const responses = await Promise.all(
      Array.from({ length: 3 }, () =>
        submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }))
      )
    );

    expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);

    const bodies = await Promise.all(responses.map((response) => response.json()));
    expect(bodies[1]).toEqual(bodies[0]);
    expect(bodies[2]).toEqual(bodies[0]);
  });
});

describe("submit-signed idempotency - rejected retries", () => {
  it("rejects the same key with a different destination and keeps the original payment", async () => {
    const key = "idem-key-destination-01";
    const firstXdr = buildSignedXdr("1.0000000", Keypair.random().publicKey());
    const secondXdr = buildSignedXdr("1.0000000", Keypair.random().publicKey());

    const first = await submitSignedPost(submitRequest({ signedXdr: firstXdr, idempotencyKey: key }));
    expect(first.status).toBe(200);
    const firstBody = await first.json();

    const conflict = await submitSignedPost(
      submitRequest({ signedXdr: secondXdr, idempotencyKey: key })
    );
    expect(conflict.status).toBe(409);
    expect(conflict.headers.get("Idempotency-Replayed")).toBe("false");
    expect(await conflict.json()).toMatchObject({
      error: "Idempotency-Key was already used with a different signed transaction.",
    });

    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);

    const stored = await getIdempotencyRecord(OPERATOR_USER_ID, key);
    expect(stored?.transactionId).toBe(firstBody.transactionHash);
    expect(stored?.result).toEqual(firstBody);
  });

  it("does not build or submit a payment when a retry with a different destination arrives mid-submit", async () => {
    const key = "idem-key-destination-race";
    const firstXdr = buildSignedXdr("1.0000000", Keypair.random().publicKey());
    const secondXdr = buildSignedXdr("1.0000000", Keypair.random().publicKey());

    // Hold the first submit inside Horizon so the retry lands while the key is
    // already claimed, which is the window that used to rebuild a second payment.
    const horizonEntered = deferred<void>();
    const horizonResult = deferred<ReturnType<typeof horizonAccepted>>();
    horizonMocks.submitTransaction.mockImplementation(() => {
      horizonEntered.resolve();
      return horizonResult.promise;
    });

    const firstPromise = submitSignedPost(
      submitRequest({ signedXdr: firstXdr, idempotencyKey: key })
    );
    await horizonEntered.promise;

    const conflict = await submitSignedPost(
      submitRequest({ signedXdr: secondXdr, idempotencyKey: key })
    );
    expect(conflict.status).toBe(409);

    horizonResult.resolve(horizonAccepted());
    const first = await firstPromise;

    expect(first.status).toBe(200);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("still rejects an in-flight retry that never settles, without submitting twice", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-stuck-00001";
    process.env.FORTEXA_IDEMPOTENCY_IN_FLIGHT_WAIT_MS = "50";

    try {
      const store = await import("@/lib/storage/submit-idempotency-store");
      const requestHash = store.hashCanonicalPaymentBody(
        key,
        withAuthorization({ signedXdr, idempotencyKey: key }),
      );
      await store.beginIdempotentSubmit(OPERATOR_USER_ID, key, requestHash, {
        inFlightWaitMs: 0,
      });

      const response = await submitSignedPost(
        submitRequest({ signedXdr, idempotencyKey: key })
      );

      expect(response.status).toBe(409);
      expect(response.headers.get("Retry-After")).toBe("1");
      expect(await response.json()).toMatchObject({ code: "idempotency_in_flight" });
      expect(horizonMocks.submitTransaction).not.toHaveBeenCalled();
    } finally {
      delete process.env.FORTEXA_IDEMPOTENCY_IN_FLIGHT_WAIT_MS;
    }
  });
});

describe("submit-signed idempotency - replay returns the original result", () => {
  it("returns the stored status and transaction id on replay", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-original-001";
    horizonMocks.submitTransaction.mockImplementation(() => slowSuccess(1, mockTxHash));

    const first = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));
    expect(first.status).toBe(200);
    const firstBody = await first.json();
    expect(firstBody.transactionHash).toBe(mockTxHash);
    expect(firstBody.payment.hash).toBe(mockTxHash);

    const replay = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));
    const replayBody = await replay.json();

    expect(replay.status).toBe(first.status);
    expect(replayBody.transactionHash).toBe(mockTxHash);
    expect(replayBody.payment.hash).toBe(mockTxHash);
    expect(replayBody).toEqual(firstBody);

    const stored = await getIdempotencyRecord(OPERATOR_USER_ID, key);
    expect(stored?.transactionId).toBe(mockTxHash);
    expect(stored?.result).toEqual(firstBody);
  });

  it("does not let a late duplicate replace the stored transaction id", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-first-write-01";

    horizonMocks.submitTransaction.mockImplementation(() => slowSuccess(1, mockTxHash));
    const first = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));
    expect(first.status).toBe(200);

    horizonMocks.submitTransaction.mockImplementation(() => slowSuccess(1, OTHER_TX_HASH));
    const replay = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect((await replay.json()).transactionHash).toBe(mockTxHash);

    const stored = await getIdempotencyRecord(OPERATOR_USER_ID, key);
    expect(stored?.transactionId).toBe(mockTxHash);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(1);
  });
});

describe("submit-signed idempotency - failed submits", () => {
  it("releases the key when the submit fails so the client can retry", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-retry-00001";

    horizonMocks.submitTransaction.mockRejectedValueOnce(
      new Error("Request failed with status code 400")
    );

    const failed = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));
    expect(failed.status).toBe(500);

    expect(await getIdempotencyRecord(OPERATOR_USER_ID, key)).toBeNull();

    const retried = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));
    expect(retried.status).toBe(200);
    expect((await retried.json()).transactionHash).toBe(mockTxHash);
    expect(horizonMocks.submitTransaction).toHaveBeenCalledTimes(2);
  });

  it("lets a waiting retry take over after the owning submit fails", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-retry-race01";

    const horizonEntered = deferred<void>();
    horizonMocks.submitTransaction
      .mockImplementationOnce(() => {
        horizonEntered.resolve();
        return new Promise((_resolve, reject) => {
          setTimeout(() => reject(new Error("Request failed with status code 400")), 80);
        });
      })
      .mockImplementationOnce(() => slowSuccess(30, OTHER_TX_HASH));

    const ownerPromise = submitSignedPost(
      submitRequest({ signedXdr, idempotencyKey: key })
    );
    await horizonEntered.promise;

    // The retry waits on the live claim; when the owner fails and releases the
    // key, the retry must take it over instead of replaying a phantom result.
    const waitedPromise = submitSignedPost(
      submitRequest({ signedXdr, idempotencyKey: key })
    );

    const failed = await ownerPromise;
    expect(failed.status).toBe(500);

    const waited = await waitedPromise;
    expect(waited.status).toBe(200);
    expect(waited.headers.get("Idempotency-Replayed")).toBe("false");
    expect((await waited.json()).transactionHash).toBe(OTHER_TX_HASH);

    const stored = await getIdempotencyRecord(OPERATOR_USER_ID, key);
    expect(stored?.state).toBe("settled");
    expect(stored?.transactionId).toBe(OTHER_TX_HASH);
  });
});

describe("submit-signed idempotency - settle failures", () => {
  it("returns the accepted result and holds the claim when storing the outcome fails", async () => {
    const signedXdr = buildSignedXdr("1.0000000");
    const key = "idem-key-settle-fail";
    storeMocks.failComplete = true;

    const response = await submitSignedPost(submitRequest({ signedXdr, idempotencyKey: key }));

    // The transaction is on the ledger, so the client still gets the real
    // transaction id instead of an error that would invite a blind resubmit.
    expect(response.status).toBe(200);
    expect((await response.json()).transactionHash).toBe(mockTxHash);

    // The claim is deliberately left in flight rather than released, because
    // releasing it would hand the next caller a clean key for a second payment.
    const stored = await getIdempotencyRecord(OPERATOR_USER_ID, key);
    expect(stored?.state).toBe("in_flight");
    expect(stored?.transactionId).toBeNull();
  });
});