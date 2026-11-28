import { Account, Keypair, Memo, Networks, TransactionBuilder, type Transaction } from "@stellar/stellar-sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";

const horizon = vi.hoisted(() => ({
  serverCtor: vi.fn(),
  loadAccount: vi.fn(),
  fetchBaseFee: vi.fn(),
}));

vi.mock("@stellar/stellar-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@stellar/stellar-sdk")>();
  class FakeServer {
    constructor(url: string) {
      horizon.serverCtor(url);
    }
    loadAccount = horizon.loadAccount;
    fetchBaseFee = horizon.fetchBaseFee;
  }
  return { ...actual, Horizon: { ...actual.Horizon, Server: FakeServer } };
});

vi.mock("@/lib/stellar/network-config", () => ({
  assertStellarNetworkConfig: () => ({
    networkPassphrase: Networks.TESTNET,
    horizonUrl: "https://horizon-testnet.stellar.org",
  }),
  getStellarHorizonUrl: () => "https://horizon-testnet.stellar.org",
}));

import { buildUnsignedPaymentTransaction } from "@/lib/stellar/client";
import {
  MEMO_MAX_BYTES,
  MEMO_TOO_LONG_CODE,
  MemoTooLongError,
  assertMemoWithinByteLimit,
  isMemoWithinByteLimit,
  memoByteLength,
} from "@/lib/stellar/memo";
import { toPublicValidationDetails } from "@/lib/validation/errors";
import {
  decisionRequestSchema,
  stellarBuildPaymentRequestSchema,
  stellarSubmitSignedRequestSchema,
} from "@/lib/validation/schemas";

const DESTINATION = Keypair.random().publicKey();
const SOURCE = Keypair.random().publicKey();
const AUDIT_ENTRY_ID = "6f1c1d56-47f4-4a8e-9a43-4b8d1e4c3f10";

// Each case is a memo and its UTF-8 size, so the boundary is stated, not computed.
const WITHIN_LIMIT: Array<[string, string, number]> = [
  ["empty", "", 0],
  ["28 ASCII characters", "a".repeat(28), 28],
  ["14 two-byte characters", "é".repeat(14), 28],
  ["9 three-byte characters", "€".repeat(9), 27],
  ["7 four-byte characters", "\u{1F600}".repeat(7), 28],
  ["26 ASCII characters and one two-byte character", `${"a".repeat(26)}é`, 28],
];

const OVER_LIMIT: Array<[string, string, number]> = [
  ["29 ASCII characters", "a".repeat(29), 29],
  ["15 two-byte characters", "é".repeat(15), 30],
  ["10 three-byte characters", "€".repeat(10), 30],
  ["8 four-byte characters", "\u{1F600}".repeat(8), 32],
  // 28 characters long, so a character-count limit lets it through: it is 29 bytes.
  ["28 characters that are 29 bytes", `${"a".repeat(27)}é`, 29],
];

describe("memo byte limit", () => {
  it("states the text memo limit as 28 bytes", () => {
    expect(MEMO_MAX_BYTES.text).toBe(28);
  });

  it.each([...WITHIN_LIMIT, ...OVER_LIMIT])("counts %s in UTF-8 bytes", (_label, memo, bytes) => {
    expect(memoByteLength(memo)).toBe(bytes);
  });

  it.each(WITHIN_LIMIT)("accepts %s", (_label, memo) => {
    expect(isMemoWithinByteLimit(memo)).toBe(true);
    expect(() => assertMemoWithinByteLimit(memo)).not.toThrow();
  });

  it.each(OVER_LIMIT)("rejects %s", (_label, memo) => {
    expect(isMemoWithinByteLimit(memo)).toBe(false);
    expect(() => assertMemoWithinByteLimit(memo)).toThrow(MemoTooLongError);
  });

  it("agrees with the SDK: whatever it accepts the Stellar library also accepts", () => {
    for (const [, memo] of WITHIN_LIMIT) {
      expect(() => Memo.text(memo)).not.toThrow();
    }
    for (const [, memo] of OVER_LIMIT) {
      expect(() => Memo.text(memo)).toThrow();
    }
  });

  it("carries the stable code and never the memo text", () => {
    const secretLooking = "é".repeat(15);
    try {
      assertMemoWithinByteLimit(secretLooking);
      throw new Error("expected a throw");
    } catch (error) {
      expect(error).toBeInstanceOf(MemoTooLongError);
      const memoError = error as MemoTooLongError;
      expect(memoError.code).toBe(MEMO_TOO_LONG_CODE);
      expect(memoError.byteLength).toBe(30);
      expect(memoError.maxBytes).toBe(28);
      expect(memoError.message).not.toContain(secretLooking);
    }
  });
});

describe("request schemas reject an oversized memo with a stable code", () => {
  const buildRequest = (memo?: string) => ({
    auditEntryId: AUDIT_ENTRY_ID,
    destination: DESTINATION,
    amountXLM: "1.5",
    ...(memo === undefined ? {} : { memo }),
  });

  it.each(WITHIN_LIMIT.filter(([, memo]) => memo.length > 0))(
    "build-payment accepts %s",
    (_label, memo) => {
      expect(stellarBuildPaymentRequestSchema.safeParse(buildRequest(memo)).success).toBe(true);
    },
  );

  it("build-payment accepts a request with no memo", () => {
    expect(stellarBuildPaymentRequestSchema.safeParse(buildRequest()).success).toBe(true);
  });

  it.each(OVER_LIMIT)("build-payment rejects %s with memo_too_long", (_label, memo) => {
    const parsed = stellarBuildPaymentRequestSchema.safeParse(buildRequest(memo));

    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.flatten().fieldErrors.memo).toEqual([MEMO_TOO_LONG_CODE]);
    }
  });

  it("keeps the code visible in the public details even though memo is a hidden field", () => {
    const parsed = stellarBuildPaymentRequestSchema.safeParse(buildRequest("é".repeat(15)));

    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const details = toPublicValidationDetails(parsed.error);
      expect(details.fieldErrors.memo).toEqual([MEMO_TOO_LONG_CODE]);
      expect(JSON.stringify(details)).not.toContain("é");
    }
  });

  it("still hides any other memo message behind the generic text", () => {
    const parsed = stellarBuildPaymentRequestSchema.safeParse({ ...buildRequest(), memo: 12345 });

    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(toPublicValidationDetails(parsed.error).fieldErrors.memo).toEqual(["Invalid value."]);
    }
  });

  it("decision request rejects an oversized quote memo", () => {
    const parsed = decisionRequestSchema.safeParse({
      paymentQuoteInput: { destination: DESTINATION, memo: "a".repeat(29) },
    });

    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(JSON.stringify(parsed.error.issues)).toContain(MEMO_TOO_LONG_CODE);
    }
  });

  it("submit-signed rejects an oversized receipt memo", () => {
    const parsed = stellarSubmitSignedRequestSchema.safeParse({
      signedXdr: "A".repeat(40),
      decisionReceipt: {
        destination: DESTINATION,
        amountXLM: "1.5",
        memo: "€".repeat(10),
      },
    });

    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(JSON.stringify(parsed.error.issues)).toContain(MEMO_TOO_LONG_CODE);
    }
  });
});

describe("buildUnsignedPaymentTransaction", () => {
  beforeEach(() => {
    horizon.serverCtor.mockReset();
    horizon.loadAccount.mockReset();
    horizon.fetchBaseFee.mockReset();
    horizon.loadAccount.mockResolvedValue(new Account(SOURCE, "100"));
    horizon.fetchBaseFee.mockResolvedValue(100);
  });

  const request = (memo?: string) => ({
    destination: DESTINATION,
    amountXLM: "1.5",
    asset: "native" as const,
    network: "testnet" as const,
    ...(memo === undefined ? {} : { memo }),
  });

  it.each(OVER_LIMIT)("rejects %s before calling Horizon or building XDR", async (_label, memo) => {
    await expect(buildUnsignedPaymentTransaction(request(memo), SOURCE)).rejects.toMatchObject({
      code: MEMO_TOO_LONG_CODE,
    });

    expect(horizon.serverCtor).not.toHaveBeenCalled();
    expect(horizon.loadAccount).not.toHaveBeenCalled();
    expect(horizon.fetchBaseFee).not.toHaveBeenCalled();
  });

  it.each(WITHIN_LIMIT.filter(([, memo]) => memo.length > 0))(
    "builds a transaction that carries %s unchanged",
    async (_label, memo) => {
      const { xdr } = await buildUnsignedPaymentTransaction(request(memo), SOURCE);

      const tx = TransactionBuilder.fromXDR(xdr, Networks.TESTNET) as Transaction;
      expect(tx.memo.value?.toString()).toBe(memo);
    },
  );

  it("falls back to the default memo when none is given", async () => {
    const { xdr } = await buildUnsignedPaymentTransaction(request(), SOURCE);

    const tx = TransactionBuilder.fromXDR(xdr, Networks.TESTNET) as Transaction;
    expect(tx.memo.value?.toString()).toBe("Fortexa payment");
  });
});
