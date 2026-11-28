import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";
import type { ZodError } from "zod";

import {
  decisionRequestSchema,
  stellarBuildPaymentRequestSchema,
  stellarSubmitSignedRequestSchema,
  strictStellarBuildPaymentRequestSchema,
} from "@/lib/validation/schemas";
import {
  buildUnknownFieldsBody,
  MAX_REPORTED_UNKNOWN_FIELDS,
  UNKNOWN_FIELDS_CODE,
} from "@/lib/validation/unknown-fields";

const DESTINATION = `G${"A".repeat(55)}`;

const validAction = {
  id: "action-1",
  name: "Research API payment",
  kind: "api_payment",
  target: "svc:endpoint",
  domain: "api.example.com",
  amountXLM: 12.5,
  tool: "web_search",
  metadata: { source: "unit-test", attempt: 1, retry: false },
};

const validBuild = {
  auditEntryId: randomUUID(),
  destination: DESTINATION,
  amountXLM: "12.5000000",
  asset: "native",
  memo: "fortexa:action-1",
  network: "testnet",
};

const validReceipt = {
  destination: DESTINATION,
  amountXLM: "12.5",
  asset: "native",
  memo: "fortexa:action-1",
  network: "testnet",
  receiptHash: "a".repeat(64),
};

// What the console submits: signedXdr plus the build-response fields.
const validSubmit = {
  signedXdr: "A".repeat(40),
  decisionId: "00000000-0000-4000-8000-000000000001",
  quoteExpiresAt: "2099-01-01T00:00:00.000Z",
  buildAuthorization: "payload.signature",
};

function failure(result: { success: boolean; error?: ZodError }): ZodError {
  expect(result.success).toBe(false);
  return result.error as ZodError;
}

describe("POST /api/decision schema", () => {
  it("still accepts every documented payload shape", () => {
    expect(decisionRequestSchema.safeParse({ scenarioId: "safe-research-payment" }).success).toBe(true);
    expect(
      decisionRequestSchema.safeParse({ scenarioId: "safe-research-payment", approvedByHuman: true }).success,
    ).toBe(true);
    expect(
      decisionRequestSchema.safeParse({
        action: validAction,
        approvedByHuman: false,
        paymentQuoteInput: { destination: DESTINATION, memo: "fortexa:action-1", network: "testnet" },
      }).success,
    ).toBe(true);
    expect(
      decisionRequestSchema.safeParse({
        action: validAction,
        paymentQuoteInput: { destination: DESTINATION },
      }).success,
    ).toBe(true);
  });

  it("rejects a single unknown top-level field with the stable code", () => {
    const error = failure(
      decisionRequestSchema.safeParse({ scenarioId: "safe-research-payment", approvedByHumna: true }),
    );
    expect(buildUnknownFieldsBody(error, "Invalid decision request body.")).toEqual({
      error: "Invalid decision request body.",
      code: UNKNOWN_FIELDS_CODE,
      unknownFields: ["approvedByHumna"],
      omittedUnknownFieldCount: 0,
    });
  });

  it("rejects an unknown field nested in action and paymentQuoteInput", () => {
    const error = failure(
      decisionRequestSchema.safeParse({
        action: { ...validAction, amountXlm: 1 },
        paymentQuoteInput: { destination: DESTINATION, destinaton: DESTINATION },
      }),
    );
    expect(buildUnknownFieldsBody(error, "x")?.unknownFields).toEqual([
      "action.amountXlm",
      "paymentQuoteInput.destinaton",
    ]);
  });

  it("keeps the existing 'provide a scenario or action' error when nothing is unknown", () => {
    const error = failure(decisionRequestSchema.safeParse({ approvedByHuman: true }));
    expect(buildUnknownFieldsBody(error, "x")).toBeNull();
  });
});

describe("POST /api/stellar/build-payment schema", () => {
  it("still accepts the documented payload, with and without optional fields", () => {
    expect(strictStellarBuildPaymentRequestSchema.safeParse(validBuild).success).toBe(true);
    expect(
      strictStellarBuildPaymentRequestSchema.safeParse({
        auditEntryId: validBuild.auditEntryId,
        destination: DESTINATION,
        amountXLM: "1",
        requestTimestampMs: Date.now(),
      }).success,
    ).toBe(true);
  });

  it("rejects a single unknown field with the stable code", () => {
    const error = failure(
      strictStellarBuildPaymentRequestSchema.safeParse({ ...validBuild, destinaton: DESTINATION }),
    );
    expect(buildUnknownFieldsBody(error, "Invalid payment build request.")).toEqual({
      error: "Invalid payment build request.",
      code: "UNKNOWN_FIELDS",
      unknownFields: ["destinaton"],
      omittedUnknownFieldCount: 0,
    });
  });

  it("leaves the lenient schema (used by /api/stellar/pay) unchanged", () => {
    expect(stellarBuildPaymentRequestSchema.safeParse({ ...validBuild, extra: 1 }).success).toBe(true);
  });
});

describe("POST /api/stellar/submit-signed schema", () => {
  it("still accepts every documented payload shape", () => {
    // The console contract, with no decisionReceipt.
    expect(stellarSubmitSignedRequestSchema.safeParse(validSubmit).success).toBe(true);
    expect(
      stellarSubmitSignedRequestSchema.safeParse({ ...validSubmit, idempotencyKey: "retry-key-0001" }).success,
    ).toBe(true);
    // Echoing the build response's decisionReceipt back is still accepted,
    // including the fields only the server stamps on a stored quote.
    expect(
      stellarSubmitSignedRequestSchema.safeParse({
        ...validSubmit,
        decisionId: randomUUID(),
        quoteExpiresAt: new Date().toISOString(),
        buildAuthorization: "b".repeat(64),
        decisionReceipt: {
          ...validReceipt,
          expiresAt: new Date().toISOString(),
          amountStroops: "180000000",
        },
      }).success,
    ).toBe(true);
  });

  it("requires the build-response fields the server validates against", () => {
    for (const field of ["decisionId", "quoteExpiresAt", "buildAuthorization"] as const) {
      const { [field]: _omitted, ...rest } = validSubmit;
      void _omitted;
      expect(stellarSubmitSignedRequestSchema.safeParse(rest).success, field).toBe(false);
    }
  });

  it("rejects a single unknown field with the stable code", () => {
    const error = failure(stellarSubmitSignedRequestSchema.safeParse({ ...validSubmit, signedXDR: "x" }));
    expect(buildUnknownFieldsBody(error, "Invalid signed transaction payload.")).toEqual({
      error: "Invalid signed transaction payload.",
      code: "UNKNOWN_FIELDS",
      unknownFields: ["signedXDR"],
      omittedUnknownFieldCount: 0,
    });
  });

  it("rejects an unknown field nested in decisionReceipt", () => {
    const error = failure(
      stellarSubmitSignedRequestSchema.safeParse({
        ...validSubmit,
        decisionReceipt: { ...validReceipt, reciptHash: "a".repeat(64) },
      }),
    );
    expect(buildUnknownFieldsBody(error, "x")?.unknownFields).toEqual(["decisionReceipt.reciptHash"]);
  });
});

describe("buildUnknownFieldsBody", () => {
  it("never reflects values, and counts instead of echoing unsafe field names", () => {
    const secretValue = "S".repeat(56);
    const hostileKey = `<script>alert("${secretValue}")</script>`;
    const error = failure(
      strictStellarBuildPaymentRequestSchema.safeParse({
        ...validBuild,
        goodTypo: secretValue,
        [hostileKey]: secretValue,
        ["x".repeat(65)]: 1,
        "has space": 1,
      }),
    );

    const body = buildUnknownFieldsBody(error, "Invalid payment build request.");
    expect(body?.unknownFields).toEqual(["goodTypo"]);
    expect(body?.omittedUnknownFieldCount).toBe(3);

    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain(secretValue);
    expect(serialized).not.toContain("script");
    expect(serialized).not.toContain("has space");
  });

  it("caps the reported names and counts the rest", () => {
    const extras = Object.fromEntries(
      Array.from({ length: MAX_REPORTED_UNKNOWN_FIELDS + 5 }, (_, i) => [`extra${String(i).padStart(2, "0")}`, i]),
    );
    const error = failure(strictStellarBuildPaymentRequestSchema.safeParse({ ...validBuild, ...extras }));
    const body = buildUnknownFieldsBody(error, "x");
    expect(body?.unknownFields).toHaveLength(MAX_REPORTED_UNKNOWN_FIELDS);
    expect(body?.omittedUnknownFieldCount).toBe(5);
  });

  it("reports other problems separately without leaking the unknown field", () => {
    const error = failure(
      strictStellarBuildPaymentRequestSchema.safeParse({
        ...validBuild,
        amountXLM: "not-a-number",
        "bad key!": 1,
      }),
    );
    const body = buildUnknownFieldsBody(error, "x");
    expect(body?.code).toBe("UNKNOWN_FIELDS");
    expect(body?.details?.fieldErrors.amountXLM?.length).toBeGreaterThan(0);
    expect(JSON.stringify(body?.details)).not.toContain("bad key");
  });

  it("returns null when the failure has no unknown fields", () => {
    const error = failure(strictStellarBuildPaymentRequestSchema.safeParse({ ...validBuild, amountXLM: "x" }));
    expect(buildUnknownFieldsBody(error, "x")).toBeNull();
  });
});
