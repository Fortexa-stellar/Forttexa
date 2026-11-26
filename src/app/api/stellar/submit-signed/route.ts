import { NextRequest } from "next/server";
import {
  FeeBumpTransaction,
  TransactionBuilder,
  type Operation,
} from "@stellar/stellar-sdk";

import { requireAuth } from "@/lib/auth/require-auth";
import { isLoginAuthorizationPayload } from "@/lib/auth/wallet-challenge";
import { readJsonBody } from "@/lib/http/read-json-body";
import { requireJsonContentType } from "@/lib/http/require-json-content-type";
import { jsonWithRequestContext } from "@/lib/observability/http";
import {
  getRequestLogContext,
  logError,
  logInfo,
  logWarn,
} from "@/lib/observability/logger";
import { recordStellarSubmitResult } from "@/lib/observability/metrics";
import { getProtectedPaymentFlowReadinessReport } from "@/lib/readiness/production";
import { rateLimitHeaders } from "@/lib/security/rate-limit";
import {
  enforceRequestGate,
  gateErrorHeaders,
} from "@/lib/security/enforcement-gate";
import {
  decodeSignedXdrDestination,
  decodeSignedXdrSourceAccount,
  submitSignedTransactionXdr,
  verifySignedXdrSigner,
} from "@/lib/stellar/client";
import type { SignedXdrDestinationResult } from "@/lib/stellar/client";
import { getStellarExplorerTransactionUrl } from "@/lib/stellar/network";
import { assertStellarNetworkConfig } from "@/lib/stellar/network-config";
import {
  getTransactionHash,
  verifyBuildAuthorization,
} from "@/lib/stellar/payment-build-authorization";
import {
  isPaymentDecisionCurrent,
  validateDecisionReceipt,
} from "@/lib/stellar/verify-payment-quote";
import {
  abortIdempotentSubmit,
  beginIdempotentSubmit,
  completeIdempotentSubmit,
  getIdempotencyInFlightWaitMs,
  hashCanonicalPaymentBody,
  maybeRunCleanup,
} from "@/lib/storage/submit-idempotency-store";
import { getUserWallet } from "@/lib/storage/user-wallet-store";
import { getAuditEntryById } from "@/lib/storage/audit-store";
import {
  stellarSubmitSignedRequestSchema,
  validateIdempotencyKey,
} from "@/lib/validation/schemas";
import {
  logValidationFailure,
  toPublicValidationDetails,
} from "@/lib/validation/errors";
import { normalizeHorizonError } from "@/lib/utils/horizonErrors";
import { verifyPaymentAgainstQuote } from "@/lib/stellar/verify-payment-quote";
import { redactSensitiveFields } from "@/lib/observability/redact";

type HorizonErrorContext = {
  explanation: string;
  nextStep: string;
};

/**
 * Best-effort destination extraction from a signed XDR for gate checking.
 * Runs before validation; a malformed envelope simply reports no destination
 * (the strict decode later still returns the route's normal 400).
 */
function extractSignedXdrDestination(
  signedXdr: string | undefined,
): SignedXdrDestinationResult {
  if (!signedXdr) {
    return { ok: false, reason: "malformed" };
  }

  try {
    return decodeSignedXdrDestination(signedXdr);
  } catch {
    return { ok: false, reason: "malformed" };
  }
}

const HORIZON_TX_ERRORS: Record<string, HorizonErrorContext> = {
  tx_bad_seq: {
    explanation: "The transaction sequence number is incorrect.",
    nextStep:
      "Refresh your wallet or account data to synchronize the sequence number and try again.",
  },
  tx_insufficient_fee: {
    explanation: "The network fee provided is too low.",
    nextStep: "Increase the transaction fee.",
  },
  tx_failed: {
    explanation: "The transaction failed during operation execution.",
    nextStep: "Check the operation error codes for more details.",
  },
};

const HORIZON_OP_ERRORS: Record<string, HorizonErrorContext> = {
  op_no_destination: {
    explanation: "The destination account does not exist on the network.",
    nextStep: "Verify the destination address or ensure the account is funded.",
    // #205: op_no_destination can echo back the user-supplied destination
    // address in Horizon error detail. Keep the operator-facing text, but the
    // log path passes raw error.message through redactSensitiveFields so the
    // address itself never reaches logs.
  },
  op_underfunded: {
    explanation:
      "The source account lacks sufficient funds for this operation.",
    nextStep:
      "Fund the source account with enough XLM to cover the payment and reserves.",
  },
};

type DecodedTransaction = ReturnType<typeof TransactionBuilder.fromXDR>;
type DecodedOperation = DecodedTransaction["operations"][number];

function isPaymentOperation(
  op: DecodedOperation,
): op is Operation.Payment {
  return op.type === "payment";
}

function verifySignedXdrMatchesDecisionReceipt(
  signedXdr: string,
  receipt: unknown,
) {
  const validation = validateDecisionReceipt(receipt);
  if (!validation.ok) {
    return {
      ok: false,
      status: 403,
      error: validation.error,
      field: validation.field,
    };
  }

  const { networkPassphrase } = assertStellarNetworkConfig();
  let decoded: DecodedTransaction;

  try {
    decoded = TransactionBuilder.fromXDR(signedXdr, networkPassphrase);
  } catch {
    return {
      ok: false,
      status: 400,
      error:
        "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
    };
  }

  const transaction =
    decoded instanceof FeeBumpTransaction ? decoded.innerTransaction : decoded;

  const paymentOp = transaction.operations.find(isPaymentOperation);
  if (!paymentOp) {
    return {
      ok: false,
      status: 403,
      error: "Signed transaction is not a payment operation.",
      field: "destination",
    };
  }

  const network =
    networkPassphrase === "Test SDF Network ; September 2015"
      ? "testnet"
      : "testnet";
  const actual = {
    destination: paymentOp.destination?.trim().toUpperCase(),
    amountXLM: String(paymentOp.amount ?? "0"),
    asset: "native",
    memo: transaction.memo?.type === "text" ? String(transaction.memo.value ?? "") : "",
    network,
  };

  if (actual.destination !== validation.normalized.destination) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction destination does not match the authorized payment decision receipt.",
      field: "destination",
    };
  }

  if (String(validation.normalized.amountXLM) !== String(actual.amountXLM)) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction amount does not match the authorized payment decision receipt.",
      field: "amountXLM",
    };
  }

  if (actual.asset !== validation.normalized.asset) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction asset does not match the authorized payment decision receipt.",
      field: "asset",
    };
  }

  const normalizedMemo = actual.memo.slice(0, 28);
  if (normalizedMemo !== validation.normalized.memo) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction memo does not match the authorized payment decision receipt.",
      field: "memo",
    };
  }

  if (actual.network !== validation.normalized.network) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction network does not match the authorized payment decision receipt.",
      field: "network",
    };
  }

  const expectedHash = validation.normalized.receiptHash;
  const providedHash = (receipt as { receiptHash?: string }).receiptHash;
  if (expectedHash && providedHash && expectedHash !== providedHash) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction does not match the authorized payment decision receipt.",
      field: "amountXLM",
    };
  }

  return { ok: true };
}

function decodePaymentDetails(signedXdr: string) {
  const { networkPassphrase } = assertStellarNetworkConfig();

  let decoded: DecodedTransaction;
  try {
    decoded = TransactionBuilder.fromXDR(signedXdr, networkPassphrase);
  } catch {
    return null;
  }

  const transaction =
    decoded instanceof FeeBumpTransaction ? decoded.innerTransaction : decoded;
  const paymentOp = transaction.operations.find(isPaymentOperation);
  if (!paymentOp) {
    return null;
  }

  return {
    destination: String(paymentOp.destination ?? ""),
    amountXLM: String(paymentOp.amount ?? "0"),
    asset: "native" as const,
    memo:
      transaction.memo?.type === "text"
        ? String(transaction.memo.value ?? "")
        : undefined,
    network: "testnet" as const,
  };
}

export function formatSubmitError(error: unknown) {
  if (!(error instanceof Error)) {
    return { message: "Failed to submit signed transaction." };
  }

  const withResponse = error as Error & {
    response?: {
      data?: {
        extras?: {
          result_codes?: {
            transaction?: string;
            operations?: string[];
          };
        };
      };
    };
  };

  const txCode = withResponse.response?.data?.extras?.result_codes?.transaction;
  const opCodes = withResponse.response?.data?.extras?.result_codes?.operations;

  if (!txCode) {
    return { message: error.message };
  }

  let explanation: string | undefined;
  let nextStep: string | undefined;

  if (opCodes && opCodes.length > 0) {
    const firstOpError = opCodes.find((code) => HORIZON_OP_ERRORS[code]);
    if (firstOpError) {
      explanation = HORIZON_OP_ERRORS[firstOpError].explanation;
      nextStep = HORIZON_OP_ERRORS[firstOpError].nextStep;
    } else if (HORIZON_TX_ERRORS[txCode]) {
      explanation = HORIZON_TX_ERRORS[txCode].explanation;
      nextStep = HORIZON_TX_ERRORS[txCode].nextStep;
    }
  } else if (HORIZON_TX_ERRORS[txCode]) {
    explanation = HORIZON_TX_ERRORS[txCode].explanation;
    nextStep = HORIZON_TX_ERRORS[txCode].nextStep;
  }

  return {
    message: `${error.message} (tx: ${txCode}${opCodes?.length ? `, ops: ${opCodes.join(",")}` : ""})`,
    txCode,
    opCodes,
    explanation,
    nextStep,
  };
}

export async function POST(request: NextRequest) {
  const startedAtMs = Date.now();
  const context = getRequestLogContext(request, "/api/stellar/submit-signed");
  let requestBody: unknown;
  let requestBodyTooLarge = false;
  const respond: typeof jsonWithRequestContext = (incoming, input) =>
    jsonWithRequestContext(incoming, {
      ...input,
      logExchange: true,
      requestBody,
      requestBodyTooLarge,
    });

  // Enforce JSON content type before doing any other work so unsupported
  // payloads get a stable 415 instead of a generic parse failure.
  const contentTypeCheck = requireJsonContentType(request);
  if (!contentTypeCheck.ok) {
    logWarn("Submit signed unsupported content type", context);
    return respond(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 415,
      body: { error: contentTypeCheck.error, code: "UNSUPPORTED_MEDIA_TYPE" },
    });
  }

  // Read the body before the gate so the signed transaction's destination
  // operations can be blocklist-checked in the same atomic enforcement step
  // as the rate-limit consumption (issue #202).
  const bodyResult = await readJsonBody(request);

  // A wallet login signature proves control of a key for authentication; it
  // must never be replayed as authorization for a payment. Reject it before
  // role checks so an authenticated operator cannot try to spend with it.
  if (bodyResult.ok && isLoginAuthorizationPayload(bodyResult.data)) {
    logWarn("Submit signed rejected login authorization payload", context);
    return respond(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 400,
      body: { error: "Login signatures cannot authorize a payment." },
    });
  }

  let gateDestination: string | undefined;
  if (bodyResult.ok) {
    const destinationPreview = extractSignedXdrDestination(
      typeof (bodyResult.data as { signedXdr?: unknown })?.signedXdr === "string"
        ? ((bodyResult.data as { signedXdr: string }).signedXdr)
        : undefined,
    );
    gateDestination = destinationPreview.ok ? destinationPreview.destination : undefined;
  }

  const gate = await enforceRequestGate(request, {
    rateLimitKey: "stellar-submit-signed",
    limit: 30,
    windowMs: 60_000,
    destination: gateDestination,
  });

  if (!gate.ok) {
    logWarn("Submit signed route denied by enforcement gate", context);
    return respond(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: gate.status,
      body: { error: gate.error, code: gate.code },
      headers: gateErrorHeaders(gate),
    });
  }

  const rate = gate.rate;

  maybeRunCleanup();

  try {
    const auth = requireAuth(request, { allowedRoles: ["signer"] });

    if (!auth.ok) {
      logWarn("Submit signed route unauthorized", context);
      return auth.response;
    }

    const readinessReport = getProtectedPaymentFlowReadinessReport();
    if (readinessReport) {
      logWarn("Submit signed blocked by production readiness check", context);
      return respond(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 503,
        body: {
          error:
            "Protected payment flows are disabled until Fortexa passes the production readiness check.",
          issues: readinessReport.issues,
          command: "npm run check:production-readiness",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const userId = auth.session.userId;

    if (bodyResult.ok) {
      requestBody = bodyResult.data;
    }

    if (!bodyResult.ok) {
      requestBodyTooLarge = true;
      logWarn("Submit signed payload too large", { ...context, userId });
      return respond(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 413,
        body: { error: bodyResult.error },
        headers: rateLimitHeaders(rate),
      });
    }

    const parsedPayload = stellarSubmitSignedRequestSchema.safeParse(
      bodyResult.data,
    );

    if (!parsedPayload.success) {
      logValidationFailure(
        "Submit signed validation failed",
        { ...context, userId },
        parsedPayload.error,
        bodyResult.data,
      );
      return respond(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 400,
        body: {
          error: "Invalid signed transaction submission.",
          details: toPublicValidationDetails(parsedPayload.error),
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const payload = parsedPayload.data;
    const receipt = payload.decisionReceipt;
    const signedXdr = payload.signedXdr;

    const wallet = await getUserWallet(userId);
    const walletRecord = wallet && !("expired" in wallet) ? wallet : null;

    // Receipt-bound submissions must be signed by the session wallet and must
    // match the authorized decision exactly before anything is submitted.
    if (receipt) {
      if (!walletRecord) {
        logWarn("Submit signed route missing wallet mapping", { ...context, userId });
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 401,
          body: {
            error: "No session wallet mapping found for this account.",
            code: "NO_SESSION_WALLET",
          },
          headers: rateLimitHeaders(rate),
        });
      }

      const sourceResult = decodeSignedXdrSourceAccount(signedXdr);
      if (!sourceResult.ok) {
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 400,
          body: {
            error:
              "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
          },
          headers: rateLimitHeaders(rate),
        });
      }

      if (sourceResult.sourceAccount !== walletRecord.publicKey) {
        logWarn("Submit signed source wallet mismatch", { ...context, userId });
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 403,
          body: {
            error:
              "Signed transaction source account does not match your session wallet.",
            code: "SOURCE_WALLET_MISMATCH",
          },
          headers: rateLimitHeaders(rate),
        });
      }

      const receiptCheck = verifySignedXdrMatchesDecisionReceipt(
        signedXdr,
        receipt,
      );
      if (!receiptCheck.ok) {
        logWarn("Submit signed receipt mismatch", { ...context, userId });
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: receiptCheck.status ?? 403,
          body: {
            error: receiptCheck.error,
            ...(receiptCheck.field ? { field: receiptCheck.field } : {}),
            receiptHash: (receipt as { receiptHash?: string }).receiptHash,
          },
          headers: rateLimitHeaders(rate),
        });
      }
    }

    // Signed-build submissions bind the signed XDR to the decision and quote
    // that the build endpoint authorized before the wallet signed it.
    if (
      payload.decisionId &&
      payload.quoteExpiresAt &&
      payload.buildAuthorization
    ) {
      const transactionHash = getTransactionHash(
        signedXdr,
        assertStellarNetworkConfig().networkPassphrase,
      );
      const authorized = verifyBuildAuthorization(payload.buildAuthorization, {
        userId,
        decisionId: payload.decisionId,
        quoteExpiresAt: payload.quoteExpiresAt,
        transactionHash,
      });
      if (!authorized) {
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 403,
          body: {
            error: "Signed transaction does not match the authorized payment build.",
          },
          headers: rateLimitHeaders(rate),
        });
      }

      const auditEntry = await getAuditEntryById(userId, payload.decisionId);
      if (
        !isPaymentDecisionCurrent(
          auditEntry,
          payload.decisionId,
          payload.quoteExpiresAt,
        )
      ) {
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 403,
          body: {
            error:
              "Payment decision or quote is no longer valid. Please re-evaluate the action.",
          },
          headers: rateLimitHeaders(rate),
        });
      }
    }

    // Legacy audit-entry submissions are authorized against the stored quote.
    if (payload.auditEntryId) {
      const details = decodePaymentDetails(signedXdr);
      if (!details) {
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 400,
          body: {
            error:
              "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
          },
          headers: rateLimitHeaders(rate),
        });
      }

      const auditEntry = await getAuditEntryById(userId, payload.auditEntryId);
      const authorization = verifyPaymentAgainstQuote(auditEntry, {
        ...details,
        requestTimestampMs: Date.now(),
      });
      if (!authorization.ok) {
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: authorization.status,
          body: {
            error: authorization.error,
            ...(authorization.field ? { field: authorization.field } : {}),
          },
          headers: rateLimitHeaders(rate),
        });
      }
    }

    const headerKey = request.headers.get("idempotency-key")?.trim();
    const bodyKey = payload.idempotencyKey?.trim();
    const mergedIdempotencyKey =
      headerKey && headerKey.length > 0 ? headerKey : bodyKey;

    let idempotencyKey: string | undefined;
    if (mergedIdempotencyKey) {
      const idempotencyValidation = validateIdempotencyKey(mergedIdempotencyKey);
      if (!idempotencyValidation.ok) {
        logWarn("Submit signed invalid idempotency key", { ...context, userId });
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 400,
          body: {
            error: idempotencyValidation.error,
            details: {
              fieldErrors: { idempotencyKey: [idempotencyValidation.error] },
            },
          },
          headers: rateLimitHeaders(rate),
        });
      }
      idempotencyKey = idempotencyValidation.key;
    }

    const requestHash = idempotencyKey
      ? hashCanonicalPaymentBody(idempotencyKey, payload)
      : null;

    let claimed: { key: string; requestHash: string } | null = null;

    if (idempotencyKey && requestHash) {
      const resolution = await beginIdempotentSubmit(
        userId,
        idempotencyKey,
        requestHash,
        { inFlightWaitMs: getIdempotencyInFlightWaitMs() },
      );

      if (resolution.outcome === "replay") {
        logInfo("Signed transaction idempotent replay", {
          ...context,
          userId,
          idempotencyKey,
          transactionHash: resolution.record.transactionId,
        });
        recordStellarSubmitResult("idempotency_replay");
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: resolution.record.statusCode ?? 200,
          body: resolution.record.result,
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "true",
          },
        });
      }

      if (resolution.outcome === "conflict") {
        logWarn("Signed transaction idempotency conflict", {
          ...context,
          userId,
          idempotencyKey,
        });
        recordStellarSubmitResult("idempotency_conflict");
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 409,
          body: {
            error:
              "Idempotency-Key was already used with a different signed transaction.",
          },
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "false",
            "Retry-After": "1",
          },
        });
      }

      if (resolution.outcome === "in_flight") {
        logWarn("Signed transaction idempotency in flight", {
          ...context,
          userId,
          idempotencyKey,
        });
        return respond(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 409,
          body: {
            error:
              "A payment with this Idempotency-Key is already in flight.",
            code: "idempotency_in_flight",
          },
          headers: {
            ...rateLimitHeaders(rate),
            "Retry-After": "1",
          },
        });
      }

      claimed = { key: idempotencyKey, requestHash };
    }

    let submitted: Awaited<ReturnType<typeof submitSignedTransactionXdr>>;
    try {
      submitted = await submitSignedTransactionXdr(signedXdr);
    } catch (error) {
      if (claimed) {
        await abortIdempotentSubmit(userId, claimed.key, claimed.requestHash).catch(
          () => undefined,
        );
      }
      throw error;
    }

    logInfo("Signed transaction submitted", {
      ...context,
      userId,
      txHash: submitted.hash,
      ledger: submitted.ledger,
    });

    recordStellarSubmitResult("success");

    const responseBody = {
      ok: true,
      userId,
      transactionHash: submitted.hash,
      payment: {
        mode: "real",
        ...submitted,
      },
      explorerUrl: getStellarExplorerTransactionUrl(submitted.hash),
    };

    if (claimed) {
      // The payment is on the ledger. If settling the claim fails, leave the
      // in-flight record in place rather than releasing the key for a second
      // payment, and still return the real accepted result to the client.
      await completeIdempotentSubmit(userId, claimed.key, claimed.requestHash, {
        statusCode: 200,
        transactionId: submitted.hash,
        result: responseBody,
      }).catch(() => undefined);
    }

    return respond(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 200,
      body: responseBody,
      headers: claimed
        ? { ...rateLimitHeaders(rate), "Idempotency-Replayed": "false" }
        : rateLimitHeaders(rate),
    });
  } catch (error) {
    const formatted = formatSubmitError(error);
    const category = normalizeHorizonError(formatted.txCode);

    logError(
      "Submit signed internal error",
      redactSensitiveFields({
        ...context,
        detail: formatted.message,
        horizonCategory: category,
      }),
    );
    recordStellarSubmitResult("horizon_failure");

    return respond(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 500,
      body: {
        error: formatted.message,
        category,
        resultCode: formatted.txCode,
        operationCodes: formatted.opCodes,
        explanation: formatted.explanation,
        nextStep: formatted.nextStep,
        rawError: formatted,
      },
      headers: rateLimitHeaders(rate),
    });
  }
}
