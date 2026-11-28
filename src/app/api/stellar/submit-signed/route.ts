import { NextRequest } from "next/server";

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
import { redactSensitiveFields } from "@/lib/observability/redact";
import { getProtectedPaymentFlowReadinessReport } from "@/lib/readiness/production";
import {
  enforceRequestGate,
  gateErrorHeaders,
} from "@/lib/security/enforcement-gate";
import { rateLimitHeaders } from "@/lib/security/rate-limit";
import {
  decodeSignedXdrSourceAccount,
  submitSignedTransactionXdr,
  verifySignedXdrSigner,
} from "@/lib/stellar/client";
import { getStellarExplorerTransactionUrl } from "@/lib/stellar/network";
import { assertStellarNetworkConfig } from "@/lib/stellar/network-config";
import {
  getTransactionHash,
  verifyBuildAuthorization,
} from "@/lib/stellar/payment-build-authorization";
import {
  isPaymentDecisionCurrent,
  validateDecisionReceipt,
  verifySignedPaymentAgainstQuote,
} from "@/lib/stellar/verify-payment-quote";
import { getAuditEntryById } from "@/lib/storage/audit-store";
import {
  abortIdempotentSubmit,
  beginIdempotentSubmit,
  completeIdempotentSubmit,
  getIdempotencyInFlightWaitMs,
  hashCanonicalPaymentBody,
  maybeRunCleanup,
} from "@/lib/storage/submit-idempotency-store";
import { getUserWallet } from "@/lib/storage/user-wallet-store";
import type { AuditEntry, PaymentQuote } from "@/lib/types/domain";
import { normalizeHorizonError } from "@/lib/utils/horizonErrors";
import {
  logValidationFailure,
  toPublicValidationDetails,
} from "@/lib/validation/errors";
import {
  stellarSubmitSignedRequestSchema,
  validateIdempotencyKey,
} from "@/lib/validation/schemas";
import { buildUnknownFieldsBody } from "@/lib/validation/unknown-fields";

const ROUTE = "/api/stellar/submit-signed";

type HorizonErrorContext = {
  explanation: string;
  nextStep: string;
};

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

const DECISION_NO_LONGER_VALID =
  "Payment decision or quote is no longer valid. Please re-evaluate the action.";

/**
 * Checks an optional client-supplied decision receipt against the quote the
 * server stored when it approved the decision. The receipt is a convenience
 * echo: the stored quote is the authority, so a receipt that is malformed,
 * tampered with, or that disagrees with the stored quote is refused.
 */
function verifyReceiptMatchesStoredQuote(
  receipt: unknown,
  storedQuote: PaymentQuote,
):
  | { ok: true }
  | { ok: false; status: 400 | 403; error: string; field?: string; receiptHash?: string } {
  const validation = validateDecisionReceipt(receipt);
  if (!validation.ok) {
    return {
      ok: false,
      status: validation.status ?? 403,
      error: validation.error,
      field: validation.field,
    };
  }

  const claimed = validation.normalized;
  const receiptHash = claimed.receiptHash;
  const mismatch = (field: string, label: string) => ({
    ok: false as const,
    status: 403 as const,
    error: `Decision receipt ${label} does not match the authorized payment decision.`,
    field,
    receiptHash,
  });

  if (claimed.destination !== storedQuote.destination.trim().toUpperCase()) {
    return mismatch("destination", "destination");
  }
  if (claimed.amountXLM !== storedQuote.amountXLM) {
    return mismatch("amountXLM", "amount");
  }
  if (claimed.asset !== storedQuote.asset) {
    return mismatch("asset", "asset");
  }
  if (claimed.memo !== storedQuote.memo) {
    return mismatch("memo", "memo");
  }
  if (claimed.network !== storedQuote.network) {
    return mismatch("network", "network");
  }

  return { ok: true };
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
  const context = getRequestLogContext(request, ROUTE);
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
      route: ROUTE,
      startedAtMs,
      status: 415,
      body: { error: contentTypeCheck.error, code: "UNSUPPORTED_MEDIA_TYPE" },
    });
  }

  // Read the body before the gate so the signed transaction's destination can
  // be blocklist-checked in the same atomic enforcement step as the
  // rate-limit consumption (issue #202).
  const bodyResult = await readJsonBody(request);

  let gateDestination: string | undefined;
  if (bodyResult.ok) {
    const signedXdr = (bodyResult.data as { signedXdr?: unknown } | null)?.signedXdr;
    if (typeof signedXdr === "string") {
      // Best effort: a malformed envelope reports no destination here and is
      // rejected with the route's normal 400 further down.
      try {
        const preview = decodeSignedXdrSourceAccount(signedXdr);
        gateDestination = preview.ok ? preview.payment?.destination : undefined;
      } catch {
        gateDestination = undefined;
      }
    }
  }

  const gate = await enforceRequestGate(request, {
    rateLimitKey: "stellar-submit-signed",
    limit: 30,
    windowMs: 60_000,
    destination: gateDestination,
  });

  if (!gate.ok) {
    logWarn("Submit signed route denied by enforcement gate", {
      ...context,
      code: gate.code,
    });
    return respond(request, {
      route: ROUTE,
      startedAtMs,
      status: gate.status,
      body: { error: gate.error, code: gate.code },
      headers: gateErrorHeaders(gate),
    });
  }

  const rate = gate.rate;

  // A wallet login signature must never double as authorization to move funds.
  if (bodyResult.ok && isLoginAuthorizationPayload(bodyResult.data)) {
    logWarn("Submit signed rejected login payload", { ...context, code: "login_payload" });
    return respond(request, {
      route: ROUTE,
      startedAtMs,
      status: 400,
      body: { error: "Login signatures cannot authorize a signed transaction submission." },
      headers: rateLimitHeaders(rate),
    });
  }

  maybeRunCleanup();

  // Set once this request owns an idempotency claim, so a failure can release it.
  let claimedIdempotency:
    | { userId: string; key: string; requestHash: string; settled: boolean }
    | undefined;

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
        route: ROUTE,
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

    if (!bodyResult.ok) {
      requestBodyTooLarge = true;
      logWarn("Submit signed payload too large", { ...context, userId });
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 413,
        body: { error: bodyResult.error },
        headers: rateLimitHeaders(rate),
      });
    }

    requestBody = bodyResult.data;

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
      recordStellarSubmitResult("validation_failure");
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 400,
        body:
          buildUnknownFieldsBody(parsedPayload.error, "Invalid signed transaction payload.") ?? {
            error: "Invalid signed transaction payload.",
            details: toPublicValidationDetails(parsedPayload.error),
          },
        headers: rateLimitHeaders(rate),
      });
    }

    const payload = parsedPayload.data;

    const sessionWallet = auth.session.publicKey;
    if (!sessionWallet) {
      logWarn("Submit signed missing session wallet key", { ...context, userId });
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 401,
        body: { error: "Session missing wallet key." },
        headers: rateLimitHeaders(rate),
      });
    }

    const assignedWallet = await getUserWallet(userId);

    if (assignedWallet && "expired" in assignedWallet) {
      logWarn("Submit signed wallet expired", { ...context, userId });
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 401,
        body: { error: "Session wallet mapping has expired." },
        headers: rateLimitHeaders(rate),
      });
    }

    if (!assignedWallet) {
      logWarn("Submit signed missing wallet mapping", { ...context, userId });
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 401,
        body: { error: "No session wallet mapping found for this user." },
        headers: rateLimitHeaders(rate),
      });
    }

    const xdrSourceResult = decodeSignedXdrSourceAccount(payload.signedXdr);

    if (!xdrSourceResult.ok) {
      logWarn("Submit signed XDR malformed", { ...context, userId });
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 400,
        body: {
          error:
            "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    // The persisted decision is the authority: it must exist, still authorize
    // execution, and still carry the expiry the build step handed out.
    const auditEntry = await getAuditEntryById(userId, payload.decisionId);
    if (
      !isPaymentDecisionCurrent(auditEntry, payload.decisionId, payload.quoteExpiresAt)
    ) {
      logWarn("Submit signed decision no longer current", { ...context, userId });
      recordStellarSubmitResult("validation_failure");
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 403,
        body: { error: DECISION_NO_LONGER_VALID },
        headers: rateLimitHeaders(rate),
      });
    }

    // The build token binds user, decision, quote expiry and the exact
    // transaction hash, so a different transaction cannot ride on it.
    let transactionHash: string;
    try {
      transactionHash = getTransactionHash(
        payload.signedXdr,
        assertStellarNetworkConfig().networkPassphrase,
      );
    } catch {
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 400,
        body: {
          error:
            "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    if (
      !verifyBuildAuthorization(payload.buildAuthorization, {
        userId,
        decisionId: payload.decisionId,
        quoteExpiresAt: payload.quoteExpiresAt,
        transactionHash,
      })
    ) {
      logWarn("Submit signed build authorization mismatch", { ...context, userId });
      recordStellarSubmitResult("validation_failure");
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 403,
        body: { error: "Signed transaction does not match the authorized payment build." },
        headers: rateLimitHeaders(rate),
      });
    }

    // Validate the signed transaction against the quote the server approved
    // (destination, asset, exact amount, memo, single payment operation). This
    // does not depend on anything the client echoes back.
    const quoteCheck = verifySignedPaymentAgainstQuote(auditEntry as AuditEntry, payload.signedXdr);
    if (!quoteCheck.ok) {
      logWarn("Submit signed XDR disagrees with the approved quote", {
        ...context,
        userId,
        field: quoteCheck.field,
      });
      recordStellarSubmitResult("validation_failure");
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: quoteCheck.status,
        body: { error: quoteCheck.error, field: quoteCheck.field },
        headers: rateLimitHeaders(rate),
      });
    }

    if (payload.decisionReceipt !== undefined) {
      const receiptCheck = verifyReceiptMatchesStoredQuote(
        payload.decisionReceipt,
        quoteCheck.quote,
      );
      if (!receiptCheck.ok) {
        logWarn("Submit signed receipt disagrees with the approved quote", {
          ...context,
          userId,
          field: receiptCheck.field,
        });
        recordStellarSubmitResult("validation_failure");
        return respond(request, {
          route: ROUTE,
          startedAtMs,
          status: receiptCheck.status,
          body: {
            error: receiptCheck.error,
            field: receiptCheck.field,
            receiptHash: receiptCheck.receiptHash,
          },
          headers: rateLimitHeaders(rate),
        });
      }
    }

    if (xdrSourceResult.sourceAccount !== assignedWallet.publicKey) {
      logWarn("Submit signed source wallet mismatch", {
        ...context,
        userId,
        expectedWallet: sessionWallet,
        actualSource: xdrSourceResult.sourceAccount,
      });
      recordStellarSubmitResult("source_wallet_mismatch");
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 403,
        body: {
          error:
            "Signed transaction source account does not match your session wallet.",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    if (!verifySignedXdrSigner(payload.signedXdr, sessionWallet)) {
      logWarn("Submit signed signer wallet mismatch", {
        ...context,
        userId,
        expectedWallet: sessionWallet,
      });
      recordStellarSubmitResult("signer_wallet_mismatch");
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 403,
        body: {
          error: "Signed transaction signer does not match your session wallet.",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const headerKey = request.headers.get("idempotency-key")?.trim();
    const bodyKey = payload.idempotencyKey?.trim();
    const suppliedKey = headerKey && headerKey.length > 0 ? headerKey : bodyKey;

    let idempotencyKey: string | undefined;
    if (suppliedKey) {
      const keyValidation = validateIdempotencyKey(suppliedKey);
      if (!keyValidation.ok) {
        logWarn("Submit signed invalid idempotency key", { ...context, userId });
        return respond(request, {
          route: ROUTE,
          startedAtMs,
          status: 400,
          body: { error: keyValidation.error },
          headers: rateLimitHeaders(rate),
        });
      }
      idempotencyKey = keyValidation.key;
    }

    if (idempotencyKey) {
      // Identity of the request is the hash of the key plus the canonical
      // body, so the store and this route can never disagree about what "the
      // same request" means.
      const requestHash = hashCanonicalPaymentBody(idempotencyKey, payload);
      const claim = await beginIdempotentSubmit(userId, idempotencyKey, requestHash, {
        inFlightWaitMs: getIdempotencyInFlightWaitMs(),
      });

      if (claim.outcome === "conflict") {
        logWarn("Signed transaction idempotency conflict", {
          ...context,
          userId,
          idempotencyKey,
        });
        recordStellarSubmitResult("idempotency_conflict");
        return respond(request, {
          route: ROUTE,
          startedAtMs,
          status: 409,
          body: {
            error:
              "Idempotency-Key was already used with a different signed transaction.",
          },
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "false",
          },
        });
      }

      if (claim.outcome === "in_flight") {
        logWarn("Signed transaction idempotency still in flight", {
          ...context,
          userId,
          idempotencyKey,
        });
        return respond(request, {
          route: ROUTE,
          startedAtMs,
          status: 409,
          body: {
            error:
              "An identical request with this Idempotency-Key is still being processed. Retry shortly.",
            code: "idempotency_in_flight",
          },
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "false",
            "Retry-After": "1",
          },
        });
      }

      if (claim.outcome === "replay") {
        logInfo("Signed transaction idempotent replay", {
          ...context,
          userId,
          idempotencyKey,
          transactionHash: claim.record.transactionId,
        });
        recordStellarSubmitResult("idempotency_replay");
        return respond(request, {
          route: ROUTE,
          startedAtMs,
          status: claim.record.statusCode ?? 200,
          body: claim.record.result,
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "true",
          },
        });
      }

      claimedIdempotency = { userId, key: idempotencyKey, requestHash, settled: false };
    }

    // The idempotency claim can take time; check the persisted authorization
    // again at the last point before the external submission.
    const currentDecision = await getAuditEntryById(userId, payload.decisionId);
    if (
      !isPaymentDecisionCurrent(currentDecision, payload.decisionId, payload.quoteExpiresAt)
    ) {
      recordStellarSubmitResult("validation_failure");
      if (claimedIdempotency) {
        await abortIdempotentSubmit(
          claimedIdempotency.userId,
          claimedIdempotency.key,
          claimedIdempotency.requestHash,
        ).catch(() => undefined);
        claimedIdempotency = undefined;
      }
      return respond(request, {
        route: ROUTE,
        startedAtMs,
        status: 403,
        body: { error: DECISION_NO_LONGER_VALID },
        headers: rateLimitHeaders(rate),
      });
    }

    const submitted = await submitSignedTransactionXdr(payload.signedXdr);

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

    if (claimedIdempotency) {
      try {
        await completeIdempotentSubmit(
          claimedIdempotency.userId,
          claimedIdempotency.key,
          claimedIdempotency.requestHash,
          { statusCode: 200, transactionId: submitted.hash, result: responseBody },
        );
        claimedIdempotency.settled = true;
      } catch (settleError) {
        // The transaction is on the ledger. Return its real result rather than
        // an error that would invite a blind resubmit, and leave the claim in
        // flight: releasing it would hand the next caller a clean key for a
        // second payment.
        claimedIdempotency.settled = true;
        logError("Submit signed could not store the idempotent outcome", {
          ...context,
          userId,
          detail: settleError instanceof Error ? settleError.message : "unknown",
        });
      }
    }

    return respond(request, {
      route: ROUTE,
      startedAtMs,
      status: 200,
      body: responseBody,
      headers: idempotencyKey
        ? { ...rateLimitHeaders(rate), "Idempotency-Replayed": "false" }
        : rateLimitHeaders(rate),
    });
  } catch (error) {
    // A failed submit releases the claim so the client can retry safely.
    if (claimedIdempotency && !claimedIdempotency.settled) {
      await abortIdempotentSubmit(
        claimedIdempotency.userId,
        claimedIdempotency.key,
        claimedIdempotency.requestHash,
      ).catch(() => undefined);
    }

    const formatted = formatSubmitError(error);
    const category = normalizeHorizonError(formatted.txCode);
    // #205: formatSubmitError embeds raw Horizon error.message (which can carry
    // the signed XDR envelope, destination addresses, or memo values) into
    // formatted.message. Pass the log detail through the shared observability
    // redactor so secrets, signed XDR, and payment metadata never reach logs.
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
      route: ROUTE,
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
