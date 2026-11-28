import { randomUUID } from "node:crypto";

import {
  Account,
  Asset,
  Keypair,
  Memo,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";

import { createBuildAuthorization } from "@/lib/stellar/payment-build-authorization";
import { buildPaymentQuoteFromDecision } from "@/lib/stellar/verify-payment-quote";
import type { AuditEntry, DecisionType, PaymentQuote } from "@/lib/types/domain";

/** Request body the console sends to `POST /api/stellar/submit-signed`. */
export type ConsoleSubmitBody = {
  signedXdr: string;
  decisionId: string;
  quoteExpiresAt: string;
  buildAuthorization: string;
  idempotencyKey?: string;
  decisionReceipt?: PaymentQuote;
};

export type AuthorizedSubmission = {
  /** The decision the server stored when it approved the payment. */
  auditEntry: AuditEntry;
  /** The quote stored on that decision (also what the build response echoes). */
  quote: PaymentQuote;
  signedXdr: string;
  /** Exactly the fields the console submits: no `decisionReceipt`. */
  body: ConsoleSubmitBody;
};

export type AuthorizedSubmissionOptions = {
  userId: string;
  /** Signs the transaction and is its source account. */
  signer: Keypair;
  destination?: string;
  /** Amount in XLM, as the quote and the transaction both carry it. */
  amount?: string;
  memo?: string;
  decision?: DecisionType;
  /** How long from now the stored quote stays valid. Negative = already expired. */
  expiresInMs?: number;
  decisionId?: string;
  /** Overrides what the *transaction* pays, leaving the stored quote unchanged. */
  transactionAmount?: string;
  transactionDestination?: string;
};

/**
 * Builds an approved decision plus a signed transaction and the request body
 * the console would send for it, mirroring what `build-payment` hands out.
 */
export function makeAuthorizedSubmission(
  options: AuthorizedSubmissionOptions,
): AuthorizedSubmission {
  const destination = options.destination ?? Keypair.random().publicKey();
  const amount = options.amount ?? "1.0000000";
  const decisionId = options.decisionId ?? randomUUID();
  const nowMs = Date.now();

  const baseQuote = buildPaymentQuoteFromDecision({
    destination,
    amountXLM: Number(amount),
    memo: options.memo ?? "fortexa:act-1",
    actionId: "act-1",
    nowMs,
  });
  const quote: PaymentQuote =
    options.expiresInMs === undefined
      ? baseQuote
      : { ...baseQuote, expiresAt: new Date(nowMs + options.expiresInMs).toISOString() };

  const auditEntry: AuditEntry = {
    id: decisionId,
    timestamp: new Date(nowMs).toISOString(),
    action: {
      id: "act-1",
      name: "Test payment",
      kind: "api_payment",
      target: "svc:endpoint",
      domain: "api.example.com",
      amountXLM: Number(amount),
    },
    decision: options.decision ?? "APPROVE",
    explanation: "Approved",
    triggeredPolicies: [],
    riskFindings: [],
    paymentQuote: quote,
  };

  const transaction = new TransactionBuilder(new Account(options.signer.publicKey(), "1"), {
    fee: "100",
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(
      Operation.payment({
        destination: options.transactionDestination ?? destination,
        asset: Asset.native(),
        amount: options.transactionAmount ?? amount,
      }),
    )
    .addMemo(Memo.text(quote.memo))
    .setTimeout(300)
    .build();
  transaction.sign(options.signer);

  const signedXdr = transaction.toXDR();

  return {
    auditEntry,
    quote,
    signedXdr,
    body: {
      signedXdr,
      decisionId,
      quoteExpiresAt: quote.expiresAt as string,
      buildAuthorization: createBuildAuthorization({
        userId: options.userId,
        decisionId,
        quoteExpiresAt: quote.expiresAt as string,
        transactionHash: transaction.hash().toString("hex"),
      }),
    },
  };
}
