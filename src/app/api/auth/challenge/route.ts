import { NextRequest } from "next/server";
import { z } from "zod";

import { isValidStellarAccount } from "@/lib/auth/stellar-account";
import { createWalletChallenge, InvalidWalletPublicKeyError } from "@/lib/auth/wallet-challenge";
import { readJsonBody } from "@/lib/http/read-json-body";
import { jsonWithRequestContext } from "@/lib/observability/http";
import { getRequestLogContext, logError, logInfo, logWarn } from "@/lib/observability/logger";
import { consumeRateLimit, rateLimitHeaders } from "@/lib/security/rate-limit";

const challengeSchema = z.object({
  publicKey: z.string().min(1),
});

// One stable response for every malformed wallet. It deliberately carries no
// field details and never repeats the submitted value.
const INVALID_WALLET_BODY = {
  error: "Invalid wallet public key.",
  code: "invalid_wallet_public_key",
} as const;

export async function POST(request: NextRequest) {
  const startedAtMs = Date.now();
  const context = getRequestLogContext(request, "/api/auth/challenge");

  const rate = await consumeRateLimit(request, {
    key: "auth-challenge",
    limit: 30,
    windowMs: 60_000,
  });

  if (!rate.ok) {
    logWarn("Auth challenge rate limited", context);
    return jsonWithRequestContext(request, {
      route: "/api/auth/challenge",
      startedAtMs,
      status: 429,
      body: { error: "Too many challenge requests. Try again later.", code: "rate_limited" },
      headers: rateLimitHeaders(rate),
      noStore: true,
    });
  }

  try {
    const body = await readJsonBody(request);
    if (!body.ok) {
      return jsonWithRequestContext(request, {
        route: "/api/auth/challenge",
        startedAtMs,
        status: 413,
        body: { error: body.error, code: "payload_too_large" },
        headers: rateLimitHeaders(rate),
        noStore: true,
      });
    }
    const parsed = challengeSchema.safeParse(body.data);

    if (!parsed.success || !isValidStellarAccount(parsed.data.publicKey)) {
      // Log the reason only: a malformed identifier must not reach logs or the
      // response, and it must not reach the challenge store either.
      logWarn("Auth challenge rejected invalid wallet", {
        ...context,
        reason: "invalid_wallet_public_key",
      });
      return jsonWithRequestContext(request, {
        route: "/api/auth/challenge",
        startedAtMs,
        status: 400,
        body: INVALID_WALLET_BODY,
        headers: rateLimitHeaders(rate),
        noStore: true,
      });
    }

    const challenge = await createWalletChallenge(parsed.data.publicKey);

    logInfo("Auth challenge created", {
      ...context,
      wallet: challenge.publicKey,
      challengeId: challenge.id,
    });

    return jsonWithRequestContext(request, {
      route: "/api/auth/challenge",
      startedAtMs,
      status: 200,
      body: {
        challengeId: challenge.id,
        message: challenge.message,
        publicKey: challenge.publicKey,
        expiresAt: new Date(challenge.expiresAtMs).toISOString(),
      },
      headers: rateLimitHeaders(rate),
      noStore: true,
    });
  } catch (error) {
    if (error instanceof InvalidWalletPublicKeyError) {
      return jsonWithRequestContext(request, {
        route: "/api/auth/challenge",
        startedAtMs,
        status: 400,
        body: INVALID_WALLET_BODY,
        headers: rateLimitHeaders(rate),
        noStore: true,
      });
    }

    logError("Auth challenge internal error", {
      ...context,
      detail: error instanceof Error ? error.message : "unknown",
    });
    return jsonWithRequestContext(request, {
      route: "/api/auth/challenge",
      startedAtMs,
      status: 500,
      body: { error: "Challenge creation failed.", code: "internal_error" },
      headers: rateLimitHeaders(rate),
      noStore: true,
    });
  }
}
