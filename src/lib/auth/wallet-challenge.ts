import { createHash, randomBytes, randomUUID } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";

import { isValidStellarAccount } from "@/lib/auth/stellar-account";
import { normalizeWalletPublicKey } from "@/lib/auth/wallet-role";
import {
  clearSharedChallenges,
  isSharedSecurityStateEnabled,
  takeSharedChallenge,
  writeSharedChallenge,
} from "@/lib/security/shared-security-state";

const SEP53_PREFIX = "Stellar Signed Message:\n";
const DEFAULT_LOGIN_ORIGIN = "http://localhost";

export type WalletChallengeRecord = {
  id: string;
  publicKey: string;
  message: string;
  expiresAtMs: number;
  origin: string;
  nonce: string;
};

type StoredChallenge = WalletChallengeRecord & {
  consumed: boolean;
};

export type Clock = () => number;

export type WalletChallengeOptions = {
  origin?: string;
  nonce?: string;
  clock?: Clock;
};

/**
 * Raised when a wallet identifier is not a valid Stellar account before any
 * challenge or lockout state is written. The error carries no input value, so
 * it is safe to surface to a caller that only needs a stable error code.
 */
export class InvalidWalletPublicKeyError extends Error {
  readonly code = "invalid_wallet_public_key";

  constructor() {
    super("Invalid Stellar wallet public key.");
    this.name = "InvalidWalletPublicKeyError";
  }
}

const challenges = new Map<string, StoredChallenge>();
const challengeVerificationLocks = new Map<string, Promise<void>>();
const consumedLoginSignatures = new Set<string>();

async function withChallengeVerificationLock<T>(
  challengeId: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = challengeVerificationLocks.get(challengeId) ?? Promise.resolve();
  let release: (() => void) | undefined;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });

  const queued = previous.then(() => current);
  challengeVerificationLocks.set(challengeId, queued);
  await previous;

  try {
    return await operation();
  } finally {
    release?.();
    if (challengeVerificationLocks.get(challengeId) === queued) {
      challengeVerificationLocks.delete(challengeId);
    }
  }
}

/**
 * Whether a challenge is expired at `nowMs`.
 *
 * Expiry is inclusive: `expiresAtMs` is the first instant the challenge is
 * invalid, not the last instant it is still valid. A challenge that lapses
 * while a wallet prompt is open therefore cannot authenticate.
 */
export function isChallengeExpired(expiresAtMs: number, nowMs: number = Date.now()) {
  return expiresAtMs <= nowMs;
}

function resolveClock(input?: Clock | { clock?: Clock }): Clock {
  if (typeof input === "function") {
    return input;
  }

  return input?.clock ?? (() => Date.now());
}

function getChallengeTtlSeconds() {
  const parsed = Number(process.env.FORTEXA_AUTH_CHALLENGE_TTL_SECONDS ?? 300);
  if (!Number.isFinite(parsed) || parsed < 30) {
    return 300;
  }
  return Math.floor(parsed);
}

export function buildChallengeMessage(input: {
  challengeId: string;
  publicKey: string;
  expiresAtMs: number;
  origin: string;
  nonce: string;
}) {
  const expiresAt = new Date(input.expiresAtMs).toISOString();
  return [
    "Fortexa wallet login",
    `Challenge: ${input.challengeId}`,
    `Wallet: ${input.publicKey}`,
    `Origin: ${input.origin}`,
    `Nonce: ${input.nonce}`,
    `Expires: ${expiresAt}`,
  ].join("\n");
}

export function isWalletLoginMessage(value: string) {
  return (
    value.startsWith("Fortexa wallet login\n") &&
    value.includes("\nOrigin: ") &&
    value.includes("\nNonce: ") &&
    value.includes("\nExpires: ")
  );
}

export function isLoginAuthorizationPayload(value: unknown): boolean {
  if (typeof value === "string") {
    return isWalletLoginMessage(value) || consumedLoginSignatures.has(value);
  }

  if (Array.isArray(value)) {
    return value.some((item) => isLoginAuthorizationPayload(item));
  }

  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some((item) =>
      isLoginAuthorizationPayload(item),
    );
  }

  return false;
}

export function hashSep53Message(message: string) {
  const payload = Buffer.concat([
    Buffer.from(SEP53_PREFIX, "utf8"),
    Buffer.from(message, "utf8"),
  ]);
  return createHash("sha256").update(payload).digest();
}

export function verifyWalletSignature(
  publicKey: string,
  message: string,
  signatureBase64: string,
) {
  try {
    const keypair = Keypair.fromPublicKey(normalizeWalletPublicKey(publicKey));
    const signature = Buffer.from(signatureBase64, "base64");
    if (signature.length !== 64) {
      return false;
    }

    return keypair.verify(hashSep53Message(message), signature);
  } catch {
    return false;
  }
}

function originFromMessage(message: string) {
  return message.match(/^Origin: (.+)$/m)?.[1] ?? DEFAULT_LOGIN_ORIGIN;
}

function nonceFromMessage(message: string) {
  return message.match(/^Nonce: (.+)$/m)?.[1] ?? "";
}

async function writeChallenge(record: StoredChallenge) {
  const ttlSeconds = Math.max(1, Math.ceil((record.expiresAtMs - Date.now()) / 1000));
  await writeSharedChallenge(
    record.id,
    {
      publicKey: record.publicKey,
      message: record.message,
      expiresAtMs: record.expiresAtMs,
      consumed: record.consumed,
    },
    ttlSeconds,
  );
  challenges.set(record.id, record);
}

/**
 * Removes a challenge from the in-memory and shared stores in one step, so a
 * challenge can be presented only once. A concurrent attempt sees it missing
 * rather than verifying the same signature twice.
 */
async function takeChallenge(challengeId: string): Promise<StoredChallenge | undefined> {
  if (isSharedSecurityStateEnabled()) {
    const shared = await takeSharedChallenge(challengeId);
    challenges.delete(challengeId);

    // Do not fall back to the local map here: a missing shared record means
    // another instance already claimed the challenge, and honouring a stale
    // process-local copy would allow a replay.
    if (!shared) {
      return undefined;
    }

    return {
      id: challengeId,
      publicKey: shared.publicKey,
      message: shared.message,
      expiresAtMs: shared.expiresAtMs,
      origin: originFromMessage(shared.message),
      nonce: nonceFromMessage(shared.message),
      consumed: shared.consumed,
    };
  }

  const record = challenges.get(challengeId);
  challenges.delete(challengeId);
  return record;
}

/**
 * Issues a login challenge bound to the wallet, origin, nonce, and expiry.
 *
 * The public key is validated as a Stellar Ed25519 account (base32 payload,
 * version byte, and checksum) before any identifier is generated or stored, so
 * a malformed wallet never consumes challenge storage or lockout state.
 */
export async function createWalletChallenge(
  publicKey: string,
  options?: WalletChallengeOptions | Clock,
): Promise<WalletChallengeRecord> {
  if (!isValidStellarAccount(publicKey)) {
    throw new InvalidWalletPublicKeyError();
  }

  const clock = resolveClock(options);
  const settings = typeof options === "function" ? undefined : options;
  const normalizedKey = normalizeWalletPublicKey(publicKey);
  const challengeId = randomUUID();
  const expiresAtMs = clock() + getChallengeTtlSeconds() * 1000;
  const origin = settings?.origin?.trim() || DEFAULT_LOGIN_ORIGIN;
  const nonce = settings?.nonce?.trim() || randomBytes(16).toString("hex");
  const message = buildChallengeMessage({
    challengeId,
    publicKey: normalizedKey,
    expiresAtMs,
    origin,
    nonce,
  });

  const record: StoredChallenge = {
    id: challengeId,
    publicKey: normalizedKey,
    message,
    expiresAtMs,
    origin,
    nonce,
    consumed: false,
  };

  await writeChallenge(record);

  return {
    id: record.id,
    publicKey: record.publicKey,
    message: record.message,
    expiresAtMs: record.expiresAtMs,
    origin: record.origin,
    nonce: record.nonce,
  };
}

export type ChallengeVerificationResult =
  | { ok: true; challenge: WalletChallengeRecord }
  | {
      ok: false;
      code: "missing" | "expired" | "replayed" | "wallet_mismatch" | "invalid_signature";
    };

export async function verifyWalletChallenge(
  input: {
    challengeId: string;
    publicKey: string;
    signature: string;
    message?: string;
  },
  clockInput?: Clock | { clock?: Clock },
): Promise<ChallengeVerificationResult> {
  return withChallengeVerificationLock(input.challengeId, async () => {
    const nowMs = resolveClock(clockInput)();
    const normalizedKey = normalizeWalletPublicKey(input.publicKey);
    const challenge = await takeChallenge(input.challengeId);

    if (!challenge) {
      return { ok: false, code: "missing" };
    }

    // The challenge is already removed: every attempt spends it, whether it
    // expired, was presented by the wrong wallet, or carried a bad signature.
    if (isChallengeExpired(challenge.expiresAtMs, nowMs)) {
      return { ok: false, code: "expired" };
    }

    if (challenge.publicKey !== normalizedKey) {
      return { ok: false, code: "wallet_mismatch" };
    }

    if (challenge.consumed) {
      return { ok: false, code: "replayed" };
    }

    const messageMatches = input.message === undefined || input.message === challenge.message;
    const signatureValid =
      messageMatches && verifyWalletSignature(normalizedKey, challenge.message, input.signature);

    if (!signatureValid) {
      return { ok: false, code: "invalid_signature" };
    }

    consumedLoginSignatures.add(input.signature);

    return {
      ok: true,
      challenge: {
        id: challenge.id,
        publicKey: challenge.publicKey,
        message: challenge.message,
        expiresAtMs: challenge.expiresAtMs,
        origin: challenge.origin,
        nonce: challenge.nonce,
      },
    };
  });
}

export async function resetWalletChallengeStore() {
  challenges.clear();
  consumedLoginSignatures.clear();
  await clearSharedChallenges();
}

/** Test-only view of the in-memory challenge count. */
export function walletChallengeStoreSize() {
  return challenges.size;
}
