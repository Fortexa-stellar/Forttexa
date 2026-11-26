import { createHash, randomBytes, randomUUID } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";

import { normalizeWalletPublicKey } from "@/lib/auth/wallet-role";
import {
  clearSharedChallenges,
  deleteSharedChallenge,
  readSharedChallenge,
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

const challenges = new Map<string, StoredChallenge>();
const challengeVerificationLocks = new Map<string, Promise<void>>();
const consumedLoginSignatures = new Set<string>();
const consumedChallengeIds = new Set<string>();

async function withChallengeVerificationLock<T>(challengeId: string, operation: () => Promise<T>): Promise<T> {
  const previous = challengeVerificationLocks.get(challengeId) ?? Promise.resolve();
  let release: (() => void) | undefined;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });

  challengeVerificationLocks.set(challengeId, previous.then(() => current));
  await previous;

  try {
    return await operation();
  } finally {
    release?.();
    if (challengeVerificationLocks.get(challengeId) === current) {
      challengeVerificationLocks.delete(challengeId);
    }
  }
}

/**
 * Whether a challenge is expired at `nowMs`.
 *
 * Expiry is inclusive: `expiresAtMs` is the first instant the challenge is invalid.
 */
export function isChallengeExpired(expiresAtMs: number, nowMs: number = Date.now()) {
  return expiresAtMs <= nowMs;
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
    return Object.values(value as Record<string, unknown>).some((item) => isLoginAuthorizationPayload(item));
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

export function verifyWalletSignature(publicKey: string, message: string, signatureBase64: string) {
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

async function readChallenge(challengeId: string): Promise<StoredChallenge | undefined> {
  const shared = await readSharedChallenge(challengeId);
  if (shared) {
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

  return challenges.get(challengeId);
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

async function removeChallenge(challengeId: string) {
  await deleteSharedChallenge(challengeId);
  challenges.delete(challengeId);
}

type ChallengeClock = () => number;

export async function createWalletChallenge(
  publicKey: string,
  optionsOrClock?: { origin?: string; nonce?: string } | ChallengeClock,
): Promise<WalletChallengeRecord> {
  const clock: ChallengeClock =
    typeof optionsOrClock === "function" ? optionsOrClock : () => Date.now();
  const options =
    typeof optionsOrClock === "function" ? undefined : optionsOrClock;
  const normalizedKey = normalizeWalletPublicKey(publicKey);
  const challengeId = randomUUID();
  const expiresAtMs = clock() + getChallengeTtlSeconds() * 1000;
  const origin = options?.origin?.trim() || DEFAULT_LOGIN_ORIGIN;
  const nonce = options?.nonce?.trim() || randomBytes(16).toString("hex");
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
  | { ok: false; code: "missing" | "expired" | "replayed" | "wallet_mismatch" | "invalid_signature" };

export async function verifyWalletChallenge(
  input: {
    challengeId: string;
    publicKey: string;
    signature: string;
    message?: string;
  },
  clock?: ChallengeClock,
): Promise<ChallengeVerificationResult> {
  const nowMs = clock ? clock() : Date.now();
  return withChallengeVerificationLock(input.challengeId, async () => {
    const normalizedKey = normalizeWalletPublicKey(input.publicKey);
    const challenge = await readChallenge(input.challengeId);

    if (!challenge) {
      return {
        ok: false,
        code: consumedChallengeIds.has(input.challengeId) ? "replayed" : "missing",
      };
    }

    if (isChallengeExpired(challenge.expiresAtMs, nowMs)) {
      await removeChallenge(input.challengeId);
      return { ok: false, code: "expired" };
    }

    if (challenge.publicKey !== normalizedKey) {
      await removeChallenge(input.challengeId);
      return { ok: false, code: "wallet_mismatch" };
    }

    if (challenge.consumed) {
      await removeChallenge(input.challengeId);
      return { ok: false, code: "missing" };
    }

    const messageMatches = input.message === undefined || input.message === challenge.message;
    const signatureValid =
      messageMatches && verifyWalletSignature(normalizedKey, challenge.message, input.signature);
    // A challenge is single-use: remove it on every terminal outcome so a
    // replay reports it as missing rather than consuming it twice.
    await removeChallenge(input.challengeId);

    if (!signatureValid) {
      return { ok: false, code: "invalid_signature" };
    }

    consumedChallengeIds.add(challenge.id);
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
  consumedChallengeIds.clear();
  await clearSharedChallenges();
}
