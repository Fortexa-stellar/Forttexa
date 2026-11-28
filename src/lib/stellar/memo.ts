import { z } from "zod";

/**
 * Stellar limits a text memo to 28 bytes of UTF-8, not 28 characters. A
 * string of 15 two-byte characters is 15 long and 30 bytes, so a character
 * count lets it through and the SDK then refuses it while the transaction is
 * being built. Count the encoded bytes up front instead.
 *
 * Fortexa only builds text memos today, so text is the only entry. A new memo
 * type adds a row here and is then covered by every check below.
 */
export const MEMO_MAX_BYTES = {
  text: 28,
} as const;

export type MemoType = keyof typeof MEMO_MAX_BYTES;

/** Stable machine-readable code returned for an oversized memo. */
export const MEMO_TOO_LONG_CODE = "memo_too_long";

const encoder = new TextEncoder();

export function memoByteLength(memo: string): number {
  return encoder.encode(memo).length;
}

export function isMemoWithinByteLimit(memo: string, type: MemoType = "text"): boolean {
  return memoByteLength(memo) <= MEMO_MAX_BYTES[type];
}

export class MemoTooLongError extends Error {
  readonly code = MEMO_TOO_LONG_CODE;
  readonly maxBytes: number;
  readonly byteLength: number;

  // The memo text itself is free-form user content and is never put in the
  // message or the fields, so it cannot reach a log through this error.
  constructor(byteLength: number, maxBytes: number) {
    super(`Memo is ${byteLength} bytes; the limit is ${maxBytes} bytes.`);
    this.name = "MemoTooLongError";
    this.byteLength = byteLength;
    this.maxBytes = maxBytes;
  }
}

/** Throws {@link MemoTooLongError} when the memo exceeds the byte limit for its type. */
export function assertMemoWithinByteLimit(memo: string, type: MemoType = "text"): void {
  const byteLength = memoByteLength(memo);
  if (byteLength > MEMO_MAX_BYTES[type]) {
    throw new MemoTooLongError(byteLength, MEMO_MAX_BYTES[type]);
  }
}

/**
 * Zod rule for a text memo. The issue message is the stable code, so every
 * route that validates with it reports the same value in its field errors.
 */
export function withMemoByteLimit<T extends z.ZodString>(schema: T) {
  return schema.refine((memo) => isMemoWithinByteLimit(memo), { message: MEMO_TOO_LONG_CODE });
}
