import { StrKey } from "@stellar/stellar-sdk";

import { isValidWalletPublicKey, normalizeWalletPublicKey } from "@/lib/auth/wallet-role";

/**
 * Full Stellar account validation: base32 payload, version byte, and CRC16
 * checksum. The shape regex alone accepts a 56-character key with a corrupted
 * body, so it is only a cheap pre-check before StrKey decodes the account.
 */
export function isValidStellarAccount(publicKey: unknown): publicKey is string {
  if (typeof publicKey !== "string" || !isValidWalletPublicKey(publicKey)) {
    return false;
  }

  return StrKey.isValidEd25519PublicKey(normalizeWalletPublicKey(publicKey));
}
