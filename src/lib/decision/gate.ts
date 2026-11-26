import { isUserWalletRevoked } from "@/lib/storage/user-wallet-store";

/** A revoked wallet binding cannot authorize another decision. */
export async function canPassDecisionGate(userId: string): Promise<boolean> {
  return !(await isUserWalletRevoked(userId));
}
