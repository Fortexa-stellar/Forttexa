import { assertSafeSessionCookieConfig } from "@/lib/auth/session-cookie";
import { ensureDatabaseReady } from "@/lib/storage/db";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    assertSafeSessionCookieConfig();
    await ensureDatabaseReady();
  }
}