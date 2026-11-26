import { ensureDatabaseReady } from "@/lib/storage/db";

export async function registerNodeInstrumentation() {
  await ensureDatabaseReady();
}
