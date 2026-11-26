import { promises as fs } from "node:fs";
import { join } from "node:path";

import Redis from "ioredis";
import { Pool } from "pg";

import { defaultPolicyConfig } from "../src/lib/policy/engine";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

const STORE_FILES = [
  "audit.json",
  "policy.json",
  "policy-history.json",
  "wallets.json",
  "submit-idempotency.json",
];

function hostIsLocal(host: string | null | undefined): boolean {
  if (!host) return true;
  return LOCAL_HOSTS.has(host.toLowerCase());
}

/** True when a PostgreSQL connection target resolves to this machine. */
export function isLocalDatabaseUrl(value: string | undefined): boolean {
  if (!value) return true;

  const trimmed = value.trim();
  if (!trimmed) return true;

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return hostIsLocal(new URL(trimmed).hostname);
    } catch {
      return false;
    }
  }

  const hostMatch = /(?:^|\s)host=([^\s]+)/i.exec(trimmed);
  if (hostMatch) {
    return hostIsLocal(hostMatch[1]);
  }

  // A key=value DSN without an explicit host targets the local socket.
  return true;
}

/** True when a Redis connection target resolves to this machine. */
export function isLocalRedisUrl(value: string | undefined): boolean {
  if (!value) return true;

  const trimmed = value.trim();
  if (!trimmed) return true;

  try {
    const url = new URL(trimmed);
    return hostIsLocal(url.hostname);
  } catch {
    return false;
  }
}

export type RunResetOptions = {
  dryRun?: boolean;
  allowLocalReset?: boolean;
  yesFlag?: boolean;
  databaseUrl?: string;
  redisUrl?: string;
  storeDir?: string;
  log?: (message: string) => void;
  errorLog?: (message: string) => void;
};

export type RunResetResult = {
  success: boolean;
  refusalReason?: string;
};

function refusal(
  reason: string,
  options: RunResetOptions,
): RunResetResult {
  (options.errorLog ?? console.error)(`REFUSAL: Execution BLOCKED. ${reason}`);
  return { success: false, refusalReason: reason };
}

/**
 * Reset the local demo state after verifying every safety guardrail.
 *
 * Refuses to touch anything unless the caller opted in through
 * `FORTEXA_ALLOW_LOCAL_RESET=true` (or the explicit option), passed `--yes`,
 * and every database/Redis target is local.
 */
export async function runReset(
  options: RunResetOptions = {},
): Promise<RunResetResult> {
  const log = options.log ?? console.log;
  const dryRun = options.dryRun ?? false;
  const storeDir = options.storeDir ?? ".fortexa";
  const databaseUrl = options.databaseUrl ?? process.env.DATABASE_URL;
  const redisUrl = options.redisUrl ?? process.env.REDIS_URL;

  log(
    dryRun
      ? "=== Fortexa Local Demo State Reset (DRY-RUN) ==="
      : "=== Fortexa Local Demo State Reset ===",
  );
  log("[Target Files]");
  for (const file of STORE_FILES) {
    log(`- ${join(storeDir, file)}`);
  }
  log("[Target Database Tables]");
  log("- fortexa_wallets, fortexa_policy_state, fortexa_policy_history");
  log("- fortexa_submit_idempotency, fortexa_audit_entries");

  const allowLocalReset =
    options.allowLocalReset ??
    process.env.FORTEXA_ALLOW_LOCAL_RESET?.trim().toLowerCase() === "true";

  if (!allowLocalReset) {
    return refusal(
      options.allowLocalReset === false
        ? "Set FORTEXA_ALLOW_LOCAL_RESET=true to allow a local reset."
        : "Missing env variable FORTEXA_ALLOW_LOCAL_RESET=true.",
      options,
    );
  }

  if (!options.yesFlag) {
    return refusal(
      "Re-run with the flag --yes to confirm the destructive reset.",
      options,
    );
  }

  if (!isLocalDatabaseUrl(databaseUrl)) {
    return refusal(
      "Refusing to reset against a non-local database host.",
      options,
    );
  }

  if (!isLocalRedisUrl(redisUrl)) {
    return refusal("Refusing to reset against a non-local redis host.", options);
  }

  if (dryRun) {
    log("Dry-run complete. No files or database rows were modified.");
    return { success: true };
  }

  for (const file of STORE_FILES) {
    try {
      await fs.unlink(join(storeDir, file));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") throw error;
    }
  }

  const pool = new Pool(
    databaseUrl ? { connectionString: databaseUrl } : undefined,
  );
  try {
    await pool.query(
      "TRUNCATE TABLE fortexa_wallets, fortexa_policy_history, fortexa_submit_idempotency, fortexa_audit_entries",
    );
    await pool.query(
      "TRUNCATE TABLE fortexa_policy_state RESTART IDENTITY",
    );
    await pool.query(
      `INSERT INTO fortexa_policy_state (id, version, updated_at, policy)
       VALUES (1, 1, $1::timestamptz, $2::jsonb)`,
      [new Date().toISOString(), JSON.stringify(defaultPolicyConfig)],
    );
  } finally {
    await pool.end();
  }

  const redis = new Redis(redisUrl ?? "redis://localhost:6379");
  try {
    const keys = await redis.keys("fortexa:*");
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } finally {
    redis.disconnect();
  }

  log("Local demo state reset successfully.");
  return { success: true };
}

if (process.argv[1] && /reset-local-demo-state/.test(process.argv[1])) {
  runReset({
    dryRun: !process.argv.includes("--yes"),
    yesFlag: process.argv.includes("--yes"),
  })
    .then((result) => {
      if (!result.success) {
        process.exitCode = 1;
      }
    })
    .catch((error) => {
      console.error(
        "Reset failed:",
        error instanceof Error ? error.message : String(error),
      );
      process.exitCode = 1;
    });
}
