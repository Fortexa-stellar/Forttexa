import { promises as fs } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  const tempRoot = process.env.TMPDIR ?? process.env.TEMP ?? "/tmp";
  process.env.FORTEXA_STORE_DIR = `${tempRoot}/fortexa-audit-store-${Date.now()}`;
  delete process.env.DATABASE_URL;
});

const { runWithDatabaseMock } = vi.hoisted(() => ({
  runWithDatabaseMock: vi.fn(
    async <T>(
      _name: string,
      _action: (pool: never) => Promise<T>,
    ): Promise<{ available: true; value: T } | { available: false }> => ({ available: false as const }),
  ),
}));

vi.mock("@/lib/storage/db", () => ({
  runWithDatabase: runWithDatabaseMock,
  runWithDatabaseStrict: runWithDatabaseMock,
}));

import { computeEntryHash, GENESIS_HASH, verifyHashChain } from "@/lib/audit/hash-chain";
import { appendAuditEntry, listAuditEntries } from "@/lib/storage/audit-store";
import type { AuditEntry } from "@/lib/types/domain";

const storePath = join(process.env.FORTEXA_STORE_DIR!, "audit.json");
const USER_ID = "audit-concurrency-user";

function makeEntry(id: string, timestamp = new Date().toISOString()): AuditEntry {
  return {
    id,
    timestamp,
    action: {
      id,
      name: "Audit fixture action",
      kind: "api_payment",
      target: "fixture:payment",
      domain: "fixture.example",
      amountXLM: 1,
    },
    decision: "APPROVE",
    explanation: "fixture",
    triggeredPolicies: [],
    riskFindings: [],
  };
}

describe("audit-store append serialization", () => {
  beforeEach(async () => {
    runWithDatabaseMock.mockReset().mockResolvedValue({ available: false });
    await fs.rm(process.env.FORTEXA_STORE_DIR!, { recursive: true, force: true });
  });

  afterAll(async () => {
    await fs.rm(process.env.FORTEXA_STORE_DIR!, { recursive: true, force: true });
  });

  it("keeps overlapping appends on one verified hash chain", async () => {
    const timestamp = new Date().toISOString();
    await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        appendAuditEntry(USER_ID, makeEntry(`entry-${index}`, timestamp)),
      ),
    );

    const entries = await listAuditEntries(USER_ID);
    const verification = verifyHashChain(entries);

    expect(entries).toHaveLength(12);
    expect(verification).toMatchObject({ valid: true, checkedCount: 12 });
    const ascending = [...entries].sort((left, right) => left.timestamp.localeCompare(right.timestamp));
    expect(ascending[0]?.previousHash).toBe(GENESIS_HASH);
    for (let index = 1; index < ascending.length; index++) {
      expect(ascending[index]?.previousHash).toBe(ascending[index - 1]?.entryHash);
    }
    expect(ascending.at(-1)?.entryHash).toBe(
      computeEntryHash({ ...ascending.at(-1)!, previousHash: ascending.at(-1)!.previousHash! }),
    );
  });

  it("returns the requested page from the file-backed store", async () => {
    await appendAuditEntry(USER_ID, makeEntry("oldest", "2026-01-01T00:00:00.000Z"));
    await appendAuditEntry(USER_ID, makeEntry("middle", "2026-01-02T00:00:00.000Z"));
    await appendAuditEntry(USER_ID, makeEntry("newest", "2026-01-03T00:00:00.000Z"));

    const page = await listAuditEntries(USER_ID, undefined, { limit: 1, offset: 1 });

    expect(page.map((entry) => entry.id)).toEqual(["middle"]);
  });

  it("bounds database reads with SQL limit and offset", async () => {
    const query = vi.fn(async () => ({ rows: [] }));
    const pool = { query };
    runWithDatabaseMock.mockImplementationOnce(async (_name, action) => ({
      available: true as const,
      value: await action(pool as never),
    }));

    await listAuditEntries(USER_ID, undefined, { limit: 26, offset: 75 });

    expect(query).toHaveBeenCalledWith(
      expect.stringContaining("LIMIT $2 OFFSET $3"),
      [USER_ID, 26, 75],
    );
  });

  it("preserves the last committed file-store tip when atomic replacement fails", async () => {
    await appendAuditEntry(USER_ID, makeEntry("first"));
    const renameSpy = vi.spyOn(fs, "rename").mockRejectedValueOnce(new Error("disk write failed"));

    await expect(appendAuditEntry(USER_ID, makeEntry("second"))).rejects.toThrow("disk write failed");

    renameSpy.mockRestore();
    const entries = await listAuditEntries(USER_ID);
    expect(entries).toHaveLength(1);
    expect(verifyHashChain(entries)).toMatchObject({ valid: true, checkedCount: 1 });
  });

  it("rolls back a failed database insert and does not fall back to a file append", async () => {
    const calls: string[] = [];
    const client = {
      query: vi.fn(async (sql: string) => {
        calls.push(sql);
        if (sql.includes("SELECT entry_hash")) return { rows: [] };
        if (sql.includes("next_sequence")) return { rows: [{ next_sequence: "1" }] };
        if (sql.includes("INSERT INTO fortexa_audit_entries")) throw new Error("insert failed");
        return { rows: [] };
      }),
      release: vi.fn(),
    };
    const pool = { connect: vi.fn(async () => client) };
    runWithDatabaseMock.mockImplementationOnce(async (_name, action) => {
      try {
        return { available: true as const, value: await action(pool as never) };
      } catch (error) {
        throw error;
      }
    });

    await expect(appendAuditEntry(USER_ID, makeEntry("db-failure"))).rejects.toThrow("insert failed");
    expect(calls).toContain("ROLLBACK");
    expect(calls).not.toContain("COMMIT");
    expect(await fs.access(storePath).then(() => true, () => false)).toBe(false);
  });
});