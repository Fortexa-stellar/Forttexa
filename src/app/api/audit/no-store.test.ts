import { NextRequest, NextResponse } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Every response from the audit export and integrity routes, success or error,
// must carry Cache-Control: no-store. The collaborators are mocked so each test
// can drive one branch of the routes and nothing else.

type Role = "operator" | "viewer";

const state = vi.hoisted(() => ({
  auth: "operator" as "operator" | "viewer" | "anonymous",
  chain: "valid" as "valid" | "broken" | "row-cap",
  storeThrows: false,
}));

vi.mock("@/lib/auth/require-auth", () => ({
  requireAuth: () => {
    if (state.auth === "anonymous") {
      return {
        ok: false as const,
        response: NextResponse.json({ error: "Unauthorized. Login required." }, { status: 401 }),
      };
    }
    return {
      ok: true as const,
      session: {
        userId: "user-1",
        email: "user-1@fortexa.local",
        role: state.auth as Role,
        sid: "sid-1",
        exp: Math.floor(Date.now() / 1000) + 120,
      },
    };
  },
}));

vi.mock("@/lib/storage/audit-store", () => ({
  validateAuditFilter: () => null,
  listAuditEntries: async () => {
    if (state.storeThrows) throw new Error("store offline");
    return [];
  },
  listAllAuditEntriesByUser: async () => {
    if (state.storeThrows) throw new Error("store offline");
    return { "user-1": [] };
  },
}));

vi.mock("@/lib/audit/hash-chain", () => {
  class AuditChainError extends Error {
    code: string;
    details?: Record<string, unknown>;
    constructor(code: string, message: string, details?: Record<string, unknown>) {
      super(message);
      this.code = code;
      this.details = details;
    }
  }
  return {
    AuditChainError,
    verifyAuditChain: () => {
      if (state.chain === "row-cap") {
        throw new AuditChainError("audit_chain_row_cap_exceeded", "Too many rows.", { maxRows: 1 });
      }
      if (state.chain === "broken") {
        return {
          result: {
            valid: false as const,
            reason: "entryHash mismatch",
            entryId: "entry-1",
            index: 0,
            checkedCount: 1,
            legacyCount: 0,
          },
          boundaries: { genesisHash: "0".repeat(64), headHash: "0".repeat(64), count: 0 },
        };
      }
      return {
        result: { valid: true as const, checkedCount: 0, legacyCount: 0 },
        boundaries: { genesisHash: "0".repeat(64), headHash: "0".repeat(64), count: 0 },
      };
    },
  };
});

vi.mock("@/lib/audit/redact", () => ({
  redactAuditExportPayload: <T>(rows: T) => rows,
  redactAuditExportEntriesByUser: <T>(entries: T) => entries,
}));

import { GET as exportGET } from "@/app/api/audit/export/route";
import { GET as integrityGET } from "@/app/api/audit/integrity/route";

function exportRequest(query: string) {
  return new NextRequest(`http://localhost/api/audit/export?${query}`);
}

function integrityRequest(query = "") {
  return new NextRequest(`http://localhost/api/audit/integrity?${query}`);
}

beforeEach(() => {
  state.auth = "operator";
  state.chain = "valid";
  state.storeThrows = false;
});

describe("GET /api/audit/export is never cacheable", () => {
  it.each([
    ["json, scope mine", "format=json&scope=mine"],
    ["csv, scope mine", "format=csv&scope=mine"],
    ["json, scope all", "format=json&scope=all"],
    ["csv, scope all", "format=csv&scope=all"],
  ])("sets no-store on a 200 (%s)", async (_label, query) => {
    const res = await exportGET(exportRequest(query));

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 400 for an unknown format", async () => {
    const res = await exportGET(exportRequest("format=xml"));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 400 when a viewer asks for scope=all", async () => {
    state.auth = "viewer";
    const res = await exportGET(exportRequest("format=json&scope=all"));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 401 when there is no session", async () => {
    state.auth = "anonymous";
    const res = await exportGET(exportRequest("format=json"));

    expect(res.status).toBe(401);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 422 when the hash chain is broken", async () => {
    state.chain = "broken";
    const res = await exportGET(exportRequest("format=csv&scope=mine"));

    expect(res.status).toBe(422);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 413 when the row cap is exceeded", async () => {
    state.chain = "row-cap";
    const res = await exportGET(exportRequest("format=json&scope=mine"));

    expect(res.status).toBe(413);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 500 when the store fails", async () => {
    state.storeThrows = true;
    const res = await exportGET(exportRequest("format=json&scope=mine"));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
});

describe("GET /api/audit/integrity is never cacheable", () => {
  it.each([
    ["scope mine", ""],
    ["scope all", "scope=all"],
  ])("sets no-store on a 200 (%s)", async (_label, query) => {
    const res = await integrityGET(integrityRequest(query));

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 200 that reports a tampered chain", async () => {
    state.chain = "broken";
    const res = await integrityGET(integrityRequest());

    expect(res.status).toBe(200);
    expect((await res.json()).valid).toBe(false);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 400 for an unknown scope", async () => {
    const res = await integrityGET(integrityRequest("scope=everyone"));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 403 when a viewer asks for scope=all", async () => {
    state.auth = "viewer";
    const res = await integrityGET(integrityRequest("scope=all"));

    expect(res.status).toBe(403);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 401 when there is no session", async () => {
    state.auth = "anonymous";
    const res = await integrityGET(integrityRequest());

    expect(res.status).toBe(401);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 413 when the row cap is exceeded", async () => {
    state.chain = "row-cap";
    const res = await integrityGET(integrityRequest());

    expect(res.status).toBe(413);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets no-store on a 500 when the store fails, without leaking the detail", async () => {
    state.storeThrows = true;
    const res = await integrityGET(integrityRequest());
    const body = await res.json();

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(JSON.stringify(body)).not.toContain("store offline");
  });
});
