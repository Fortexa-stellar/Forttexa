import { describe, expect, it } from "vitest";

import {
  AUDIT_PAGE_DEFAULT_LIMIT,
  AUDIT_PAGE_MAX_LIMIT,
  AUDIT_PAGE_MAX_OFFSET,
  AUDIT_PAGE_MIN_LIMIT,
  parseAuditPagination,
} from "@/lib/audit/pagination";

function parse(query: string) {
  return parseAuditPagination(new URLSearchParams(query));
}

describe("audit pagination validation", () => {
  it("uses bounded defaults", () => {
    expect(parse("")).toEqual({ ok: true, pagination: { limit: AUDIT_PAGE_DEFAULT_LIMIT, offset: 0 } });
  });

  it("accepts documented limit and offset boundaries", () => {
    expect(parse(`limit=${AUDIT_PAGE_MIN_LIMIT}&offset=0`)).toEqual({
      ok: true,
      pagination: { limit: AUDIT_PAGE_MIN_LIMIT, offset: 0 },
    });
    expect(parse(`limit=${AUDIT_PAGE_MAX_LIMIT}&cursor=${AUDIT_PAGE_MAX_OFFSET}`)).toEqual({
      ok: true,
      pagination: { limit: AUDIT_PAGE_MAX_LIMIT, offset: AUDIT_PAGE_MAX_OFFSET },
    });
  });

  it.each([
    "limit=0",
    "limit=101",
    "limit=-1",
    "limit=1.5",
    "limit=9007199254740992",
    "offset=-1",
    "offset=1.5",
    "offset=9007199254740992",
    "offset=10001",
    "cursor=-1",
    "cursor=1.5",
    "cursor=9007199254740992",
    "cursor=10001",
    "offset=0&cursor=1",
    "limit=1&limit=2",
  ])("rejects invalid pagination query %s with a stable code", (query) => {
    expect(parse(query)).toEqual({ ok: false, code: "invalid_pagination_parameters" });
  });
});