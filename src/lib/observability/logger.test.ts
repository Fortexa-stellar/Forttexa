import { afterEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

import { MAX_REQUEST_ID_LENGTH } from "@/lib/http/request-id";
import { getRequestId, getRequestLogContext, logInfo } from "@/lib/observability/logger";

function requestWithId(id?: string | null): NextRequest {
  return {
    method: "GET",
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "x-request-id" ? (id ?? null) : null,
    },
  } as NextRequest;
}

describe("getRequestId", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reuses a safe inbound id for logging", () => {
    expect(getRequestId(requestWithId("log-req-1"))).toBe("log-req-1");
  });

  it("does not log control characters from an inbound id", () => {
    const generated = "11111111-2222-4333-8444-555555555555";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);

    const unsafe = "evil\nX-Injected: 1";
    expect(getRequestId(requestWithId(unsafe))).toBe(generated);
    expect(getRequestId(requestWithId(unsafe))).not.toContain("\n");
  });

  it("does not log an oversized inbound id", () => {
    const generated = "22222222-3333-4444-8555-666666666666";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);

    const oversized = "y".repeat(MAX_REQUEST_ID_LENGTH + 1);
    expect(getRequestId(requestWithId(oversized))).toBe(generated);
    expect(getRequestId(requestWithId(oversized)).length).toBeLessThanOrEqual(MAX_REQUEST_ID_LENGTH);
  });
});

describe("getRequestLogContext", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("puts a sanitized request id into the log context", () => {
    const generated = "33333333-4444-4555-8666-777777777777";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);

    const context = getRequestLogContext(requestWithId("bad\rid"), "/api/decision");
    expect(context.requestId).toBe(generated);
    expect(context.route).toBe("/api/decision");
    expect(context.method).toBe("GET");
  });

  it("serializes a sanitized request id when logging", () => {
    const generated = "44444444-5555-4666-8777-888888888888";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);

    const context = getRequestLogContext(requestWithId("bad\x00id"), "/api/metrics");
    logInfo("metrics read", context);

    const logged = String(log.mock.calls[0]?.[0] ?? "");
    expect(logged).toContain(generated);
    expect(logged).not.toContain("\x00");
    expect(JSON.parse(logged).requestId).toBe(generated);
  });
});
