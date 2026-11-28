import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { jsonWithRequestContext } from "@/lib/observability/http";
import { getRequestLogContext } from "@/lib/observability/logger";
import { securityHeadersForRequest } from "@/lib/security/headers";
import { proxy } from "@/proxy";
import { MAX_REQUEST_ID_LENGTH, requestIdFor } from "./request-id";

afterEach(() => { vi.restoreAllMocks(); });

describe("request ID correlation", () => {
  it.each([undefined, "x".repeat(MAX_REQUEST_ID_LENGTH + 1), "two,headers"])(
    "uses the same safe response and log ID for invalid input %s",
    (invalid) => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      const request = new NextRequest("http://localhost/api/health", {
        headers: invalid === undefined ? {} : { "x-request-id": invalid },
      });
      const context = getRequestLogContext(request, "/api/health");
      const response = jsonWithRequestContext(request, {
        route: "/api/health",
        startedAtMs: Date.now(),
        status: 200,
        body: { ok: true },
        logExchange: true,
      });
      const id = response.headers.get("x-request-id");
      expect(id).toMatch(/^[a-f0-9-]{36}$/);
      expect(context.requestId).toBe(id);
      expect(securityHeadersForRequest(request)["x-request-id"]).toBe(id);
      expect(JSON.parse(String(log.mock.calls[0]?.[0])).requestId).toBe(id);
    },
  );

  it("passes the sanitized ID from proxy to the downstream request", () => {
    const request = new NextRequest("http://localhost/api/health", {
      headers: { "x-request-id": "bad value" },
    });
    const response = proxy(request);
    expect(response.headers.get("x-middleware-request-x-request-id"))
      .toBe(response.headers.get("x-request-id"));
    expect(requestIdFor(new NextRequest("http://localhost", {
      headers: { "x-request-id": "trace-1.safe" },
    }))).toBe("trace-1.safe");
  });
});
