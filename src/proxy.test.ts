import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { config, proxy } from "./proxy";

function expectSecurityHeaders(response: Response) {
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  expect(response.headers.get("x-request-id")).toBeTruthy();
}

describe("API proxy security headers", () => {
  it("covers API requests in the proxy matcher", () => {
    expect(config.matcher.join(" ")).not.toContain("api");

    const response = proxy(new NextRequest("http://localhost/api/health"));

    expectSecurityHeaders(response);
  });

  it("preserves an incoming request id on API responses", () => {
    const request = new NextRequest("http://localhost/api/policy/validate", {
      headers: { "x-request-id": "api-request-123" },
    });

    const response = proxy(request);

    expect(response.headers.get("x-request-id")).toBe("api-request-123");
  });
});
