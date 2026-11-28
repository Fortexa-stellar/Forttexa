import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { GET, POST } from "./route";

function expectSecurityHeaders(response: Response) {
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  expect(response.headers.get("x-request-id")).toBeTruthy();
}

describe("/api/auth/challenge response headers", () => {
  it("sets headers on a successful challenge response", async () => {
    const response = await GET(new NextRequest("http://localhost/api/auth/challenge"));

    expect(response.status).toBe(200);
    expect(typeof (await response.json()).challenge).toBe("string");
    expectSecurityHeaders(response);
  });

  it("sets headers when malformed JSON produces an error response", async () => {
    const request = new NextRequest("http://localhost/api/auth/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });

    const response = await POST(request);

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid challenge", code: "INVALID_CHALLENGE" });
    expectSecurityHeaders(response);
  });
});