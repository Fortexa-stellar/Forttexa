import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { POST as challengePost } from "@/app/api/auth/challenge/route";
import { POST as loginPost } from "@/app/api/auth/login/route";
import { POST as refreshPost } from "@/app/api/auth/refresh/route";
import { POST as logoutPost } from "@/app/api/auth/logout/route";
import { GET as sessionGet } from "@/app/api/auth/session/route";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";

function makeSessionToken() {
  process.env.FORTEXA_AUTH_SECRET = "test-non-cacheable-secret";
  return createSessionToken({
    email: "test@fortexa.local",
    role: "operator",
    userId: "test-user-id",
    expiresInSeconds: 120,
  });
}

describe("Wallet authentication responses are non-cacheable", () => {
  it("sets Cache-Control: no-store and Pragma: no-cache on challenge responses", async () => {
    // Error response (invalid payload)
    const badReq = new NextRequest("http://localhost/api/auth/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    const badRes = await challengePost(badReq);
    expect(badRes.headers.get("Cache-Control")).toBe("no-store");
    expect(badRes.headers.get("Pragma")).toBe("no-cache");

    // Success response
    const goodReq = new NextRequest("http://localhost/api/auth/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ publicKey: "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L" }),
    });
    const goodRes = await challengePost(goodReq);
    expect(goodRes.headers.get("Cache-Control")).toBe("no-store");
    expect(goodRes.headers.get("Pragma")).toBe("no-cache");
  });

  it("sets Cache-Control: no-store and Pragma: no-cache on login responses", async () => {
    // Error response
    const badReq = new NextRequest("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    const badRes = await loginPost(badReq);
    expect(badRes.headers.get("Cache-Control")).toBe("no-store");
    expect(badRes.headers.get("Pragma")).toBe("no-cache");
  });

  it("sets Cache-Control: no-store and Pragma: no-cache on refresh responses", async () => {
    // Unauthenticated (error response)
    const unauthReq = new NextRequest("http://localhost/api/auth/refresh", {
      method: "POST",
    });
    const unauthRes = await refreshPost(unauthReq);
    expect(unauthRes.headers.get("Cache-Control")).toBe("no-store");
    expect(unauthRes.headers.get("Pragma")).toBe("no-cache");
  });

  it("sets Cache-Control: no-store and Pragma: no-cache on logout responses", async () => {
    const req = new NextRequest("http://localhost/api/auth/logout", {
      method: "POST",
    });
    const res = await logoutPost(req);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Pragma")).toBe("no-cache");
  });

  it("sets Cache-Control: no-store and Pragma: no-cache on session responses", async () => {
    // Unauthenticated
    const unauthReq = new NextRequest("http://localhost/api/auth/session", {
      method: "GET",
    });
    const unauthRes = await sessionGet(unauthReq);
    expect(unauthRes.headers.get("Cache-Control")).toBe("no-store");
    expect(unauthRes.headers.get("Pragma")).toBe("no-cache");

    // Authenticated
    const token = makeSessionToken();
    const authReq = new NextRequest("http://localhost/api/auth/session", {
      method: "GET",
      headers: { cookie: `${AUTH_COOKIE_KEY}=${token}` },
    });
    const authRes = await sessionGet(authReq);
    expect(authRes.headers.get("Cache-Control")).toBe("no-store");
    expect(authRes.headers.get("Pragma")).toBe("no-cache");
  });
});
