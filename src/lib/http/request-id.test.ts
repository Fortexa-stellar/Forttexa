import { describe, expect, it, vi } from "vitest";

import {
  MAX_REQUEST_ID_LENGTH,
  isValidRequestId,
  resolveRequestId,
} from "@/lib/http/request-id";

describe("isValidRequestId", () => {
  it("accepts UUIDs and common tracing ids within the documented max length", () => {
    expect(isValidRequestId("request-123")).toBe(true);
    expect(isValidRequestId("6f1a1b2c-3d4e-5f60-7a8b-9c0d1e2f3a4b")).toBe(true);
    expect(isValidRequestId("a".repeat(MAX_REQUEST_ID_LENGTH))).toBe(true);
  });

  it("rejects empty, oversized, or control-character values", () => {
    expect(isValidRequestId("")).toBe(false);
    expect(isValidRequestId("a".repeat(MAX_REQUEST_ID_LENGTH + 1))).toBe(false);
    expect(isValidRequestId("bad\nid")).toBe(false);
    expect(isValidRequestId("bad\rid")).toBe(false);
    expect(isValidRequestId("bad\x00id")).toBe(false);
    expect(isValidRequestId("has space")).toBe(false);
    expect(isValidRequestId(null)).toBe(false);
    expect(isValidRequestId(undefined)).toBe(false);
  });
});

describe("resolveRequestId", () => {
  it("reuses a safe inbound x-request-id", () => {
    const request = new Request("http://localhost/api/decision", {
      headers: { "x-request-id": "incoming-id" },
    });
    expect(resolveRequestId(request)).toBe("incoming-id");
  });

  it("mints a server UUID when the inbound id is missing", () => {
    const generated = "11111111-2222-4333-8444-555555555555";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);

    const request = new Request("http://localhost/api/decision");
    expect(resolveRequestId(request)).toBe(generated);

    vi.restoreAllMocks();
  });

  it("mints a server UUID when the inbound id has control characters", () => {
    const generated = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);

    // Fetch Headers rejects CR/LF, so stub get() the way a hostile proxy might.
    const request = {
      headers: { get: () => "evil\nX-Injected: 1" },
    };
    expect(resolveRequestId(request)).toBe(generated);

    vi.restoreAllMocks();
  });

  it("mints a server UUID when the inbound id exceeds the documented max length", () => {
    const generated = "99999999-8888-4777-8666-555555555555";
    vi.spyOn(crypto, "randomUUID").mockReturnValue(generated);

    const request = new Request("http://localhost/api/decision", {
      headers: { "x-request-id": "x".repeat(MAX_REQUEST_ID_LENGTH + 1) },
    });
    expect(resolveRequestId(request)).toBe(generated);

    vi.restoreAllMocks();
  });
});
