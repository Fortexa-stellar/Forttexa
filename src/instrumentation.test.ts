import { beforeEach, describe, expect, it, vi } from "vitest";

const { ensureDatabaseReadyMock, assertSafeSessionCookieConfigMock } = vi.hoisted(() => ({
  ensureDatabaseReadyMock: vi.fn(),
  assertSafeSessionCookieConfigMock: vi.fn(),
}));

vi.mock("@/lib/storage/db", () => ({
  ensureDatabaseReady: ensureDatabaseReadyMock,
}));

vi.mock("@/lib/auth/session-cookie", async () => {
  const actual = await vi.importActual<typeof import("@/lib/auth/session-cookie")>(
    "@/lib/auth/session-cookie"
  );
  return {
    ...actual,
    assertSafeSessionCookieConfig: assertSafeSessionCookieConfigMock,
  };
});

import { register } from "@/instrumentation";

describe("Next.js startup instrumentation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("waits for database migrations in the Node runtime", async () => {
    process.env.NEXT_RUNTIME = "nodejs";
    await register();
    expect(assertSafeSessionCookieConfigMock).toHaveBeenCalledOnce();
    expect(ensureDatabaseReadyMock).toHaveBeenCalledOnce();
  });

  it("fails startup when session cookie policy is unsafe", async () => {
    process.env.NEXT_RUNTIME = "nodejs";
    assertSafeSessionCookieConfigMock.mockImplementationOnce(() => {
      throw new Error("Unsafe session cookie configuration for production.");
    });
    await expect(register()).rejects.toThrow(/Unsafe session cookie configuration/);
    expect(ensureDatabaseReadyMock).not.toHaveBeenCalled();
  });

  it("fails startup when database migrations fail", async () => {
    process.env.NEXT_RUNTIME = "nodejs";
    ensureDatabaseReadyMock.mockRejectedValueOnce(new Error("migration failed"));
    await expect(register()).rejects.toThrow("migration failed");
  });

  it("does not connect to storage in a non-Node runtime", async () => {
    process.env.NEXT_RUNTIME = "edge";
    await register();
    expect(assertSafeSessionCookieConfigMock).not.toHaveBeenCalled();
    expect(ensureDatabaseReadyMock).not.toHaveBeenCalled();
  });
});