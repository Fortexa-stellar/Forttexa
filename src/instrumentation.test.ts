import { beforeEach, describe, expect, it, vi } from "vitest";

const { ensureDatabaseReadyMock } = vi.hoisted(() => ({
  ensureDatabaseReadyMock: vi.fn(),
}));

vi.mock("@/lib/storage/db", () => ({
  ensureDatabaseReady: ensureDatabaseReadyMock,
}));

import { register } from "@/instrumentation";

describe("Next.js startup instrumentation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("waits for database migrations in the Node runtime", async () => {
    process.env.NEXT_RUNTIME = "nodejs";
    await register();
    expect(ensureDatabaseReadyMock).toHaveBeenCalledOnce();
  });

  it("rejects an insecure cookie override before opening storage", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_RUNTIME", "nodejs");
    vi.stubEnv("FORTEXA_SESSION_COOKIE_SECURE", "false");
    try {
      await expect(register()).rejects.toThrow("Production session cookies must use Secure");
      expect(ensureDatabaseReadyMock).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("fails startup when database migrations fail", async () => {
    process.env.NEXT_RUNTIME = "nodejs";
    ensureDatabaseReadyMock.mockRejectedValueOnce(new Error("migration failed"));
    await expect(register()).rejects.toThrow("migration failed");
  });

  it("does not connect to storage in a non-Node runtime", async () => {
    process.env.NEXT_RUNTIME = "edge";
    await register();
    expect(ensureDatabaseReadyMock).not.toHaveBeenCalled();
  });
});