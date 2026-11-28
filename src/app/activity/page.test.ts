import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditEntry } from "@/lib/types/domain";

const cookieValue = vi.hoisted(() => ({ token: undefined as string | undefined }));
const listAuditEntries = vi.hoisted(() => vi.fn());
const verifySessionToken = vi.hoisted(() => vi.fn());
const isSessionRevoked = vi.hoisted(() => vi.fn());

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (cookieValue.token ? { value: cookieValue.token } : undefined),
  }),
}));

vi.mock("@/lib/storage/audit-store", () => ({ listAuditEntries }));

vi.mock("@/lib/auth/session", () => ({
  AUTH_COOKIE_KEY: "fortexa_session",
  verifySessionToken,
}));

vi.mock("@/lib/auth/session-revocation", () => ({ isSessionRevoked }));

import ActivityPage from "@/app/activity/page";

function makeEntry(n: number): AuditEntry {
  return {
    id: `audit-${n}`,
    timestamp: "2026-01-15T12:30:00.000Z",
    action: {
      id: `action-${n}`,
      name: `Payout ${n}`,
      kind: "api_payment",
      target: "api.example.com",
      domain: "api.example.com",
      amountXLM: n,
    },
    decision: "APPROVE",
    explanation: `Explanation ${n}`,
    triggeredPolicies: [],
    riskFindings: [],
  };
}

async function render(): Promise<string> {
  // The page is an async server component: resolve it first, then render the tree.
  return renderToStaticMarkup(await ActivityPage());
}

describe("/activity page", () => {
  beforeEach(() => {
    cookieValue.token = undefined;
    listAuditEntries.mockReset();
    verifySessionToken.mockReset();
    isSessionRevoked.mockReset();
    isSessionRevoked.mockResolvedValue(false);
  });

  it("renders the empty state when there is no session", async () => {
    const markup = await render();

    expect(markup).toContain("Activity");
    expect(markup).toContain("No audit entries yet");
    expect(listAuditEntries).not.toHaveBeenCalled();
  });

  it("renders the empty state for a signed-in user with no entries", async () => {
    cookieValue.token = "token";
    verifySessionToken.mockReturnValue({ userId: "user-1", sid: "sid-1" });
    listAuditEntries.mockResolvedValue([]);

    const markup = await render();

    expect(listAuditEntries).toHaveBeenCalledWith("user-1");
    expect(markup).toContain("No audit entries yet");
  });

  it("renders the full activity list, not the five-entry compact view", async () => {
    cookieValue.token = "token";
    verifySessionToken.mockReturnValue({ userId: "user-1", sid: "sid-1" });
    listAuditEntries.mockResolvedValue([1, 2, 3, 4, 5, 6, 7].map(makeEntry));

    const markup = await render();

    for (let n = 1; n <= 7; n += 1) {
      expect(markup).toContain(`Payout ${n}`);
      expect(markup).toContain(`Explanation ${n}`);
    }
    expect(markup).not.toContain("No audit entries yet");
  });

  it("treats an invalid session token as signed out", async () => {
    cookieValue.token = "forged";
    verifySessionToken.mockReturnValue(null);

    const markup = await render();

    expect(listAuditEntries).not.toHaveBeenCalled();
    expect(markup).toContain("No audit entries yet");
  });

  it("checks the revocation store for the session id before reading entries", async () => {
    cookieValue.token = "token";
    verifySessionToken.mockReturnValue({ userId: "user-1", sid: "sid-1" });
    listAuditEntries.mockResolvedValue([makeEntry(1)]);

    await render();

    expect(isSessionRevoked).toHaveBeenCalledWith("sid-1");
  });

  it("treats a revoked (logged-out) session as signed out and never reads entries", async () => {
    cookieValue.token = "logged-out-but-still-signed";
    verifySessionToken.mockReturnValue({ userId: "user-1", sid: "sid-1" });
    isSessionRevoked.mockResolvedValue(true);
    listAuditEntries.mockResolvedValue([makeEntry(1)]);

    const markup = await render();

    expect(isSessionRevoked).toHaveBeenCalledWith("sid-1");
    expect(listAuditEntries).not.toHaveBeenCalled();
    expect(markup).not.toContain("Payout 1");
    expect(markup).toContain("No audit entries yet");
  });
});
