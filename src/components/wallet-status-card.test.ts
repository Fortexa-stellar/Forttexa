import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// The card module imports the Freighter-backed session hook and Next router;
// the panel under test uses neither, and no browser extension is loaded.
vi.mock("@stellar/freighter-api", () => {
  throw new Error("browser extension must not be used in tests");
});
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

import {
  COPY_FAILED_MESSAGE,
  PublicKeyField,
  WalletActionsPanel,
  copyTextToClipboard,
} from "@/components/wallet-status-card";
import { resolveWalletCardState } from "@/lib/auth/session-wallet";

const SESSION_WALLET = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H";
const OTHER_ACCOUNT = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7";

function buttonDisabled(html: string, action: string) {
  const match = html.match(new RegExp(`<button[^>]*data-action="${action}"[^>]*>`));
  expect(match, `${action} button rendered`).not.toBeNull();
  return /\sdisabled=""/.test(match![0]);
}

describe("resolveWalletCardState", () => {
  it("enables pay and policy for an operator whose connected account matches", () => {
    const state = resolveWalletCardState({
      authenticated: true,
      role: "operator",
      sessionWallet: SESSION_WALLET,
      connectedAccount: SESSION_WALLET.toLowerCase(),
    });
    expect(state).toMatchObject({ status: "match", canPay: true, canEditPolicy: true });
  });

  it("enables only what the role allows for a matching viewer", () => {
    const state = resolveWalletCardState({
      authenticated: true,
      role: "viewer",
      sessionWallet: SESSION_WALLET,
      connectedAccount: SESSION_WALLET,
    });
    expect(state).toMatchObject({ status: "match", canPay: false, canEditPolicy: false });
  });

  it("disables pay and policy when the connected account differs", () => {
    const state = resolveWalletCardState({
      authenticated: true,
      role: "operator",
      sessionWallet: SESSION_WALLET,
      connectedAccount: OTHER_ACCOUNT,
    });
    expect(state).toMatchObject({ status: "mismatch", canPay: false, canEditPolicy: false });
  });

  it("disables actions when no account is connected or no wallet is bound", () => {
    expect(
      resolveWalletCardState({ authenticated: true, role: "operator", sessionWallet: SESSION_WALLET, connectedAccount: null }),
    ).toMatchObject({ status: "not_connected", canPay: false, canEditPolicy: false });
    expect(
      resolveWalletCardState({ authenticated: true, role: "operator", sessionWallet: null, connectedAccount: SESSION_WALLET }),
    ).toMatchObject({ status: "unbound", canPay: false, canEditPolicy: false });
  });

  it("returns signed out with nothing enabled after revoke", () => {
    const state = resolveWalletCardState({
      authenticated: true,
      revoked: true,
      role: "operator",
      sessionWallet: SESSION_WALLET,
      connectedAccount: SESSION_WALLET,
    });
    expect(state).toEqual({
      status: "signed_out",
      sessionWallet: null,
      connectedAccount: null,
      canPay: false,
      canEditPolicy: false,
    });
  });
});

describe("WalletActionsPanel", () => {
  it("renders enabled pay and policy actions for a matching operator", () => {
    const html = renderToStaticMarkup(
      createElement(WalletActionsPanel, {
        state: resolveWalletCardState({
          authenticated: true,
          role: "operator",
          sessionWallet: SESSION_WALLET,
          connectedAccount: SESSION_WALLET,
        }),
      }),
    );
    expect(html).toContain('data-status="match"');
    expect(buttonDisabled(html, "pay")).toBe(false);
    expect(buttonDisabled(html, "policy")).toBe(false);
  });

  it("renders a mismatch state with pay and policy disabled", () => {
    const html = renderToStaticMarkup(
      createElement(WalletActionsPanel, {
        state: resolveWalletCardState({
          authenticated: true,
          role: "operator",
          sessionWallet: SESSION_WALLET,
          connectedAccount: OTHER_ACCOUNT,
        }),
      }),
    );
    expect(html).toContain('data-status="mismatch"');
    expect(html).toContain('role="alert"');
    expect(buttonDisabled(html, "pay")).toBe(true);
    expect(buttonDisabled(html, "policy")).toBe(true);
  });

  it("shows signed out after revoke with no action enabled", () => {
    const html = renderToStaticMarkup(
      createElement(WalletActionsPanel, {
        state: resolveWalletCardState({
          authenticated: true,
          revoked: true,
          role: "operator",
          sessionWallet: SESSION_WALLET,
          connectedAccount: SESSION_WALLET,
        }),
      }),
    );
    expect(html).toContain('data-status="signed_out"');
    expect(html).toContain("Signed out");
    expect(buttonDisabled(html, "pay")).toBe(true);
    expect(buttonDisabled(html, "policy")).toBe(true);
    expect(html).not.toContain('data-action="revoke"');
  });
});

describe("copyTextToClipboard", () => {
  it("reports success only after the clipboard write resolves", async () => {
    let resolveWrite!: () => void;
    const writeText = vi.fn(() => new Promise<void>((resolve) => (resolveWrite = resolve)));
    let settled = false;
    const result = copyTextToClipboard(SESSION_WALLET, { writeText }).then((value) => {
      settled = true;
      return value;
    });

    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith(SESSION_WALLET);
    expect(settled).toBe(false);

    resolveWrite();
    await expect(result).resolves.toBe("copied");
  });

  it("reports failure when clipboard permission is denied", async () => {
    const writeText = vi.fn().mockRejectedValue(new DOMException("denied", "NotAllowedError"));
    await expect(copyTextToClipboard(SESSION_WALLET, { writeText })).resolves.toBe("failed");
  });

  it("reports failure when the Clipboard API is unavailable", async () => {
    await expect(copyTextToClipboard(SESSION_WALLET, undefined)).resolves.toBe("failed");
  });
});

describe("PublicKeyField", () => {
  function render(copyState: "idle" | "copied" | "failed") {
    return renderToStaticMarkup(createElement(PublicKeyField, { publicKey: SESSION_WALLET, copyState }));
  }

  it("shows a truncated key with the full key in its title by default", () => {
    const html = render("idle");
    expect(html).toContain(`title="${SESSION_WALLET}"`);
    expect(html).not.toContain('role="alert"');
    expect(html).toContain("Copy wallet public key to clipboard");
  });

  it("announces success only in the copied state", () => {
    expect(render("copied")).toContain("Wallet public key copied to clipboard.");
    expect(render("idle")).not.toContain("Wallet public key copied to clipboard.");
    expect(render("failed")).not.toContain("Wallet public key copied to clipboard.");
  });

  it("shows an accessible failure alert and the full selectable address when copying fails", () => {
    const html = render("failed");
    expect(html).toMatch(/<p[^>]*id="wallet-public-key-copy-error"[^>]*role="alert"[^>]*>/);
    expect(html).toContain(COPY_FAILED_MESSAGE.replace("'", "&#x27;"));
    expect(html).toMatch(/aria-describedby="wallet-public-key-copy-error"/);

    const full = html.match(/<p[^>]*data-testid="public-key-full"[^>]*>([^<]*)<\/p>/);
    expect(full).not.toBeNull();
    expect(full![0]).toContain("select-all");
    expect(full![1]).toBe(SESSION_WALLET);
    expect(html).not.toContain("Copied");
  });
});
