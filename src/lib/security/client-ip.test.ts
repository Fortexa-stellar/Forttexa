import { afterEach, describe, expect, it } from "vitest";

import {
  isTrustedProxyEnabled,
  normalizeClientIp,
  resolveClientIp,
} from "@/lib/security/client-ip";

function headersOf(init: Record<string, string>) {
  return new Headers(init);
}

describe("normalizeClientIp", () => {
  it("trims, lowercases, and unwraps common proxy forms", () => {
    expect(normalizeClientIp("  203.0.113.10  ")).toBe("203.0.113.10");
    expect(normalizeClientIp('"203.0.113.10"')).toBe("203.0.113.10");
    expect(normalizeClientIp("[2001:db8::1]")).toBe("2001:db8::1");
    expect(normalizeClientIp("::FFFF:192.0.2.8")).toBe("192.0.2.8");
    expect(normalizeClientIp("192.0.2.8:443")).toBe("192.0.2.8");
    expect(normalizeClientIp("")).toBe("unknown");
    expect(normalizeClientIp(null)).toBe("unknown");
  });
});

describe("resolveClientIp", () => {
  afterEach(() => {
    delete process.env.FORTEXA_TRUSTED_PROXY;
  });

  it("ignores Forwarded and X-Forwarded-For by default (spoofing)", () => {
    expect(isTrustedProxyEnabled()).toBe(false);

    const spoofed = headersOf({
      "x-forwarded-for": "198.51.100.50, 10.0.0.1",
      forwarded: 'for=198.51.100.50;proto=https',
      "x-real-ip": "203.0.113.9",
    });

    // Spoofed forwarding headers must not choose the security-state key.
    expect(resolveClientIp(spoofed)).toBe("203.0.113.9");

    const onlySpoofed = headersOf({
      "x-forwarded-for": "198.51.100.50",
      forwarded: "for=198.51.100.51",
    });
    expect(resolveClientIp(onlySpoofed)).toBe("unknown");
  });

  it("honors X-Forwarded-For when FORTEXA_TRUSTED_PROXY is enabled", () => {
    process.env.FORTEXA_TRUSTED_PROXY = "true";

    const headers = headersOf({
      "x-forwarded-for": "198.51.100.50, 10.0.0.1",
      "x-real-ip": "203.0.113.9",
    });

    expect(resolveClientIp(headers)).toBe("198.51.100.50");
  });

  it("honors the Forwarded header when trusted proxies are enabled", () => {
    process.env.FORTEXA_TRUSTED_PROXY = "1";

    const headers = headersOf({
      forwarded: 'for="[2001:DB8::AA]";proto=https, for=10.0.0.1',
    });

    expect(resolveClientIp(headers)).toBe("2001:db8::aa");
  });

  it("normalizes the selected address before returning it", () => {
    process.env.FORTEXA_TRUSTED_PROXY = "yes";

    const headers = headersOf({
      "x-forwarded-for": "  ::FFFF:203.0.113.77:8443 , 10.0.0.1",
    });

    // Unwrap IPv4-mapped form, then strip a trailing IPv4 port.
    expect(resolveClientIp(headers)).toBe("203.0.113.77");
  });
});
