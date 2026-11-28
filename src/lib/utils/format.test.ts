import { describe, it, expect } from "vitest";
import {
  truncateMiddle,
  formatNumber,
  formatCurrency,
  formatPct,
  formatAuditTimestamp
} from "@/lib/utils/format";

describe("truncateMiddle", () => {
  it("returns value unchanged when short enough", () => {
    expect(truncateMiddle("GABC1234")).toBe("GABC1234");
  });

  it("returns value unchanged at exact threshold", () => {
    expect(truncateMiddle("GABCDEF123456", 6, 6)).toBe("GABCDEF123456");
  });

  it("truncates when longer than threshold", () => {
    expect(truncateMiddle("GABCDEF1234567890", 6, 6)).toBe("GABCDE...567890");
  });

  it("preserves prefix and suffix for a normal stellar key", () => {
    const key = "GDEVXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    const result = truncateMiddle(key, 8, 8);
    expect(result).toBe("GDEVXXXX...XXXXXXXX");
    expect(result.startsWith("GDEV")).toBe(true);
    expect(result.endsWith("XXXXXXXX")).toBe(true);
  });

  it("returns empty string unchanged", () => {
    expect(truncateMiddle("")).toBe("");
  });

  it("uses custom left and right values", () => {
    expect(truncateMiddle("ABCDEFGHIJKLMNOP", 4, 4)).toBe("ABCD...MNOP");
  });
});

describe("formatNumber", () => {
  it("formats normal values correctly", () => {
    expect(formatNumber(1234.56)).toBe("1,234.56");
    expect(formatNumber(1000)).toBe("1,000");
  });

  it("handles zero correctly", () => {
    expect(formatNumber(0)).toBe("0");
  });

  it("handles edge cases and non-finite inputs", () => {
    expect(formatNumber(NaN)).toBe("0");
    expect(formatNumber(Infinity)).toBe("0");
    expect(formatNumber(-Infinity)).toBe("0");
  });

  it("respects decimal configuration", () => {
    expect(formatNumber(1.234, 1, 1)).toBe("1.2");
  });
});

describe("formatCurrency", () => {
  it("formats standard amounts", () => {
    expect(formatCurrency(1234.5)).toBe("$1,234.50");
  });

  it("handles zero correctly", () => {
    expect(formatCurrency(0)).toBe("$0.00");
  });

  it("handles edge cases and non-finite inputs", () => {
    expect(formatCurrency(NaN)).toBe("$0.00");
    expect(formatCurrency(Infinity)).toBe("$0.00");
  });

  it("supports alternate currencies", () => {
    const eur = formatCurrency(100, "EUR");
    expect(eur.includes("100.00")).toBe(true);
    expect(eur.includes("€")).toBe(true);
  });
});

describe("formatPct", () => {
  it("formats normal values correctly", () => {
    expect(formatPct(0.1234)).toBe("12.34%");
    expect(formatPct(1)).toBe("100.00%");
  });

  it("handles zero correctly", () => {
    expect(formatPct(0)).toBe("0.00%");
  });

  it("handles edge cases and non-finite inputs", () => {
    expect(formatPct(NaN)).toBe("0.00%");
    expect(formatPct(Infinity)).toBe("0.00%");
  });
});

describe("formatAuditTimestamp", () => {
  it("formats ISO string into consistent UTC date and time with ISO dateTime", () => {
    const result = formatAuditTimestamp("2026-01-15T12:30:45.000Z");
    expect(result.isValid).toBe(true);
    expect(result.dateTime).toBe("2026-01-15T12:30:45.000Z");
    expect(result.formatted).toBe("2026-01-15 12:30:45 UTC");
    expect(result.timeOnly).toBe("12:30:45 UTC");
  });

  it("handles Date instances", () => {
    const date = new Date("2026-06-20T08:15:00.000Z");
    const result = formatAuditTimestamp(date);
    expect(result.isValid).toBe(true);
    expect(result.dateTime).toBe("2026-06-20T08:15:00.000Z");
    expect(result.formatted).toBe("2026-06-20 08:15:00 UTC");
    expect(result.timeOnly).toBe("08:15:00 UTC");
  });

  it("handles numeric timestamps and numeric strings", () => {
    const ms = Date.UTC(2026, 0, 1, 0, 0, 0);
    const resultNum = formatAuditTimestamp(ms);
    expect(resultNum.isValid).toBe(true);
    expect(resultNum.formatted).toBe("2026-01-01 00:00:00 UTC");

    const resultStr = formatAuditTimestamp(String(ms));
    expect(resultStr.isValid).toBe(true);
    expect(resultStr.formatted).toBe("2026-01-01 00:00:00 UTC");
  });

  it("returns clear fallback for invalid or unparseable timestamps", () => {
    const invalidRes = formatAuditTimestamp("not-a-valid-date");
    expect(invalidRes.isValid).toBe(false);
    expect(invalidRes.dateTime).toBeUndefined();
    expect(invalidRes.formatted).toBe("Invalid timestamp");
    expect(invalidRes.timeOnly).toBe("Invalid timestamp");
  });

  it("returns clear fallback for null, undefined, or empty string", () => {
    expect(formatAuditTimestamp(null)).toEqual({
      formatted: "Invalid timestamp",
      timeOnly: "Invalid timestamp",
      isValid: false,
    });
    expect(formatAuditTimestamp(undefined)).toEqual({
      formatted: "Invalid timestamp",
      timeOnly: "Invalid timestamp",
      isValid: false,
    });
    expect(formatAuditTimestamp("")).toEqual({
      formatted: "Invalid timestamp",
      timeOnly: "Invalid timestamp",
      isValid: false,
    });
  });
});
