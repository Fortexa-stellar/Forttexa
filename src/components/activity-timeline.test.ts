import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ActivityTimeline } from "@/components/activity-timeline";
import type { AuditEntry } from "@/lib/types/domain";

const entry: AuditEntry = {
  id: "audit-1",
  timestamp: "2026-01-15T12:30:00.000Z",
  action: {
    id: "action-1",
    name: "Research payout",
    kind: "api_payment",
    target: "api.example.com",
    domain: "api.example.com",
    amountXLM: 12,
  },
  decision: "APPROVE",
  explanation: "Within the daily cap.",
  triggeredPolicies: [],
  riskFindings: [],
};

describe("ActivityTimeline", () => {
  it("renders the empty state", () => {
    const html = renderToStaticMarkup(createElement(ActivityTimeline, { entries: [] }));
    expect(html).toContain("No audit entries yet");
  });

  it("renders a populated timeline entry with explicit UTC and semantic time element", () => {
    const html = renderToStaticMarkup(createElement(ActivityTimeline, { entries: [entry] }));
    expect(html).toContain("Research payout");
    expect(html).toContain("Within the daily cap.");
    expect(html).toContain("audit-1");
    expect(html).toContain("APPROVE");
    expect(html).toContain("12 XLM");

    // Explicit UTC displayed
    expect(html).toContain("2026-01-15 12:30:00 UTC");
    expect(html).toContain("12:30:00 UTC");

    // Semantic <time> element with ISO datetime attribute
    expect(html).toContain('<time dateTime="2026-01-15T12:30:00.000Z">2026-01-15 12:30:00 UTC</time>');
    expect(html).toContain('<time dateTime="2026-01-15T12:30:00.000Z">12:30:00 UTC</time>');
  });

  it("renders a clear fallback for invalid timestamps", () => {
    const invalidEntry: AuditEntry = {
      ...entry,
      id: "audit-invalid",
      timestamp: "not-a-valid-date",
    };
    const html = renderToStaticMarkup(createElement(ActivityTimeline, { entries: [invalidEntry] }));
    expect(html).toContain("Invalid timestamp");
    expect(html).toContain("<time>Invalid timestamp</time>");
    expect(html).not.toContain("NaN");
  });

  it("renders a clear fallback for empty timestamp", () => {
    const emptyEntry: AuditEntry = {
      ...entry,
      id: "audit-empty",
      timestamp: "",
    };
    const html = renderToStaticMarkup(createElement(ActivityTimeline, { entries: [emptyEntry] }));
    expect(html).toContain("Invalid timestamp");
    expect(html).toContain("<time>Invalid timestamp</time>");
  });
});
