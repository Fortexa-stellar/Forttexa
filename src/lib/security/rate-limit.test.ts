import { rm } from "node:fs/promises";
import path from "node:path";
import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

const sharedStatePath = path.join(process.cwd(), ".fortexa", "rate-limit-shared.test.json");

function requestFromIp(ip: string) {
  return new NextRequest("http://localhost/api/test", {
    method: "GET",
    headers: {
      "x-forwarded-for": ip,
    },
  });
}

describe("rate limit shared state", () => {
  afterEach(async () => {
    delete process.env.FORTEXA_SHARED_STATE_PATH;
    await rm(sharedStatePath, { force: true });
    vi.resetModules();
  });

  it("persists bucket state across module reloads", async () => {
    process.env.FORTEXA_SHARED_STATE_PATH = sharedStatePath;

    const firstModule = await import("@/lib/security/rate-limit");
    await firstModule.resetRateLimitStore();

    const firstResult = await firstModule.consumeRateLimit(requestFromIp("10.0.0.4"), {
      key: "shared-test",
      limit: 1,
      windowMs: 60_000,
    });

    expect(firstResult.ok).toBe(true);

    vi.resetModules();

    const secondModule = await import("@/lib/security/rate-limit");
    const secondResult = await secondModule.consumeRateLimit(requestFromIp("10.0.0.4"), {
      key: "shared-test",
      limit: 1,
      windowMs: 60_000,
    });

    expect(secondResult.ok).toBe(false);
    expect(secondResult.retryAfterSeconds).toBeGreaterThan(0);
  });
});

describe("rate limit Retry-After boundaries", () => {
  afterEach(async () => {
    vi.useRealTimers();
    vi.resetModules();
  });

  it("derives Retry-After from the remaining window and omits it when allowed", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));

    const rateLimit = await import("@/lib/security/rate-limit");
    await rateLimit.resetRateLimitStore();

    const config = { key: "retry-after-boundary", limit: 1, windowMs: 5_000 };
    const allowed = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.20"), config);
    expect(allowed.ok).toBe(true);
    expect(rateLimit.rateLimitHeaders(allowed)["Retry-After"]).toBeUndefined();

    const rejected = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.20"), config);
    expect(rejected.ok).toBe(false);
    expect(rejected.retryAfterSeconds).toBe(5);
    expect(rateLimit.rateLimitHeaders(rejected)["Retry-After"]).toBe("5");

    // 1ms before window end still reports a 1-second delay-seconds value.
    vi.setSystemTime(new Date(rejected.resetAt - 1));
    const nearExpiry = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.20"), config);
    expect(nearExpiry.ok).toBe(false);
    expect(nearExpiry.retryAfterSeconds).toBe(1);
    expect(rateLimit.rateLimitHeaders(nearExpiry)["Retry-After"]).toBe("1");

    // Exactly at reset the bucket opens again and Retry-After stays absent.
    vi.setSystemTime(new Date(rejected.resetAt));
    const afterReset = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.20"), config);
    expect(afterReset.ok).toBe(true);
    expect(rateLimit.rateLimitHeaders(afterReset)["Retry-After"]).toBeUndefined();
  });
});

describe("rate limit metrics", () => {
  // Both modules are imported dynamically so they resolve from the same module
  // registry; the shared-state test above calls `vi.resetModules()`.
  async function loadModules() {
    const rateLimit = await import("@/lib/security/rate-limit");
    const metrics = await import("@/lib/observability/metrics");
    await rateLimit.resetRateLimitStore();
    metrics.resetMetrics();
    return { rateLimit, metrics };
  }

  it("counts rejections so the ops dashboard and the metrics scrape agree", async () => {
    const { rateLimit, metrics } = await loadModules();
    const config = { key: "metrics-test", limit: 2, windowMs: 60_000 };

    const first = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.9"), config);
    const second = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.9"), config);
    const rejected = await rateLimit.consumeRateLimit(requestFromIp("10.0.0.9"), config);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(rejected.ok).toBe(false);

    expect(metrics.getRateLimitRejectionCount()).toBe(1);
    expect(metrics.getMetricsSnapshot().counters.rateLimit).toBe(1);
  });

  it("leaves the counter at zero while the bucket still has capacity", async () => {
    const { rateLimit, metrics } = await loadModules();

    await rateLimit.consumeRateLimit(requestFromIp("10.0.0.10"), {
      key: "metrics-test-no-rejection",
      limit: 5,
      windowMs: 60_000,
    });

    expect(metrics.getRateLimitRejectionCount()).toBe(0);
  });
});
