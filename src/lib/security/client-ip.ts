/**
 * Resolve the client IP used for rate limits and login lockouts.
 *
 * Forwarded / X-Forwarded-For are ignored unless FORTEXA_TRUSTED_PROXY is
 * explicitly enabled. Spoofable forwarding headers must never choose the
 * security-state key on a publicly reachable process.
 */

const UNKNOWN_IP = "unknown";

function isTruthyEnv(value: string | undefined) {
  if (!value) {
    return false;
  }

  const normalized = value.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

export function isTrustedProxyEnabled(env: NodeJS.ProcessEnv = process.env) {
  return isTruthyEnv(env.FORTEXA_TRUSTED_PROXY);
}

/**
 * Normalize an address before it is used as a security-state lookup key.
 * Strips quotes/brackets, drops trailing ports on IPv4, and unwraps
 * IPv4-mapped IPv6 forms so equivalent addresses share one bucket.
 */
export function normalizeClientIp(raw: string | null | undefined): string {
  if (!raw) {
    return UNKNOWN_IP;
  }

  let value = raw.trim();
  if (!value) {
    return UNKNOWN_IP;
  }

  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1).trim();
  }

  if (value.startsWith("[") && value.includes("]")) {
    value = value.slice(1, value.indexOf("]")).trim();
  }

  value = value.toLowerCase();

  if (value.startsWith("::ffff:")) {
    value = value.slice("::ffff:".length);
  }

  // IPv4 with an explicit port (proxies sometimes append :port).
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) {
    value = value.replace(/:\d+$/, "");
  }

  return value || UNKNOWN_IP;
}

function firstForwardedForAddress(headers: Headers): string | null {
  const forwardedFor = headers.get("x-forwarded-for");
  if (!forwardedFor) {
    return null;
  }

  const first = forwardedFor.split(",")[0]?.trim();
  return first || null;
}

function firstForwardedAddress(headers: Headers): string | null {
  const forwarded = headers.get("forwarded");
  if (!forwarded) {
    return null;
  }

  // RFC 7239: Forwarded: for=1.2.3.4;proto=https, for=10.0.0.1
  for (const part of forwarded.split(",")) {
    for (const directive of part.split(";")) {
      const trimmed = directive.trim();
      const match = /^for=(.+)$/i.exec(trimmed);
      if (!match) {
        continue;
      }

      let candidate = match[1]?.trim() ?? "";
      if (
        (candidate.startsWith('"') && candidate.endsWith('"')) ||
        (candidate.startsWith("'") && candidate.endsWith("'"))
      ) {
        candidate = candidate.slice(1, -1).trim();
      }

      if (candidate) {
        return candidate;
      }
    }
  }

  return null;
}

function directClientIp(headers: Headers): string {
  const realIp = headers.get("x-real-ip")?.trim();
  return normalizeClientIp(realIp || UNKNOWN_IP);
}

/**
 * Select and normalize the client address used for security-state lookups.
 * When trusted proxies are disabled (default), Forwarded and X-Forwarded-For
 * are ignored so callers cannot pick their own rate-limit / lockout key.
 */
export function resolveClientIp(headers: Headers, env: NodeJS.ProcessEnv = process.env): string {
  if (isTrustedProxyEnabled(env)) {
    const forwarded =
      firstForwardedForAddress(headers) ?? firstForwardedAddress(headers) ?? headers.get("x-real-ip");
    return normalizeClientIp(forwarded);
  }

  return directClientIp(headers);
}
