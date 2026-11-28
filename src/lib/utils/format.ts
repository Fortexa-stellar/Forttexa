export function truncateMiddle(value: string, left = 6, right = 6) {
  if (value.length <= left + right + 3) {
    return value;
  }
  return `${value.slice(0, left)}...${value.slice(-right)}`;
}

export function decisionVariant(decision: string): "approve" | "warn" | "require" | "block" | "default" {
  if (decision === "APPROVE") return "approve";
  if (decision === "WARN") return "warn";
  if (decision === "REQUIRE_APPROVAL") return "require";
  if (decision === "BLOCK") return "block";
  return "default";
}

export function formatNumber(value: number, minDecimals = 0, maxDecimals = 2): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "0";
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: minDecimals,
    maximumFractionDigits: maxDecimals,
  }).format(value);
}

export function formatCurrency(value: number, currency = "USD"): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "$0.00";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(value);
}

export function formatPct(value: number): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "0.00%";
  return `${(value * 100).toFixed(2)}%`;
}

export interface FormattedAuditTimestamp {
  /** Full ISO 8601 string suitable for the HTML <time dateTime="..."> attribute. */
  dateTime?: string;
  /** Human-readable date and time with explicit UTC timezone (e.g. "2026-01-15 12:30:00 UTC"). */
  formatted: string;
  /** Human-readable time-only with explicit UTC timezone (e.g. "12:30:00 UTC"). */
  timeOnly: string;
  /** Whether the input parsed into a valid timestamp. */
  isValid: boolean;
}

/**
 * Formats an audit timestamp into consistent UTC display strings and an ISO dateTime string.
 * Returns a clear fallback ("Invalid timestamp") if the timestamp is missing, empty, or unparseable.
 */
export function formatAuditTimestamp(
  raw: string | number | Date | null | undefined
): FormattedAuditTimestamp {
  if (raw === null || raw === undefined || raw === "") {
    return {
      formatted: "Invalid timestamp",
      timeOnly: "Invalid timestamp",
      isValid: false,
    };
  }

  let date: Date;
  if (raw instanceof Date) {
    date = raw;
  } else if (typeof raw === "number") {
    date = new Date(raw);
  } else if (typeof raw === "string" && /^\d+$/.test(raw.trim())) {
    date = new Date(Number(raw.trim()));
  } else {
    date = new Date(String(raw));
  }

  if (Number.isNaN(date.getTime())) {
    return {
      formatted: "Invalid timestamp",
      timeOnly: "Invalid timestamp",
      isValid: false,
    };
  }

  const iso = date.toISOString();

  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  const seconds = String(date.getUTCSeconds()).padStart(2, "0");

  const formatted = `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
  const timeOnly = `${hours}:${minutes}:${seconds} UTC`;

  return {
    dateTime: iso,
    formatted,
    timeOnly,
    isValid: true,
  };
}
