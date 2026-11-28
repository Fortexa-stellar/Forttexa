export const AUDIT_PAGE_MIN_LIMIT = 1;
export const AUDIT_PAGE_MAX_LIMIT = 100;
export const AUDIT_PAGE_DEFAULT_LIMIT = 50;
export const AUDIT_PAGE_MAX_OFFSET = 10000;

export type AuditPagination = {
  limit: number;
  offset: number;
};

export type AuditPaginationResult =
  | { ok: true; pagination: AuditPagination }
  | { ok: false; code: "invalid_pagination_parameters" };

function parseUnsignedInteger(value: string): number | null {
  if (!/^(0|[1-9]\d*)$/.test(value)) {
    return null;
  }

  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

export function parseAuditPagination(params: URLSearchParams): AuditPaginationResult {
  const limitValues = params.getAll("limit");
  const offsetValues = params.getAll("offset");
  const cursorValues = params.getAll("cursor");

  if (
    limitValues.length > 1 ||
    offsetValues.length > 1 ||
    cursorValues.length > 1 ||
    (offsetValues.length > 0 && cursorValues.length > 0)
  ) {
    return { ok: false, code: "invalid_pagination_parameters" };
  }

  const limit = limitValues.length === 0
    ? AUDIT_PAGE_DEFAULT_LIMIT
    : parseUnsignedInteger(limitValues[0]);
  const offsetRaw = offsetValues[0] ?? cursorValues[0] ?? "0";
  const offset = parseUnsignedInteger(offsetRaw);

  if (
    limit === null ||
    limit < AUDIT_PAGE_MIN_LIMIT ||
    limit > AUDIT_PAGE_MAX_LIMIT ||
    offset === null ||
    offset > AUDIT_PAGE_MAX_OFFSET
  ) {
    return { ok: false, code: "invalid_pagination_parameters" };
  }

  return { ok: true, pagination: { limit, offset } };
}