import { NextRequest, NextResponse } from "next/server";

import { DuplicateRuleError, validateNoDuplicateRules } from "@/lib/policy/engine";
import { policyConfigSchema } from "@/lib/validation/schemas";
import { securityHeadersForRequest } from "@/lib/security/headers";

/**
 * POST /api/policy/validate
 *
 * Validates a policy JSON against the schema without saving.
 * Useful for preview/diff functionality.
 *
 * Body: { policy: unknown }
 * Response: { valid: boolean; data?: unknown; errors?: string[] }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { policy } = body;

    if (!policy) {
      return NextResponse.json(
        {
          valid: false,
          errors: ["No policy data provided"],
        },
        { status: 400, headers: securityHeadersForRequest(request) }
      );
    }

    // Validate against schema
    const result = policyConfigSchema.safeParse(policy);

    if (!result.success) {
      const errors = result.error.issues.map((issue) => ({
        path: issue.path.join(".") || "root",
        message: issue.message,
      }));

      return NextResponse.json(
        {
          valid: false,
          errors: errors.map((e) => `${e.path}: ${e.message}`),
        },
        { status: 400, headers: securityHeadersForRequest(request) }
      );
    }

    // Check for duplicate rule identifiers
    try {
      validateNoDuplicateRules(result.data);
    } catch (error) {
      if (error instanceof DuplicateRuleError) {
        return NextResponse.json(
          {
            valid: false,
            errors: [error.message],
            code: "DUPLICATE_RULE_IDENTIFIER",
            field: error.field,
            duplicateValue: error.value,
          },
          { status: 422, headers: securityHeadersForRequest(request) }
        );
      }
      throw error;
    }

    // Valid policy
    return NextResponse.json(
      {
        valid: true,
        data: result.data,
      },
      { status: 200, headers: securityHeadersForRequest(request) }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";

    return NextResponse.json(
      {
        valid: false,
        errors: [message],
      },
      { status: 500, headers: securityHeadersForRequest(request) }
    );
  }
}