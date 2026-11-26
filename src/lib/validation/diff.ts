import { evaluateDecision } from "@/lib/decision/engine";
import type {
  AgentAction,
  AuditEntry,
  DailyUsage,
  DecisionType,
  PolicyConfig,
} from "@/lib/types/domain";

export {
  generatePolicyDiff,
  formatDiffChange,
  groupDiffChanges,
  type DiffChange,
  type DiffChangeType,
  type PolicyDiff,
} from "@/lib/validation/policy-diff";

import { generatePolicyDiff, type DiffChange } from "@/lib/validation/policy-diff";

/** Decisions that let a payment proceed. */
export function isAllowDecision(decision: DecisionType): boolean {
  return decision === "APPROVE" || decision === "WARN";
}

/**
 * Cap on how many open allow decisions are re-run for a single report so a
 * large audit history cannot stall this read. The newest decisions are kept.
 */
export const MAX_OPEN_ALLOW_DECISIONS = 100;

/** An allow decision that is still open for a payment. */
export interface OpenAllowDecision {
  /** Id of the payment/decision record (audit entry) carrying the allow. */
  paymentId: string;
  action: AgentAction;
  /** Decision recorded for the payment the last time it was evaluated. */
  decision: DecisionType;
  /** Daily usage snapshot the payment was evaluated against. */
  usage: DailyUsage;
}

/** A payment whose result would change under the candidate policy. */
export interface FlippedPayment {
  paymentId: string;
  /** Rule id (the diff path) of the change responsible for the flip. */
  ruleId: string;
  from: DecisionType;
  to: DecisionType;
}

/** Read-only report of how a candidate policy would flip open allow decisions. */
export interface DecisionImpactReport {
  /** Payment ids whose result would change from an allow to a denial. */
  flippedIds: string[];
  flips: FlippedPayment[];
  hasDecisionChange: boolean;
  /** Explicit "no decision change" status when the candidate flips nothing. */
  status: "decision change" | "no decision change";
}

const RULE_LIST_FIELDS = [
  "allowedDomains",
  "blockedDomains",
  "allowedTools",
  "blockedTools",
] as const;

type RuleListField = (typeof RULE_LIST_FIELDS)[number];

function isRuleListField(field: string): field is RuleListField {
  return (RULE_LIST_FIELDS as readonly string[]).includes(field);
}

/**
 * Apply one diff change (one rule id) to a policy and return the patched copy.
 * The input policy is never mutated.
 */
function applyRuleChange(policy: PolicyConfig, change: DiffChange): PolicyConfig {
  const bracketIndex = change.path.indexOf("[");

  if (bracketIndex !== -1) {
    const field = change.path.slice(0, bracketIndex);
    if (!isRuleListField(field)) {
      return policy;
    }

    const current = policy[field];
    const next =
      change.type === "added"
        ? [...current, String(change.newValue)]
        : current.filter((item) => item !== change.oldValue);

    return { ...policy, [field]: next };
  }

  switch (change.path) {
    case "perTxCapXLM":
      return { ...policy, perTxCapXLM: Number(change.newValue) };
    case "dailyCapXLM":
      return { ...policy, dailyCapXLM: Number(change.newValue) };
    case "maxToolCallsPerDay":
      return { ...policy, maxToolCallsPerDay: Number(change.newValue) };
    case "riskThreshold":
      return { ...policy, riskThreshold: Number(change.newValue) };
    case "allowedHours":
      return { ...policy, allowedHours: change.newValue as PolicyConfig["allowedHours"] };
    default:
      return policy;
  }
}

/**
 * Collect the open allow decisions from audit entries (newest first).
 *
 * A decision stays open only while it is the latest recorded result for its
 * action: a later decision supersedes the earlier one, and a payment whose
 * latest result is a denial is not an open allow.
 */
export function openAllowDecisions(
  entries: AuditEntry[],
  usage: DailyUsage,
): OpenAllowDecision[] {
  const seen = new Set<string>();
  const open: OpenAllowDecision[] = [];

  for (const entry of entries) {
    if (seen.has(entry.action.id)) {
      continue;
    }
    seen.add(entry.action.id);

    if (!isAllowDecision(entry.decision)) {
      continue;
    }

    open.push({
      paymentId: entry.id,
      action: entry.action,
      decision: entry.decision,
      usage,
    });
  }

  return open;
}

/**
 * Apply the rule changes one at a time until one of them turns the allow into
 * a denial. That change is the rule id responsible for the flip.
 */
async function attributeRuleChange(params: {
  activePolicy: PolicyConfig;
  changes: DiffChange[];
  action: AgentAction;
  usage: DailyUsage;
}): Promise<string> {
  const { activePolicy, changes, action, usage } = params;
  let current = activePolicy;

  for (const change of changes) {
    current = applyRuleChange(current, change);
    const result = await evaluateDecision(action, current, usage);
    if (!isAllowDecision(result.decision)) {
      return change.path;
    }
  }

  // Applying every change reproduces the candidate, which is already known to
  // deny, so this fallback only guards against a change that could not apply.
  return changes[changes.length - 1]?.path ?? "policy";
}

/**
 * Re-run open allow decisions against a candidate policy and report which
 * payments would flip to a denial, plus the rule id responsible.
 *
 * Pure read: the candidate is evaluated but never activated. Every payment is
 * re-checked against the active policy first so only candidate-caused flips
 * are reported.
 */
export async function diffDecisionImpact(params: {
  activePolicy: PolicyConfig;
  candidatePolicy: PolicyConfig;
  decisions: OpenAllowDecision[];
}): Promise<DecisionImpactReport> {
  const { activePolicy, candidatePolicy, decisions } = params;
  const changes = generatePolicyDiff(activePolicy, candidatePolicy).changes;
  const flips: FlippedPayment[] = [];

  if (changes.length > 0) {
    for (const decision of decisions.slice(0, MAX_OPEN_ALLOW_DECISIONS)) {
      if (!isAllowDecision(decision.decision)) {
        continue;
      }

      const before = await evaluateDecision(decision.action, activePolicy, decision.usage);
      if (!isAllowDecision(before.decision)) {
        // Already denied by the active policy: not a candidate-caused flip.
        continue;
      }

      const after = await evaluateDecision(decision.action, candidatePolicy, decision.usage);
      if (isAllowDecision(after.decision)) {
        continue;
      }

      flips.push({
        paymentId: decision.paymentId,
        ruleId: await attributeRuleChange({
          activePolicy,
          changes,
          action: decision.action,
          usage: decision.usage,
        }),
        from: before.decision,
        to: after.decision,
      });
    }
  }

  const flippedIds = flips.map((flip) => flip.paymentId);

  return {
    flippedIds,
    flips,
    hasDecisionChange: flippedIds.length > 0,
    status: flippedIds.length > 0 ? "decision change" : "no decision change",
  };
}
