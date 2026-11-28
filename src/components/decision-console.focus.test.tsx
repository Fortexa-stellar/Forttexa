import { beforeEach, describe, expect, it, vi } from "vitest";

type Props = Record<string, unknown>;
type TreeNode = { type?: unknown; props?: Props };

const harness = vi.hoisted(() => ({
  stateIndex: 0,
  refIndex: 0,
  states: [] as unknown[],
  setters: [] as Array<(value: unknown) => void>,
  refs: [] as Array<{ current: unknown }>,
  effects: [] as Array<() => void | (() => void)>,
  headingFocus: [vi.fn(), vi.fn(), vi.fn(), vi.fn()],
}));

const freighter = vi.hoisted(() => ({
  isConnected: vi.fn(),
  getNetwork: vi.fn(),
  signTransaction: vi.fn(),
}));

vi.mock("@stellar/freighter-api", () => freighter);

vi.mock("@/lib/auth/use-auth-session", () => ({
  useAuthSession: () => ({ isOperator: true, loading: false }),
}));

vi.mock("@/lib/scenarios/seed", () => ({
  demoScenarios: [
    {
      id: "test-scenario",
      title: "Test Scenario",
      description: "Test description",
      expectedDecision: "ALLOW",
      action: {
        id: "test-action",
        name: "Test Action",
        domain: "test.com",
        amountXLM: 5,
      },
    },
  ],
}));

vi.mock("lucide-react", () => ({
  Loader2: () => null,
  Sparkles: () => null,
  ChevronRight: () => null,
  ChevronLeft: () => null,
  ShieldAlert: () => null,
  Play: () => null,
  Hand: () => null,
  RefreshCcw: () => null,
}));

vi.mock("@/components/ui/alert", () => ({
  Alert: (props: Props) => ({ type: "Alert", props }),
  AlertTitle: (props: Props) => ({ type: "AlertTitle", props }),
  AlertDescription: (props: Props) => ({ type: "AlertDescription", props }),
}));

vi.mock("@/components/ui/button", () => ({
  Button: (props: Props) => ({ type: "Button", props }),
}));

vi.mock("@/components/ui/card", () => ({
  Card: (props: Props) => ({ type: "Card", props }),
  CardHeader: (props: Props) => ({ type: "CardHeader", props }),
  CardTitle: (props: Props) => ({ type: "CardTitle", props }),
  CardDescription: (props: Props) => ({ type: "CardDescription", props }),
  CardContent: (props: Props) => ({ type: "CardContent", props }),
}));

vi.mock("@/components/ui/input", () => ({
  Input: (props: Props) => ({ type: "Input", props }),
}));

vi.mock("@/components/ui/stepper", () => ({
  Stepper: () => null,
}));

vi.mock("@/components/decision-badge", () => ({
  DecisionBadge: () => null,
}));

vi.mock("@/components/decision-result-view", () => ({
  DecisionResultView: () => null,
}));

vi.mock("react", async () => {
  const original = await vi.importActual<typeof import("react")>("react");
  return {
    ...original,
    useState: (initialValue: unknown) => {
      const index = harness.stateIndex++;
      if (harness.states.length <= index) {
        harness.states.push(
          typeof initialValue === "function" ? (initialValue as () => unknown)() : initialValue,
        );
        harness.setters.push((next: unknown) => {
          harness.states[index] =
            typeof next === "function"
              ? (next as (prev: unknown) => unknown)(harness.states[index])
              : next;
        });
      }
      return [harness.states[index], harness.setters[index]];
    },
    useRef: (initialValue: unknown) => {
      const index = harness.refIndex++;
      if (harness.refs.length <= index) {
        harness.refs.push(
          index >= 1 && index <= 4
            ? { current: { focus: harness.headingFocus[index - 1] } }
            : { current: initialValue },
        );
      }
      return harness.refs[index];
    },
    useMemo: (factory: () => unknown) => factory(),
    useEffect: (effect: () => void | (() => void)) => {
      harness.effects.push(effect);
    },
  };
});

import { CardTitle } from "@/components/ui/card";
import { DecisionConsole } from "./decision-console";

const STEP = 0;
const HEADINGS = ["Define intent", "Evaluate", "Human approval", "Execute payment"];

const fetchMock = vi.fn();
global.fetch = fetchMock;

function treeText(node: unknown): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(treeText).join("");
  if (node && typeof node === "object" && "props" in (node as TreeNode)) {
    return treeText((node as TreeNode).props?.children);
  }
  return "";
}

function walk(node: unknown, visit: (node: TreeNode) => void): void {
  if (Array.isArray(node)) {
    node.forEach((child) => walk(child, visit));
    return;
  }
  if (node && typeof node === "object" && "props" in (node as TreeNode)) {
    const tree = node as TreeNode;
    visit(tree);
    walk(tree.props?.children, visit);
  }
}

function findClickable(node: unknown, label: string): TreeNode | undefined {
  if (Array.isArray(node)) {
    for (const child of node) {
      const hit = findClickable(child, label);
      if (hit) return hit;
    }
    return undefined;
  }
  if (node && typeof node === "object" && "props" in (node as TreeNode)) {
    const tree = node as TreeNode;
    if (typeof tree.props?.onClick === "function" && treeText(tree).includes(label)) {
      return tree;
    }
    return findClickable(tree.props?.children, label);
  }
  return undefined;
}

function renderConsole(): TreeNode {
  harness.stateIndex = 0;
  harness.refIndex = 0;
  harness.effects.length = 0;
  const tree = DecisionConsole() as unknown as TreeNode;
  harness.effects.forEach((effect) => effect());
  return tree;
}

function click(tree: TreeNode, label: string): void | Promise<void> {
  const button = findClickable(tree, label);
  expect(button).toBeDefined();
  return (button!.props!.onClick as () => void | Promise<void>)();
}

function heading(tree: TreeNode, label: string): Props {
  let found: Props | undefined;
  walk(tree, (node) => {
    if (node.type === CardTitle && treeText(node.props?.children).includes(label)) {
      found = node.props;
    }
  });
  expect(found, label).toBeDefined();
  return found!;
}

function expectOnlyHeadingFocused(step: number) {
  harness.headingFocus.forEach((focus, index) => {
    if (index === step - 1) {
      expect(focus).toHaveBeenCalledTimes(1);
    } else {
      expect(focus).not.toHaveBeenCalled();
    }
  });
}

function decisionResponse(decision: string) {
  return {
    ok: true,
    json: async () => ({
      result: { decision },
      auditEntry: { id: "test-audit-id" },
      usage: { spentXLM: 0.1, toolCalls: 1 },
    }),
  };
}

async function flush() {
  for (let i = 0; i < 30; i++) {
    await Promise.resolve();
  }
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function evaluate(tree: TreeNode) {
  const pending = click(tree, "Run evaluation");
  await flush();
  await pending;
}

describe("DecisionConsole - Focus Management", () => {
  beforeEach(() => {
    harness.stateIndex = 0;
    harness.refIndex = 0;
    harness.states.length = 0;
    harness.setters.length = 0;
    harness.refs.length = 0;
    harness.effects.length = 0;
    harness.headingFocus.forEach((focus) => focus.mockClear());
    fetchMock.mockReset();
    freighter.isConnected.mockReset().mockResolvedValue({ isConnected: true });
    freighter.getNetwork.mockReset().mockResolvedValue({ networkPassphrase: "TESTNET" });
    freighter.signTransaction.mockReset();
  });

  it("should NOT move focus during initial page render", () => {
    renderConsole();

    harness.headingFocus.forEach((focus) => expect(focus).not.toHaveBeenCalled());
  });

  it("should make all step headings focusable programmatically with tabIndex=-1", () => {
    HEADINGS.forEach((label, index) => {
      harness.states[STEP] = index + 1;
      const tree = renderConsole();
      expect(heading(tree, label).tabIndex).toBe(-1);
    });
  });

  it("should move focus to step 2 heading when clicking Continue from step 1", () => {
    const tree = renderConsole();
    expect(harness.states[STEP]).toBe(1);

    click(tree, "Continue");
    expect(harness.states[STEP]).toBe(2);

    renderConsole();
    expectOnlyHeadingFocused(2);
  });

  it("should move focus to step 1 heading when clicking Back from step 2", () => {
    click(renderConsole(), "Continue");
    expect(harness.states[STEP]).toBe(2);
    renderConsole();

    harness.headingFocus.forEach((focus) => focus.mockClear());
    const step2Tree = renderConsole();
    click(step2Tree, "Back");
    expect(harness.states[STEP]).toBe(1);

    renderConsole();
    expectOnlyHeadingFocused(1);
  });

  it("should move focus to step 4 heading after Run Evaluation completes with ALLOW decision", async () => {
    fetchMock.mockResolvedValueOnce(decisionResponse("ALLOW"));

    click(renderConsole(), "Continue");
    const step2Tree = renderConsole();
    harness.headingFocus.forEach((focus) => focus.mockClear());

    await evaluate(step2Tree);
    expect(harness.states[STEP]).toBe(4);

    renderConsole();
    expectOnlyHeadingFocused(4);
  });

  it("should move focus to step 3 heading after Run Evaluation completes with REQUIRE_APPROVAL decision", async () => {
    fetchMock.mockResolvedValueOnce(decisionResponse("REQUIRE_APPROVAL"));

    click(renderConsole(), "Continue");
    const step2Tree = renderConsole();
    harness.headingFocus.forEach((focus) => focus.mockClear());

    await evaluate(step2Tree);
    expect(harness.states[STEP]).toBe(3);

    renderConsole();
    expectOnlyHeadingFocused(3);
  });

  it("should move focus to step 2 heading when clicking Back from step 3", async () => {
    fetchMock.mockResolvedValueOnce(decisionResponse("REQUIRE_APPROVAL"));

    click(renderConsole(), "Continue");
    await evaluate(renderConsole());
    expect(harness.states[STEP]).toBe(3);
    renderConsole();

    harness.headingFocus.forEach((focus) => focus.mockClear());
    const step3Tree = renderConsole();
    click(step3Tree, "Back");
    expect(harness.states[STEP]).toBe(2);

    renderConsole();
    expectOnlyHeadingFocused(2);
  });
});
