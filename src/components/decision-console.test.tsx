import { beforeEach, describe, expect, it, vi } from "vitest";

// The wallet is stubbed through the Freighter module mock and the submit route
// through global fetch, so no extension prompt or network request is opened.

const freighter = vi.hoisted(() => ({
  isConnected: vi.fn(),
  getNetwork: vi.fn(),
  signTransaction: vi.fn(),
}));

vi.mock("@stellar/freighter-api", () => freighter);

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
  Alert: (props: Record<string, unknown>) => ({ type: "Alert", props }),
  AlertTitle: (props: Record<string, unknown>) => ({ type: "AlertTitle", props }),
  AlertDescription: (props: Record<string, unknown>) => ({ type: "AlertDescription", props }),
}));

vi.mock("@/components/ui/button", () => ({
  Button: (props: Record<string, unknown>) => ({ type: "Button", props }),
}));

vi.mock("@/components/ui/card", () => ({
  Card: (props: Record<string, unknown>) => ({ type: "Card", props }),
  CardHeader: (props: Record<string, unknown>) => ({ type: "CardHeader", props }),
  CardTitle: (props: Record<string, unknown>) => ({ type: "CardTitle", props }),
  CardDescription: (props: Record<string, unknown>) => ({ type: "CardDescription", props }),
  CardContent: (props: Record<string, unknown>) => ({ type: "CardContent", props }),
}));

vi.mock("@/components/ui/input", () => ({
  Input: (props: Record<string, unknown>) => ({ type: "Input", props }),
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

vi.mock("@/lib/auth/use-auth-session", () => ({
  useAuthSession: () => ({ isOperator: true, loading: false }),
}));

// Index-addressed hook storage, same approach as the other component tests.
let hookIndex = 0;
let refIndex = 0;
const states: unknown[] = [];
const setters: Array<(value: unknown) => void> = [];
const refs: Array<{ current: unknown }> = [];

vi.mock("react", async () => {
  const original = await vi.importActual<typeof import("react")>("react");
  return {
    ...original,
    useState: (initialValue: unknown) => {
      const index = hookIndex;
      hookIndex += 1;
      if (states.length <= index) {
        const value = typeof initialValue === "function" ? (initialValue as () => unknown)() : initialValue;
        states.push(value);
        setters.push((next: unknown) => {
          states[index] = typeof next === "function" ? (next as (prev: unknown) => unknown)(states[index]) : next;
        });
      }
      return [states[index], setters[index]];
    },
    useRef: (initialValue: unknown) => {
      const index = refIndex;
      refIndex += 1;
      if (refs.length <= index) {
        refs.push({ current: initialValue });
      }
      return refs[index];
    },
    useMemo: (factory: () => unknown) => factory(),
    useEffect: () => {},
  };
});

import { DecisionConsole } from "./decision-console";

const DESTINATION = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";
const UNSIGNED_XDR = "AAAAunsigned-envelope";

// State slots in declaration order inside DecisionConsole.
const STEP = 0;
const DESTINATION_SLOT = 3;
const EXECUTE_AMOUNT = 4;
const DECISION_DATA = 5;
const AUDIT_ENTRY_ID = 6;
const BUILD_AUTHORIZATION = 7;
const QUOTE_EXPIRES_AT = 8;
const UNSIGNED_XDR_SLOT = 12;
const SIGNED_XDR_SLOT = 13;

const fetchMock = vi.fn();
global.fetch = fetchMock;

type Tree = { props?: Record<string, unknown> };

async function flush() {
  for (let i = 0; i < 30; i++) {
    await Promise.resolve();
  }
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function renderConsole(): Tree {
  hookIndex = 0;
  refIndex = 0;
  return DecisionConsole() as unknown as Tree;
}

function treeText(node: unknown): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(treeText).join("");
  if (node && typeof node === "object" && "props" in (node as Tree)) {
    return treeText((node as Tree).props?.children);
  }
  return "";
}

function findClickable(node: unknown, label: string): Tree | undefined {
  if (Array.isArray(node)) {
    for (const child of node) {
      const hit = findClickable(child, label);
      if (hit) return hit;
    }
    return undefined;
  }
  if (node && typeof node === "object" && "props" in (node as Tree)) {
    const tree = node as Tree;
    if (typeof tree.props?.onClick === "function" && treeText(tree).includes(label)) {
      return tree;
    }
    return findClickable(tree.props?.children, label);
  }
  return undefined;
}

/** Put the console on the Execute step with a prepared, unsigned XDR. */
function renderExecutableStep() {
  renderConsole();
  states[STEP] = 4;
  states[DESTINATION_SLOT] = DESTINATION;
  states[EXECUTE_AMOUNT] = "5";
  states[DECISION_DATA] = {
    result: { decision: "ALLOW" },
    auditEntry: { id: "audit-1" },
    usage: { spentXLM: 0, toolCalls: 1 },
  };
  states[AUDIT_ENTRY_ID] = "audit-1";
  states[BUILD_AUTHORIZATION] = "build-authorization";
  states[QUOTE_EXPIRES_AT] = new Date(Date.now() + 60_000).toISOString();
  states[UNSIGNED_XDR_SLOT] = UNSIGNED_XDR;
  states[SIGNED_XDR_SLOT] = UNSIGNED_XDR;
  return renderConsole();
}

beforeEach(() => {
  states.length = 0;
  setters.length = 0;
  refs.length = 0;
  fetchMock.mockReset();
  freighter.isConnected.mockReset().mockResolvedValue({ isConnected: true });
  freighter.getNetwork.mockReset().mockResolvedValue({ networkPassphrase: "TESTNET" });
  freighter.signTransaction.mockReset();
  fetchMock.mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({
      payment: { hash: "abc123" },
      explorerUrl: "https://stellar.expert/explorer/testnet/tx/abc123",
    }),
  });
});

describe("DecisionConsole evaluation", () => {
  it.each([false, true])("blocks same-render duplicate requests and unlocks after ok=%s", async (ok) => {
    let resolveResponse!: (value: unknown) => void;
    const response = {
      ok,
      json: async () => ok
        ? { result: { decision: "BLOCK" }, auditEntry: { id: "audit-eval" } }
        : { error: "Evaluation failed" },
    };
    fetchMock
      .mockImplementationOnce(() => new Promise((resolve) => { resolveResponse = resolve; }))
      .mockResolvedValue(response);

    renderConsole();
    states[STEP] = 2;
    const button = findClickable(renderConsole(), "Run evaluation");
    expect(button?.props?.disabled).toBe(false);
    const click = button!.props!.onClick as () => Promise<void>;
    const first = click();
    await click();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/decision");
    expect(findClickable(renderConsole(), "Run evaluation")?.props?.disabled).toBe(true);

    resolveResponse(response);
    await first;
    expect(findClickable(renderConsole(), "Run evaluation")?.props?.disabled).toBe(false);
    await click();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("DecisionConsole wallet signing", () => {
  it("opens one Freighter prompt for repeated clicks and restores the action after completion", async () => {
    let resolveSign!: (value: unknown) => void;
    freighter.signTransaction.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSign = resolve;
        })
    );

    const tree = renderExecutableStep();
    const signButton = findClickable(tree, "Sign & submit");
    expect(signButton).toBeDefined();
    expect(signButton!.props!.disabled).toBe(false);

    (signButton!.props!.onClick as () => void)();
    await flush();
    expect(freighter.signTransaction).toHaveBeenCalledTimes(1);

    // The second click lands before React re-renders the disabled button.
    (signButton!.props!.onClick as () => void)();
    await flush();
    expect(freighter.signTransaction).toHaveBeenCalledTimes(1);

    const pending = renderConsole();
    const pendingButton = findClickable(pending, "Waiting for Freighter");
    expect(pendingButton).toBeDefined();
    expect(pendingButton!.props!.disabled).toBe(true);

    resolveSign({ signedTxXdr: "AAAA-signed-envelope", signerAddress: "" });
    await flush();

    const settled = renderConsole();
    const restored = findClickable(settled, "Sign & submit");
    expect(restored).toBeDefined();
    expect(restored!.props!.disabled).toBe(false);
    expect(states[SIGNED_XDR_SLOT]).toBe("AAAA-signed-envelope");
  });

  it("restores the signing action after the wallet cancels", async () => {
    freighter.signTransaction.mockResolvedValue({ error: { message: "User rejected the request" } });

    const tree = renderExecutableStep();
    const signButton = findClickable(tree, "Sign & submit");
    (signButton!.props!.onClick as () => void)();
    await flush();

    const settled = renderConsole();
    const retry = findClickable(settled, "Retry sign");
    expect(retry).toBeDefined();
    expect(retry!.props!.disabled).toBe(false);

    // A retry after cancellation may prompt again.
    (retry!.props!.onClick as () => void)();
    await flush();
    expect(freighter.signTransaction).toHaveBeenCalledTimes(2);
  });
});
