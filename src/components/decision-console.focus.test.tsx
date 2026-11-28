import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DecisionConsole } from "./decision-console";

// Mock dependencies
jest.mock("@/lib/auth/use-auth-session", () => ({
  useAuthSession: () => ({ isOperator: true, loading: false }),
}));

jest.mock("@/lib/scenarios/seed", () => ({
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

describe("DecisionConsole - Focus Management", () => {
  beforeEach(() => {
    // Mock fetch for API calls
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("should move focus to step 2 heading when clicking Continue from step 1", async () => {
    const user = userEvent.setup();
    render(<DecisionConsole />);

    // Step 1 should be visible
    const step1Heading = screen.getByRole("heading", { name: /define intent/i });
    expect(step1Heading).toBeInTheDocument();

    // Click Continue button
    const continueButton = screen.getByRole("button", { name: /continue/i });
    await user.click(continueButton);

    // Wait for step 2 to render
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /evaluate/i })).toBeInTheDocument();
    });

    // Check that focus moved to step 2 heading
    const step2Heading = screen.getByRole("heading", { name: /evaluate/i });
    expect(step2Heading).toHaveFocus();
  });

  it("should move focus to step 1 heading when clicking Back from step 2", async () => {
    const user = userEvent.setup();
    render(<DecisionConsole />);

    // Navigate to step 2
    const continueButton = screen.getByRole("button", { name: /continue/i });
    await user.click(continueButton);

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /evaluate/i })).toBeInTheDocument();
    });

    // Click Back button
    const backButton = screen.getByRole("button", { name: /back/i });
    await user.click(backButton);

    // Wait for step 1 to render
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /define intent/i })).toBeInTheDocument();
    });

    // Check that focus moved to step 1 heading
    const step1Heading = screen.getByRole("heading", { name: /define intent/i });
    expect(step1Heading).toHaveFocus();
  });

  it("should NOT move focus during initial page render", () => {
    render(<DecisionConsole />);

    const step1Heading = screen.getByRole("heading", { name: /define intent/i });
    
    // Focus should not be on the heading initially
    expect(step1Heading).not.toHaveFocus();
  });

  it("should make all step headings focusable programmatically with tabIndex=-1", async () => {
    const user = userEvent.setup();
    render(<DecisionConsole />);

    // Check step 1 heading has tabIndex=-1
    const step1Heading = screen.getByRole("heading", { name: /define intent/i });
    expect(step1Heading).toHaveAttribute("tabindex", "-1");

    // Navigate to step 2 and check
    await user.click(screen.getByRole("button", { name: /continue/i }));
    
    await waitFor(() => {
      const step2Heading = screen.getByRole("heading", { name: /evaluate/i });
      expect(step2Heading).toHaveAttribute("tabindex", "-1");
    });
  });

  it("should move focus to step 4 heading after Run Evaluation completes with ALLOW decision", async () => {
    const user = userEvent.setup();
    
    // Mock successful decision API response
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        result: { decision: "ALLOW" },
        auditEntry: { id: "test-audit-id" },
        usage: { spentXLM: 0.1, toolCalls: 1 },
      }),
    });

    render(<DecisionConsole />);

    // Navigate to step 2
    await user.click(screen.getByRole("button", { name: /continue/i }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /evaluate/i })).toBeInTheDocument();
    });

    // Click Run evaluation (this will transition to step 4 for ALLOW decision)
    const runButton = screen.getByRole("button", { name: /run evaluation/i });
    await user.click(runButton);

    // Wait for step 4 to render
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /execute payment/i })).toBeInTheDocument();
    });

    // Focus should move to step 4 heading (user-triggered async action)
    const step4Heading = screen.getByRole("heading", { name: /execute payment/i });
    expect(step4Heading).toHaveFocus();
  });

  it("should move focus to step 3 heading after Run Evaluation completes with REQUIRE_APPROVAL decision", async () => {
    const user = userEvent.setup();
    
    // Mock decision API response with REQUIRE_APPROVAL
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        result: { decision: "REQUIRE_APPROVAL" },
        auditEntry: { id: "test-audit-id" },
        usage: { spentXLM: 0.1, toolCalls: 1 },
      }),
    });

    render(<DecisionConsole />);

    // Navigate to step 2
    await user.click(screen.getByRole("button", { name: /continue/i }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /evaluate/i })).toBeInTheDocument();
    });

    // Click Run evaluation
    const runButton = screen.getByRole("button", { name: /run evaluation/i });
    await user.click(runButton);

    // Wait for step 3 to render
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /human approval/i })).toBeInTheDocument();
    });

    // Focus should move to step 3 heading
    const step3Heading = screen.getByRole("heading", { name: /human approval/i });
    expect(step3Heading).toHaveFocus();
  });

  it("should move focus to step 2 heading when clicking Back from step 3", async () => {
    const user = userEvent.setup();
    
    // Mock decision API response with REQUIRE_APPROVAL to reach step 3
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        result: { decision: "REQUIRE_APPROVAL" },
        auditEntry: { id: "test-audit-id" },
        usage: { spentXLM: 0.1, toolCalls: 1 },
      }),
    });

    render(<DecisionConsole />);

    // Navigate to step 2
    await user.click(screen.getByRole("button", { name: /continue/i }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /evaluate/i })).toBeInTheDocument();
    });

    // Run evaluation to reach step 3
    await user.click(screen.getByRole("button", { name: /run evaluation/i }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /human approval/i })).toBeInTheDocument();
    });

    // Click Back button from step 3
    const backButton = screen.getByRole("button", { name: /back/i });
    await user.click(backButton);

    // Wait for step 2 to render
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /evaluate/i })).toBeInTheDocument();
    });

    // Focus should move to step 2 heading
    const step2Heading = screen.getByRole("heading", { name: /evaluate/i });
    expect(step2Heading).toHaveFocus();
  });
});
