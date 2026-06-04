import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { CopilotPage } from "./CopilotPage";

const mockSummarize = vi.fn();
const mockAsk = vi.fn();
const mockConfirm = vi.fn();

vi.mock("../services/copilot", () => ({
  copilotApi: {
    summarize: (...args: unknown[]) => mockSummarize(...args),
    ask: (...args: unknown[]) => mockAsk(...args),
    confirm: (...args: unknown[]) => mockConfirm(...args),
    propose: vi.fn(),
  },
}));

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CopilotPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("CopilotPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSummarize.mockResolvedValue({
      data: {
        session_id: "s1",
        entity_id: "host-1",
        summary: "Elevated risk on host-1.",
        grounded: true,
        citations: ["score:s1", "audit:e1"],
        citation_provenance: { "score:s1": "deadbeef" },
        proposals: [
          {
            proposal_id: "proposal:p1",
            executed: false,
            reversible: true,
            ttl_seconds: 900,
            entity_id: "host-1",
            action_type: "block",
            rationale: "brute force",
            signature: "sig",
          },
        ],
      },
    });
    mockConfirm.mockResolvedValue({
      data: {
        confirmed: true,
        proposal: {},
        forward_to: "policy-orchestrator/enforcement",
      },
    });
  });

  it("summarizes an incident and shows the grounded summary, citations, and a proposal", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText(/entity id/i), "host-1");
    await user.click(screen.getByRole("button", { name: /summarize/i }));

    expect(
      await screen.findByText(/elevated risk on host-1/i),
    ).toBeInTheDocument();
    expect(screen.getByText("score:s1")).toBeInTheDocument();
    expect(screen.getByTestId("proposal-card")).toBeInTheDocument();
    expect(mockSummarize).toHaveBeenCalledWith("host-1");
    // Advisory only: nothing is confirmed/executed automatically.
    expect(mockConfirm).not.toHaveBeenCalled();
  });

  it("confirms a proposal only after explicit human confirmation", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText(/entity id/i), "host-1");
    await user.click(screen.getByRole("button", { name: /summarize/i }));
    await screen.findByTestId("proposal-card");

    await user.click(screen.getByRole("button", { name: /review & confirm/i }));
    expect(mockConfirm).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole("button", { name: /confirm in enforcement/i }),
    );
    await waitFor(() => expect(mockConfirm).toHaveBeenCalledTimes(1));
  });
});
