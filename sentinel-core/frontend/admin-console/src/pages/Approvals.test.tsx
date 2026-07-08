import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Approvals } from "./Approvals";

const mockList = vi.fn();
const mockConfirm = vi.fn();

vi.mock("../services/copilot", () => ({
  copilotApi: {
    listProposals: (...args: unknown[]) => mockList(...args),
    confirm: (...args: unknown[]) => mockConfirm(...args),
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
        <Approvals />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const PROPOSAL = {
  proposal_id: "proposal:xyz",
  executed: false,
  reversible: true,
  ttl_seconds: 900,
  entity_id: "host-9",
  action_type: "quarantine",
  rationale: "auto-triage: reverse shell tooling",
  signature: "sig",
  nonce: "n1",
  issued_at: 1,
};

describe("Approvals", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockList.mockResolvedValue({
      data: {
        proposals: [
          {
            alert_id: 7,
            severity: "critical",
            comm: "nc",
            exe: "/usr/bin/nc",
            hostname: "host-9",
            summary: "offensive tool 'nc'",
            triage_text: "Reverse shell tooling executed [node_alert:7].",
            citations: ["node_alert:7"],
            proposal: PROPOSAL,
            created_at: "2026-07-08T04:00:00+00:00",
          },
        ],
      },
    });
    mockConfirm.mockResolvedValue({
      data: { confirmed: true, proposal: PROPOSAL, forward_to: "…/enforcement" },
    });
  });

  it("renders the pending queue with grounded triage and citations", async () => {
    renderPage();
    expect(
      await screen.findByText(/Reverse shell tooling executed/),
    ).toBeInTheDocument();
    // Cited alert id appears in the header AND as a citation chip.
    expect(screen.getAllByText("node_alert:7").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByTestId("proposal-card")).toBeInTheDocument();
  });

  it("confirms a proposal only after the human confirms in the dialog", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByTestId("proposal-card");
    // Rendering must NOT have executed anything.
    expect(mockConfirm).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /Review & confirm/i }));
    // Opening the dialog still must not confirm.
    expect(mockConfirm).not.toHaveBeenCalled();

    const confirmBtn = await screen.findByRole("button", {
      name: /Confirm in enforcement/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => expect(mockConfirm).toHaveBeenCalledTimes(1));
    expect(mockConfirm).toHaveBeenCalledWith(PROPOSAL);
    // The forward_to target from the confirm response is surfaced to the user.
    expect(await screen.findByText("…/enforcement")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is pending", async () => {
    mockList.mockResolvedValue({ data: { proposals: [] } });
    renderPage();
    expect(
      await screen.findByText(/No pending proposals/),
    ).toBeInTheDocument();
  });
});
