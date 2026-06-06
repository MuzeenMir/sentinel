import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ProposalCard } from "./ProposalCard";
import type { CopilotProposal } from "../services/copilot";

const proposal: CopilotProposal = {
  proposal_id: "proposal:p1",
  executed: false,
  reversible: true,
  ttl_seconds: 900,
  entity_id: "host-1",
  action_type: "block",
  rationale: "repeated failed logins",
  signature: "sig-abc",
};

describe("ProposalCard", () => {
  it("renders as proposed and does not execute on render or on opening the dialog", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(<ProposalCard proposal={proposal} onConfirm={onConfirm} />);

    expect(screen.getByText(/proposed — not executed/i)).toBeInTheDocument();
    expect(onConfirm).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /review & confirm/i }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    // Opening the dialog must NOT execute the action.
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("executes only after explicit human confirmation", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(<ProposalCard proposal={proposal} onConfirm={onConfirm} />);

    await user.click(screen.getByRole("button", { name: /review & confirm/i }));
    await user.click(
      screen.getByRole("button", { name: /confirm in enforcement/i }),
    );

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledWith(proposal);
  });
});
