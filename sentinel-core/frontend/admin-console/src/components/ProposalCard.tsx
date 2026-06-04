import { useState } from "react";
import { ShieldAlert, Lock } from "lucide-react";
import type { CopilotProposal } from "../services/copilot";
import { ConfirmDialog } from "./ConfirmDialog";

interface ProposalCardProps {
  proposal: CopilotProposal;
  pending?: boolean;
  onConfirm: (proposal: CopilotProposal) => void;
}

/**
 * Renders a copilot proposal. The proposal is NOT executed by rendering or by
 * opening the dialog — `onConfirm` only fires after the human confirms inside
 * the dialog. This preserves the advisory-only / no-auto-exec invariant.
 */
export function ProposalCard({ proposal, pending, onConfirm }: ProposalCardProps) {
  const [dialogOpen, setDialogOpen] = useState(false);

  return (
    <div
      data-testid="proposal-card"
      className="card space-y-3 border-amber-500/20 p-4"
    >
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-amber-400" />
        <span className="text-sm font-semibold text-white">
          {proposal.action_type}
        </span>
        <span className="text-sm text-slate-400">on {proposal.entity_id}</span>
        <span className="ml-auto rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-300">
          Proposed — not executed
        </span>
      </div>

      {proposal.rationale && (
        <p className="text-xs text-slate-400">{proposal.rationale}</p>
      )}

      <div className="flex items-center gap-3 text-[11px] text-slate-500">
        <span>Reversible · TTL {proposal.ttl_seconds}s</span>
        {proposal.signature && (
          <span className="flex items-center gap-1 text-emerald-400">
            <Lock className="h-3 w-3" /> Signed
          </span>
        )}
      </div>

      <button
        type="button"
        onClick={() => setDialogOpen(true)}
        className="rounded-lg bg-amber-600/90 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-500"
      >
        Review &amp; confirm…
      </button>

      <ConfirmDialog
        open={dialogOpen}
        proposal={proposal}
        pending={pending}
        onCancel={() => setDialogOpen(false)}
        onConfirm={() => {
          onConfirm(proposal);
          setDialogOpen(false);
        }}
      />
    </div>
  );
}
