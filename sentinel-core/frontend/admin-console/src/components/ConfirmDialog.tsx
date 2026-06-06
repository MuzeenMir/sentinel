import { AlertTriangle } from "lucide-react";
import type { CopilotProposal } from "../services/copilot";

interface ConfirmDialogProps {
  open: boolean;
  proposal: CopilotProposal;
  pending?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

/**
 * Human-in-the-loop gate. The copilot never executes enforcement; this dialog
 * is the explicit, deliberate human confirmation step before a reversible
 * action is forwarded to the policy-orchestrator.
 */
export function ConfirmDialog({
  open,
  proposal,
  pending,
  onCancel,
  onConfirm,
}: ConfirmDialogProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Confirm enforcement action"
        className="card w-full max-w-md space-y-4 p-6"
      >
        <div className="flex items-center gap-3">
          <AlertTriangle className="h-6 w-6 text-amber-400" />
          <h2 className="text-lg font-semibold text-white">
            Confirm reversible enforcement
          </h2>
        </div>
        <p className="text-sm text-slate-300">
          You are about to confirm a{" "}
          <strong className="text-white">{proposal.action_type}</strong> on{" "}
          <strong className="text-white">{proposal.entity_id}</strong>. It is
          reversible and auto-rolls back after {proposal.ttl_seconds}s. The
          copilot proposed this — <strong>you</strong> are executing it.
        </p>
        {proposal.rationale && (
          <p className="rounded-lg bg-slate-800/60 p-3 text-xs text-slate-400">
            {proposal.rationale}
          </p>
        )}
        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white hover:bg-amber-500 disabled:opacity-50"
          >
            {pending ? "Confirming…" : "Confirm in enforcement"}
          </button>
        </div>
      </div>
    </div>
  );
}
