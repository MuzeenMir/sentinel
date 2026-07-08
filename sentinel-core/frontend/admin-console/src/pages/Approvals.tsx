import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { ShieldCheck, CheckCircle2, RefreshCw } from "lucide-react";
import {
  copilotApi,
  type CopilotProposal,
  type PendingProposal,
} from "../services/copilot";
import { ProposalCard } from "../components/ProposalCard";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  medium: "text-cyan-300 bg-cyan-500/10 border-cyan-500/20",
  low: "text-slate-300 bg-slate-500/10 border-slate-500/20",
  info: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

/**
 * Approval queue: the reversible actions the auto-triage worker proposed from
 * detector alerts. A human confirms each one — nothing is executed by loading
 * this page or by opening a proposal. Advisory-only invariant preserved.
 */
export function Approvals() {
  const [confirmedIds, setConfirmedIds] = useState<Record<string, string>>({});

  const query = useQuery({
    queryKey: ["copilot", "proposals"],
    queryFn: () => copilotApi.listProposals().then((r) => r.data),
  });

  const confirm = useMutation({
    mutationFn: (proposal: CopilotProposal) =>
      copilotApi.confirm(proposal).then((r) => r.data),
    onSuccess: (data, proposal) => {
      setConfirmedIds((m) => ({
        ...m,
        [proposal.proposal_id]:
          data.forward_to ?? "Confirmed for enforcement.",
      }));
    },
  });

  const items = query.data?.proposals ?? [];

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div className="flex items-center gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold text-white">
            <ShieldCheck className="h-5 w-5 text-cyan-400" />
            Pending Approvals
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Reversible actions the analyst proposed from detector alerts. Review
            the grounded triage, then confirm — nothing runs until you do.
          </p>
        </div>
        <button
          type="button"
          onClick={() => query.refetch()}
          disabled={query.isFetching}
          className="ml-auto flex items-center gap-2 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${query.isFetching ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {query.isError && (
        <p className="text-sm text-red-400">
          Could not load the approval queue.
        </p>
      )}

      {!query.isLoading && items.length === 0 && (
        <div className="card p-6 text-center text-sm text-slate-400">
          No pending proposals. New detector alerts are triaged automatically
          and will appear here for confirmation.
        </div>
      )}

      <div className="space-y-4">
        {items.map((item: PendingProposal) => (
          <div key={item.proposal.proposal_id} className="space-y-2">
            <div className="flex items-center gap-2">
              <span
                className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                  SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES.info
                }`}
              >
                {item.severity}
              </span>
              <span className="font-mono text-xs text-slate-400">
                {item.comm ?? "process"} on {item.hostname ?? "node"}
              </span>
              <span className="ml-auto font-mono text-[10px] text-slate-600">
                node_alert:{item.alert_id}
              </span>
            </div>

            {item.triage_text && (
              <div className="card p-4">
                <p className="whitespace-pre-wrap text-sm text-slate-200">
                  {item.triage_text}
                </p>
                {item.citations.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {item.citations.map((c) => (
                      <span
                        key={c}
                        className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-cyan-300"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            <ProposalCard
              proposal={item.proposal}
              pending={confirm.isPending}
              onConfirm={(proposal) => confirm.mutate(proposal)}
            />

            {confirmedIds[item.proposal.proposal_id] && (
              <p className="flex items-center gap-2 text-sm text-emerald-400">
                <CheckCircle2 className="h-4 w-4" />
                {confirmedIds[item.proposal.proposal_id]}
              </p>
            )}
          </div>
        ))}
      </div>

      <p className="text-[11px] text-slate-600">
        The copilot is advisory only. Confirming validates the proposal&apos;s
        signature and TTL and records the decision; enforcement is applied by
        the policy service, not the copilot.
      </p>
    </div>
  );
}
