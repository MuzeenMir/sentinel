import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Sparkles, Send, CheckCircle2 } from "lucide-react";
import {
  copilotApi,
  type CopilotProposal,
  type SummarizeResponse,
  type AskResponse,
} from "../services/copilot";
import { ProposalCard } from "./ProposalCard";

interface ChatTurn {
  role: "user" | "assistant";
  text: string;
  citations?: string[];
}

/**
 * Grounded analyst copilot panel: summarize an incident, ask follow-ups with
 * citations, and review/confirm reversible enforcement proposals. Advisory only.
 */
export function CopilotPanel({
  initialEntityId = "",
}: {
  initialEntityId?: string;
}) {
  const [entityId, setEntityId] = useState(initialEntityId);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [proposals, setProposals] = useState<CopilotProposal[]>([]);
  const [question, setQuestion] = useState("");
  const [confirmation, setConfirmation] = useState<string | null>(null);

  const summarize = useMutation({
    mutationFn: (id: string) => copilotApi.summarize(id).then((r) => r.data),
    onSuccess: (data: SummarizeResponse) => {
      setSessionId(data.session_id);
      setTurns([
        { role: "assistant", text: data.summary, citations: data.citations },
      ]);
      setProposals(data.proposals);
      setConfirmation(null);
    },
  });

  const ask = useMutation({
    mutationFn: (q: string) =>
      copilotApi.ask(sessionId as string, q).then((r) => r.data),
    onSuccess: (data: AskResponse, q) => {
      setTurns((t) => [
        ...t,
        { role: "user", text: q },
        { role: "assistant", text: data.answer, citations: data.citations },
      ]);
      setProposals((p) => [...p, ...data.proposals]);
      setQuestion("");
    },
  });

  const confirm = useMutation({
    mutationFn: (proposal: CopilotProposal) =>
      copilotApi.confirm(proposal).then((r) => r.data),
    onSuccess: (data) =>
      setConfirmation(data.forward_to ?? "Confirmed for enforcement."),
  });

  return (
    <div className="space-y-4">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (entityId.trim()) summarize.mutate(entityId.trim());
        }}
        className="flex gap-2"
      >
        <input
          aria-label="Entity ID"
          value={entityId}
          onChange={(e) => setEntityId(e.target.value)}
          placeholder="Entity ID (host or user)…"
          className="flex-1 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={summarize.isPending || !entityId.trim()}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
        >
          <Sparkles className="h-4 w-4" />
          {summarize.isPending ? "Summarizing…" : "Summarize"}
        </button>
      </form>

      {summarize.isError && (
        <p className="text-sm text-red-400">
          Failed to summarize the incident.
        </p>
      )}

      {turns.length > 0 && (
        <div className="space-y-3">
          {turns.map((turn, i) => (
            <div
              key={i}
              className={`card p-4 ${
                turn.role === "assistant" ? "" : "bg-slate-800/40"
              }`}
            >
              <p className="text-xs uppercase tracking-wide text-slate-500">
                {turn.role}
              </p>
              <p className="mt-1 whitespace-pre-wrap text-sm text-slate-200">
                {turn.text}
              </p>
              {turn.citations && turn.citations.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {turn.citations.map((c) => (
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
          ))}
        </div>
      )}

      {proposals.length > 0 && (
        <div className="space-y-2">
          {proposals.map((p) => (
            <ProposalCard
              key={p.proposal_id}
              proposal={p}
              pending={confirm.isPending}
              onConfirm={(proposal) => confirm.mutate(proposal)}
            />
          ))}
        </div>
      )}

      {confirmation && (
        <p className="flex items-center gap-2 text-sm text-emerald-400">
          <CheckCircle2 className="h-4 w-4" />
          {confirmation}
        </p>
      )}

      {sessionId && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (question.trim()) ask.mutate(question.trim());
          }}
          className="flex gap-2"
        >
          <input
            aria-label="Ask a follow-up"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask a follow-up…"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={ask.isPending || !question.trim()}
            className="flex items-center gap-2 rounded-lg bg-slate-700 px-4 py-2 text-sm font-medium text-white hover:bg-slate-600 disabled:opacity-50"
          >
            <Send className="h-4 w-4" />
            Ask
          </button>
        </form>
      )}
    </div>
  );
}
