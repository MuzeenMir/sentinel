import { api } from "./api";

export interface CopilotProposal {
  proposal_id: string;
  executed: boolean;
  reversible: boolean;
  ttl_seconds: number;
  entity_id?: string;
  action_type?: string;
  rationale?: string;
  confirm_via?: string;
  // Tamper-evidence (backend C4): proposals are signed + single-use + TTL.
  nonce?: string;
  issued_at?: number;
  signature?: string;
}

export interface SummarizeResponse {
  session_id: string;
  entity_id: string;
  summary: string;
  grounded: boolean;
  citations: string[];
  // Verifiable citation provenance (backend C2): record id -> source hash.
  citation_provenance: Record<string, string>;
  proposals: CopilotProposal[];
}

export interface AskResponse {
  session_id: string;
  answer: string;
  grounded: boolean;
  citations: string[];
  citation_provenance: Record<string, string>;
  proposals: CopilotProposal[];
}

export interface ConfirmResponse {
  confirmed: boolean;
  proposal: CopilotProposal;
  forward_to?: string;
}

/**
 * Analyst-copilot client. The copilot is advisory only: it summarizes, answers
 * with citations, and *proposes* reversible enforcement. A proposal is only
 * ever executed when a human explicitly confirms it via `confirm` (which the
 * backend verifies + audits but does not execute — the human-initiated call to
 * the policy-orchestrator does).
 */
// Routed through the api-gateway under the standard /api/v1 prefix; the gateway
// proxies /api/v1/copilot/* to the llm-gateway's /copilot/* endpoints.
export const copilotApi = {
  summarize: (entityId: string) =>
    api.post<SummarizeResponse>("/api/v1/copilot/summarize", {
      entity_id: entityId,
    }),
  ask: (sessionId: string, question: string) =>
    api.post<AskResponse>("/api/v1/copilot/ask", {
      session_id: sessionId,
      question,
    }),
  propose: (
    entityId: string,
    actionType: string,
    rationale: string,
    ttlSeconds = 900,
  ) =>
    api.post<{ proposal: CopilotProposal }>("/api/v1/copilot/propose", {
      entity_id: entityId,
      action_type: actionType,
      rationale,
      ttl_seconds: ttlSeconds,
    }),
  confirm: (proposal: CopilotProposal) =>
    api.post<ConfirmResponse>("/api/v1/copilot/confirm", { proposal }),
};
