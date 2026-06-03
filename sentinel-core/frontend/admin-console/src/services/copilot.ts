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
}

export interface SummarizeResponse {
    session_id: string;
    entity_id: string;
    summary: string;
    grounded: boolean;
    citations: string[];
    proposals: CopilotProposal[];
}

export interface AskResponse {
    session_id: string;
    answer: string;
    grounded: boolean;
    citations: string[];
    proposals: CopilotProposal[];
}

const unwrap = <T,>(promise: Promise<{ data: T }>): Promise<T> =>
    promise.then((response) => response.data);

export const summarizeIncident = (entityId: string): Promise<SummarizeResponse> =>
    unwrap(api.post("/copilot/summarize", { entity_id: entityId }));

export const askCopilot = (
    sessionId: string,
    question: string,
): Promise<AskResponse> =>
    unwrap(api.post("/copilot/ask", { session_id: sessionId, question }));

export const proposeAction = (
    entityId: string,
    actionType: string,
    rationale: string,
    ttlSeconds = 900,
): Promise<{ proposal: CopilotProposal }> =>
    unwrap(
        api.post("/copilot/propose", {
            entity_id: entityId,
            action_type: actionType,
            rationale,
            ttl_seconds: ttlSeconds,
        }),
    );
