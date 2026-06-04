import { CopilotPanel } from "../components/CopilotPanel";

export function CopilotPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-white">Analyst Copilot</h1>
        <p className="mt-1 text-sm text-slate-400">
          Grounded incident summaries with citations to source records. The
          copilot is advisory only — it proposes reversible actions; a human
          confirms them.
        </p>
      </div>
      <CopilotPanel />
    </div>
  );
}
