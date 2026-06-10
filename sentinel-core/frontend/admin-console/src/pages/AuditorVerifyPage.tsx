import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, ShieldAlert, AlertTriangle } from "lucide-react";
import { fetchLedgerReport, type LedgerReport } from "../services/ledger";

function short(hex: string): string {
  return hex.length > 16 ? `${hex.slice(0, 16)}…` : hex;
}

export function AuditorVerifyPage() {
  const { data, isLoading, isError } = useQuery<LedgerReport>({
    queryKey: ["ledger-verify-report"],
    queryFn: () => fetchLedgerReport(),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-6 w-6 text-cyan-400" />
        <h1 className="text-2xl font-bold text-white">
          Audit Ledger Verification
        </h1>
      </div>
      <p className="max-w-3xl text-sm text-slate-400">
        Read-only view of the independent tamper-evidence check. The verifier
        recomputes the daily Merkle chain from the append-only audit log, checks
        each nightly root&rsquo;s cosign signature, and reports the first
        divergent day. This page renders that signed verdict — it does not
        perform the verification itself.
      </p>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading verification report…</p>
        </div>
      ) : isError || !data ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">
            Could not load the verification report. Run{" "}
            <code className="text-slate-300">
              verify_audit_chain.py --report-json
            </code>{" "}
            and publish the artifact.
          </p>
        </div>
      ) : (
        <Verdict report={data} />
      )}
    </div>
  );
}

function Verdict({ report }: { report: LedgerReport }) {
  return (
    <div className="space-y-6">
      <div
        className={`card flex items-center gap-4 p-6 ${
          report.ok ? "border-emerald-600/40" : "border-red-600/40"
        }`}
      >
        {report.ok ? (
          <ShieldCheck className="h-10 w-10 shrink-0 text-emerald-400" />
        ) : (
          <ShieldAlert className="h-10 w-10 shrink-0 text-red-400" />
        )}
        <div>
          <h2
            className={`text-xl font-bold ${
              report.ok ? "text-emerald-300" : "text-red-300"
            }`}
          >
            {report.ok ? "Ledger verified" : "Verification failed"}
          </h2>
          <p className="text-sm text-slate-400">
            {report.row_count} rows · {report.daily_root_count} daily roots ·{" "}
            {report.trusted_root_count} cosign-trusted anchors
            {report.generated_at ? ` · as of ${report.generated_at}` : ""}
          </p>
        </div>
      </div>

      {!report.ok && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {report.first_divergence && (
            <Finding
              testId="first-divergence"
              title="First divergent day"
              body={`${report.first_divergence.date} (${report.first_divergence.reason})`}
            />
          )}
          {report.first_signature_failure && (
            <Finding
              testId="first-signature-failure"
              title="First signature failure"
              body={`${report.first_signature_failure.date} (${report.first_signature_failure.reason})`}
            />
          )}
          {report.first_tamper && (
            <Finding
              testId="first-tamper"
              title="First tampered row"
              body={`row id ${report.first_tamper.id}`}
            />
          )}
        </div>
      )}

      <div className="card overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-800/50 text-slate-400">
            <tr>
              <th className="px-4 py-2 font-medium">Date</th>
              <th className="px-4 py-2 font-medium">Events</th>
              <th className="px-4 py-2 font-medium">Chained root</th>
              <th className="px-4 py-2 font-medium">Cosign anchor</th>
            </tr>
          </thead>
          <tbody>
            {report.daily.map((day) => (
              <tr key={day.date} className="border-t border-slate-800">
                <td className="px-4 py-2 text-white">{day.date}</td>
                <td className="px-4 py-2 text-slate-300">{day.count}</td>
                <td className="px-4 py-2 font-mono text-slate-400">
                  {short(day.root)}
                </td>
                <td className="px-4 py-2">
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${
                      day.trusted
                        ? "bg-emerald-900/40 text-emerald-300"
                        : "bg-red-900/40 text-red-300"
                    }`}
                  >
                    {day.trusted ? "Trusted" : "Untrusted"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Finding({
  testId,
  title,
  body,
}: {
  testId: string;
  title: string;
  body: string;
}) {
  return (
    <div className="card p-4" data-testid={testId}>
      <div className="flex items-center gap-2 text-red-300">
        <AlertTriangle className="h-4 w-4" />
        <span className="text-sm font-semibold">{title}</span>
      </div>
      <p className="mt-1 text-sm text-slate-300">{body}</p>
    </div>
  );
}
