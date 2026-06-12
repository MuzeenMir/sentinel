import { api } from "./api";

// Mirrors the verdict written by
// sentinel-core/scripts/verify_audit_chain.py --report-json. The verifier runs
// out-of-band (auditor / CI with the DB read role + cosign); the console only
// renders the signed artifact, so cryptographic verification stays independent
// of the system being audited.

export interface LedgerDay {
  date: string;
  count: number;
  root: string;
  trusted: boolean;
}

export interface LedgerTamper {
  id: number;
  stored: string;
  recomputed: string;
}

export interface LedgerSignatureFailure {
  date: string;
  reason: string;
}

export interface LedgerDivergence {
  date: string;
  reason: string;
  computed?: string;
  published?: string;
}

export interface LedgerReport {
  ok: boolean;
  /** False when no cosign-trusted published root anchored the run —
   * integrity-only, must not be presented as "verified". */
  anchored: boolean;
  row_count: number;
  daily_root_count: number;
  trusted_root_count: number;
  first_tamper: LedgerTamper | null;
  first_signature_failure: LedgerSignatureFailure | null;
  first_divergence: LedgerDivergence | null;
  daily: LedgerDay[];
  generated_at?: string;
}

// Default location of the published verdict artifact. Configurable per
// deployment; overridable via the page's loader so an auditor can point at a
// freshly generated report.
export const DEFAULT_REPORT_URL = "/audit/verify-report.json";

/** Normalize an untrusted report artifact into a safe-to-render shape. */
export function parseLedgerReport(raw: unknown): LedgerReport {
  const r = (raw ?? {}) as Record<string, unknown>;
  const daily = Array.isArray(r.daily) ? (r.daily as LedgerDay[]) : [];
  const trustedCount = Number(r.trusted_root_count ?? 0);
  return {
    ok: Boolean(r.ok),
    // Older reports lack the field; infer from the trusted-root count so an
    // unanchored run is never rendered as verified.
    anchored: r.anchored !== undefined ? Boolean(r.anchored) : trustedCount > 0,
    row_count: Number(r.row_count ?? 0),
    daily_root_count: Number(r.daily_root_count ?? 0),
    trusted_root_count: trustedCount,
    first_tamper: (r.first_tamper as LedgerTamper | null) ?? null,
    first_signature_failure:
      (r.first_signature_failure as LedgerSignatureFailure | null) ?? null,
    first_divergence: (r.first_divergence as LedgerDivergence | null) ?? null,
    daily: daily.map((d) => ({
      date: String(d.date),
      count: Number(d.count ?? 0),
      root: String(d.root ?? ""),
      trusted: Boolean(d.trusted),
    })),
    generated_at: r.generated_at ? String(r.generated_at) : undefined,
  };
}

export async function fetchLedgerReport(
  url: string = DEFAULT_REPORT_URL,
): Promise<LedgerReport> {
  const { data } = await api.get<unknown>(url);
  return parseLedgerReport(data);
}
