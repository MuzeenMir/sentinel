import { describe, it, expect } from "vitest";
import { parseLedgerReport } from "./ledger";

describe("parseLedgerReport", () => {
  it("normalizes a well-formed report", () => {
    const report = parseLedgerReport({
      ok: false,
      row_count: 3,
      daily_root_count: 2,
      trusted_root_count: 1,
      first_tamper: { id: 7, stored: "ab", recomputed: "cd" },
      first_signature_failure: { date: "2026-05-31", reason: "signature_invalid" },
      first_divergence: { date: "2026-05-31", reason: "root_mismatch" },
      daily: [{ date: "2026-05-31", count: 2, root: "ff", trusted: false }],
      generated_at: "2026-06-07T00:00:00+00:00",
    });
    expect(report.ok).toBe(false);
    expect(report.first_tamper?.id).toBe(7);
    expect(report.daily[0].trusted).toBe(false);
  });

  it("defends against a missing/empty artifact", () => {
    const report = parseLedgerReport(null);
    expect(report.ok).toBe(false);
    expect(report.daily).toEqual([]);
    expect(report.first_divergence).toBeNull();
  });
});
