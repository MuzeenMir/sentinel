import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AuditorVerifyPage } from "./AuditorVerifyPage";
import type { LedgerReport } from "../services/ledger";

const mockFetch = vi.fn();

vi.mock("../services/ledger", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../services/ledger")>();
  return {
    ...actual,
    fetchLedgerReport: (...args: unknown[]) => mockFetch(...args),
  };
});

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuditorVerifyPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const cleanReport: LedgerReport = {
  ok: true,
  row_count: 2,
  daily_root_count: 2,
  trusted_root_count: 2,
  first_tamper: null,
  first_signature_failure: null,
  first_divergence: null,
  daily: [
    { date: "2026-05-30", count: 1, root: "a".repeat(64), trusted: true },
    { date: "2026-05-31", count: 1, root: "b".repeat(64), trusted: true },
  ],
  generated_at: "2026-06-07T00:00:00+00:00",
};

const tamperedReport: LedgerReport = {
  ok: false,
  row_count: 2,
  daily_root_count: 2,
  trusted_root_count: 1,
  first_tamper: { id: 2, stored: "abc", recomputed: "def" },
  first_signature_failure: { date: "2026-05-31", reason: "signature_invalid" },
  first_divergence: { date: "2026-05-31", reason: "missing_published_root" },
  daily: [
    { date: "2026-05-30", count: 1, root: "a".repeat(64), trusted: true },
    { date: "2026-05-31", count: 1, root: "b".repeat(64), trusted: false },
  ],
  generated_at: "2026-06-07T00:00:00+00:00",
};

describe("AuditorVerifyPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows a verified verdict for a clean ledger", async () => {
    mockFetch.mockResolvedValue(cleanReport);
    renderPage();
    expect(await screen.findByText(/ledger verified/i)).toBeInTheDocument();
    expect(screen.getByText("2026-05-30")).toBeInTheDocument();
    // both days anchored by a cosign-trusted root
    expect(screen.getAllByText(/^trusted$/i)).toHaveLength(2);
  });

  it("surfaces the first divergent day and tamper on a broken ledger", async () => {
    mockFetch.mockResolvedValue(tamperedReport);
    renderPage();
    expect(await screen.findByText(/verification failed/i)).toBeInTheDocument();
    // first divergent day is called out explicitly
    const divergence = screen.getByTestId("first-divergence");
    expect(divergence).toHaveTextContent("2026-05-31");
    expect(divergence).toHaveTextContent(/missing_published_root/i);
    // the untrusted (unsigned) day is flagged
    expect(screen.getByText(/^untrusted$/i)).toBeInTheDocument();
    // the first tampered row is surfaced
    expect(screen.getByTestId("first-tamper")).toHaveTextContent("2");
  });

  it("renders an error state when the report cannot be loaded", async () => {
    mockFetch.mockRejectedValue(new Error("not found"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/could not load/i)).toBeInTheDocument(),
    );
  });
});
