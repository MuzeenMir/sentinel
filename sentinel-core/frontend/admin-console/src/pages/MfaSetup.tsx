import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  QrCode,
  Key,
  AlertTriangle,
  Check,
  X,
} from "lucide-react";
import { mfaApi } from "../services/api";
import type { MfaStatus } from "../types";

type Step = "status" | "enroll" | "verify" | "backup" | "disable";

export function MfaSetup() {
  const qc = useQueryClient();
  const [step, setStep] = useState<Step>("status");
  const [provisioningUri, setProvisioningUri] = useState("");
  const [code, setCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState("");

  const { data: statusData, isLoading } = useQuery<MfaStatus>({
    queryKey: ["mfa-status"],
    queryFn: () => mfaApi.status().then((r) => r.data),
  });

  const enrollMutation = useMutation({
    mutationFn: () => mfaApi.enroll(),
    onSuccess: (res) => {
      setProvisioningUri(res.data.provisioning_uri);
      setError("");
      setStep("verify");
    },
    onError: () => setError("Failed to start MFA enrollment"),
  });

  const verifyMutation = useMutation({
    mutationFn: (c: string) => mfaApi.verify(c),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mfa-status"] });
      setError("");
      setStep("backup");
    },
    onError: () => setError("Invalid TOTP code. Try again."),
  });

  const backupMutation = useMutation({
    mutationFn: () => mfaApi.generateBackupCodes(),
    onSuccess: (res) => {
      setBackupCodes(res.data.backup_codes);
      setError("");
    },
    onError: () => setError("Failed to generate backup codes"),
  });

  const disableMutation = useMutation({
    mutationFn: (c: string) => mfaApi.disable(c),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mfa-status"] });
      setStep("status");
      setDisableCode("");
      setError("");
    },
    onError: () => setError("Invalid TOTP code. MFA not disabled."),
  });

  // Build QR code URL using Google Charts (data URL approach via provisioning URI)
  const qrUrl = provisioningUri
    ? `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(provisioningUri)}`
    : "";

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">MFA Setup</h1>
        </div>
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading MFA status…</p>
        </div>
      </div>
    );
  }

  const mfaEnabled = statusData?.enabled ?? false;
  const enrolled = statusData?.enrolled ?? false;

  return (
    <div className="space-y-6 max-w-2xl">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-6 w-6 text-cyan-400" />
        <h1 className="text-2xl font-bold text-white">MFA Setup</h1>
      </div>

      {/* Status card */}
      <div className="card p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-400">
              Multi-Factor Authentication
            </p>
            <p className="text-lg font-semibold text-white mt-1">
              {mfaEnabled
                ? "Enabled (TOTP)"
                : enrolled
                  ? "Enrolled (not verified)"
                  : "Not configured"}
            </p>
            {statusData?.has_backup_codes && (
              <p className="text-xs text-green-400 mt-1">
                Backup codes generated
              </p>
            )}
          </div>
          <div
            className={`flex h-12 w-12 items-center justify-center rounded-full ${
              mfaEnabled ? "bg-green-500/20" : "bg-slate-700"
            }`}
          >
            {mfaEnabled ? (
              <Check className="h-6 w-6 text-green-400" />
            ) : (
              <AlertTriangle className="h-6 w-6 text-slate-400" />
            )}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Wizard steps */}
      {(step === "status" || step === "enroll") && !mfaEnabled && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-3">
            <QrCode className="h-5 w-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">
              Step 1 — Enroll
            </h2>
          </div>
          <p className="text-sm text-slate-400">
            Click below to generate a TOTP secret. You'll then scan the QR code
            with your authenticator app (Google Authenticator, Authy, etc.).
          </p>
          <button
            onClick={() => enrollMutation.mutate()}
            disabled={enrollMutation.isPending}
            className="btn-primary gap-2"
          >
            <QrCode className="h-4 w-4" />
            {enrollMutation.isPending ? "Generating…" : "Generate QR Code"}
          </button>
        </div>
      )}

      {step === "verify" && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-3">
            <QrCode className="h-5 w-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">
              Step 2 — Scan &amp; Verify
            </h2>
          </div>
          <p className="text-sm text-slate-400">
            Scan this QR code with your authenticator app, then enter the
            6-digit code to verify.
          </p>
          {qrUrl && (
            <div className="flex justify-center">
              <img
                src={qrUrl}
                alt="TOTP QR Code"
                className="rounded-lg border border-slate-700 bg-white p-2"
                width={200}
                height={200}
              />
            </div>
          )}
          <p className="text-xs text-slate-500 break-all font-mono">
            {provisioningUri}
          </p>
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-1">
                6-digit code
              </label>
              <input
                type="text"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                placeholder="123456"
                className="input-field font-mono text-lg tracking-widest"
              />
            </div>
            <button
              onClick={() => verifyMutation.mutate(code)}
              disabled={code.length !== 6 || verifyMutation.isPending}
              className="btn-primary gap-2"
            >
              <Check className="h-4 w-4" />
              {verifyMutation.isPending ? "Verifying…" : "Verify & Enable"}
            </button>
          </div>
        </div>
      )}

      {step === "backup" && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-3">
            <Key className="h-5 w-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">
              Step 3 — Backup Codes
            </h2>
          </div>
          <p className="text-sm text-slate-400">
            MFA is now enabled. Generate backup codes in case you lose access to
            your authenticator. Store them somewhere safe — they're shown only
            once.
          </p>
          {backupCodes.length > 0 ? (
            <>
              <div className="grid grid-cols-2 gap-2">
                {backupCodes.map((c) => (
                  <code
                    key={c}
                    className="rounded bg-slate-800 px-3 py-1.5 text-sm font-mono text-cyan-300"
                  >
                    {c}
                  </code>
                ))}
              </div>
              <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-xs text-yellow-400">
                Each code can only be used once. Store them somewhere safe now.
              </div>
              <button onClick={() => setStep("status")} className="btn-primary">
                Done
              </button>
            </>
          ) : (
            <button
              onClick={() => backupMutation.mutate()}
              disabled={backupMutation.isPending}
              className="btn-secondary gap-2"
            >
              <Key className="h-4 w-4" />
              {backupMutation.isPending
                ? "Generating…"
                : "Generate Backup Codes"}
            </button>
          )}
        </div>
      )}

      {/* Actions when MFA is enabled */}
      {mfaEnabled && step !== "disable" && (
        <div className="card p-6 space-y-4">
          <h2 className="text-lg font-semibold text-white">Manage MFA</h2>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => {
                backupMutation.mutate();
                setStep("backup");
              }}
              className="btn-secondary gap-2"
            >
              <Key className="h-4 w-4" /> Regenerate Backup Codes
            </button>
            <button
              onClick={() => {
                setStep("disable");
                setError("");
              }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20"
            >
              <X className="h-4 w-4" /> Disable MFA
            </button>
          </div>
        </div>
      )}

      {step === "disable" && (
        <div className="card p-6 space-y-4 border border-red-500/20">
          <h2 className="text-lg font-semibold text-red-400">Disable MFA</h2>
          <p className="text-sm text-slate-400">
            Enter your current TOTP code to confirm disabling MFA.
          </p>
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-1">
                Current TOTP code
              </label>
              <input
                type="text"
                maxLength={6}
                value={disableCode}
                onChange={(e) =>
                  setDisableCode(e.target.value.replace(/\D/g, ""))
                }
                placeholder="123456"
                className="input-field font-mono text-lg tracking-widest"
              />
            </div>
            <button
              onClick={() => disableMutation.mutate(disableCode)}
              disabled={disableCode.length !== 6 || disableMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-red-600 hover:bg-red-500 text-white"
            >
              {disableMutation.isPending ? "Disabling…" : "Confirm Disable"}
            </button>
            <button
              onClick={() => {
                setStep("status");
                setError("");
              }}
              className="btn-secondary"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
