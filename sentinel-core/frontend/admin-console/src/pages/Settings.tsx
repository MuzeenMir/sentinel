import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Settings as SettingsIcon, Save } from "lucide-react";
import { configApi } from "../services/api";
import { useSettingsStore } from "../store/settingsStore";

export function Settings() {
  const queryClient = useQueryClient();
  const settings = useSettingsStore();
  const [saved, setSaved] = useState(false);

  const configQuery = useQuery({
    queryKey: ["config"],
    queryFn: () => configApi.getConfig().then((r) => r.data),
  });

  const updateMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      configApi.updateConfig(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["config"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    },
  });

  const handleSave = () => {
    updateMutation.mutate({
      organization: {
        name: settings.organizationName,
      },
      timezone: settings.timezone,
      detection: {
        autoBlockHighThreats: settings.autoBlockHighThreats,
        drlAutoDecisions: settings.drlAutoDecisions,
        confidenceThreshold: settings.confidenceThreshold,
      },
      notifications: {
        emailAlerts: settings.emailAlerts,
        slackIntegration: settings.slackIntegration,
      },
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <SettingsIcon className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Settings</h1>
        </div>
        <button
          onClick={handleSave}
          disabled={updateMutation.isPending}
          className="btn-primary gap-2"
        >
          <Save className="h-4 w-4" /> Save Settings
        </button>
      </div>

      {saved && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-3 text-sm text-green-400">
          Settings saved to backend successfully.
        </div>
      )}

      <div className="card p-6">
        <h2 className="text-lg font-semibold text-white mb-2">Platform</h2>
        <p className="text-sm text-slate-400">
          Configure platform-wide defaults for organization, detection, and
          notifications.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            General Settings
          </h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Organization Name
              </label>
              <input
                type="text"
                value={settings.organizationName}
                onChange={(e) => settings.setOrganizationName(e.target.value)}
                className="input-field"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Default Timezone
              </label>
              <select
                value={settings.timezone}
                onChange={(e) => settings.setTimezone(e.target.value)}
                className="select-field w-full"
              >
                <option value="UTC">UTC</option>
                <option value="America/New_York">Eastern (ET)</option>
                <option value="America/Chicago">Central (CT)</option>
                <option value="America/Denver">Mountain (MT)</option>
                <option value="America/Los_Angeles">Pacific (PT)</option>
                <option value="Europe/London">London (GMT)</option>
                <option value="Europe/Berlin">Berlin (CET)</option>
                <option value="Asia/Tokyo">Tokyo (JST)</option>
              </select>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Detection Settings
          </h2>
          <div className="space-y-4">
            <ToggleRow
              label="Auto-block High Threats"
              description="Automatically block threats with high confidence scores"
              value={settings.autoBlockHighThreats}
              onChange={settings.setAutoBlockHighThreats}
            />
            <ToggleRow
              label="DRL Auto Decisions"
              description="Allow DRL engine to make autonomous policy decisions"
              value={settings.drlAutoDecisions}
              onChange={settings.setDrlAutoDecisions}
            />
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-sm text-slate-400">
                  Confidence Threshold
                </label>
                <span className="text-sm font-medium text-white">
                  {settings.confidenceThreshold}%
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={settings.confidenceThreshold}
                onChange={(e) =>
                  settings.setConfidenceThreshold(Number(e.target.value))
                }
                className="w-full accent-cyan-500"
              />
            </div>
          </div>
        </div>

        <div className="card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Notifications
          </h2>
          <div className="space-y-4">
            <ToggleRow
              label="Email Alerts"
              description="Send critical alerts via email"
              value={settings.emailAlerts}
              onChange={settings.setEmailAlerts}
            />
            <ToggleRow
              label="Slack Integration"
              description="Send alerts to Slack channels"
              value={settings.slackIntegration}
              onChange={settings.setSlackIntegration}
            />
          </div>
        </div>

        <div className="card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">System</h2>
          <div className="space-y-4">
            {configQuery.isLoading ? (
              <p className="text-sm text-slate-400">Loading configuration…</p>
            ) : configQuery.isError ? (
              <p className="text-sm text-red-400">
                Failed to load system configuration.
              </p>
            ) : configQuery.data ? (
              <pre className="text-xs text-slate-400 overflow-auto max-h-48 rounded-lg bg-slate-900 p-3">
                {JSON.stringify(configQuery.data, null, 2)}
              </pre>
            ) : (
              <p className="text-sm text-slate-400">
                No system configuration loaded.
              </p>
            )}
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button onClick={() => settings.reset()} className="btn-secondary">
          Reset to Defaults
        </button>
      </div>
    </div>
  );
}

function ToggleRow({
  label,
  description,
  value,
  onChange,
}: {
  label: string;
  description: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-white">{label}</p>
        <p className="text-xs text-slate-400">{description}</p>
      </div>
      <label className="relative inline-block h-6 w-11 cursor-pointer">
        <input
          type="checkbox"
          checked={value}
          onChange={(e) => onChange(e.target.checked)}
          className="absolute inset-0 z-10 h-full w-full cursor-pointer opacity-0"
        />
        <span
          aria-hidden="true"
          className={`absolute inset-0 rounded-full transition-colors ${
            value ? "bg-cyan-600" : "bg-slate-600"
          }`}
        />
        <span
          aria-hidden="true"
          className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
            value ? "translate-x-5" : ""
          }`}
        />
      </label>
    </div>
  );
}
