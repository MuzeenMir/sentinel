import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plug, Plus, CheckCircle, XCircle, X, ChevronDown, ChevronUp } from 'lucide-react'
import { siemApi } from '../services/api'
import type { Integration } from '../types'

type IntegrationType =
  | 'webhook'
  | 'siem_splunk'
  | 'siem_elastic'
  | 'soar_xsoar'
  | 'ticketing_servicenow'
  | 'ticketing_jira'

interface IntegrationTypeConfig {
  label: string
  fields: { key: string; label: string; placeholder?: string; type?: string }[]
}

const INTEGRATION_TYPES: Record<IntegrationType, IntegrationTypeConfig> = {
  webhook: {
    label: 'Generic Webhook',
    fields: [
      { key: 'url', label: 'Webhook URL', placeholder: 'https://your-endpoint.example.com/hook' },
      { key: 'secret', label: 'HMAC Secret (optional)', placeholder: 'signing secret' },
    ],
  },
  siem_splunk: {
    label: 'Splunk HEC',
    fields: [
      { key: 'hec_url', label: 'HEC URL', placeholder: 'https://splunk:8088/services/collector/event' },
      { key: 'hec_token', label: 'HEC Token', placeholder: 'Splunk token', type: 'password' },
      { key: 'index', label: 'Index', placeholder: 'sentinel' },
    ],
  },
  siem_elastic: {
    label: 'Elastic SIEM',
    fields: [
      { key: 'elastic_url', label: 'Elasticsearch URL', placeholder: 'https://elastic:9200' },
      { key: 'api_key', label: 'API Key', placeholder: 'base64 api key', type: 'password' },
      { key: 'index', label: 'Index', placeholder: 'sentinel-events' },
    ],
  },
  soar_xsoar: {
    label: 'Palo Alto XSOAR',
    fields: [
      { key: 'xsoar_url', label: 'XSOAR URL', placeholder: 'https://xsoar.example.com' },
      { key: 'api_key', label: 'API Key', placeholder: 'XSOAR API key', type: 'password' },
    ],
  },
  ticketing_servicenow: {
    label: 'ServiceNow',
    fields: [
      { key: 'instance', label: 'Instance (subdomain)', placeholder: 'mycompany' },
      { key: 'username', label: 'Username', placeholder: 'admin' },
      { key: 'password', label: 'Password', placeholder: '••••••', type: 'password' },
    ],
  },
  ticketing_jira: {
    label: 'Jira',
    fields: [
      { key: 'jira_url', label: 'Jira URL', placeholder: 'https://yourcompany.atlassian.net' },
      { key: 'email', label: 'Email', placeholder: 'admin@yourcompany.com' },
      { key: 'api_token', label: 'API Token', placeholder: 'Jira API token', type: 'password' },
      { key: 'project_key', label: 'Project Key', placeholder: 'SEC' },
    ],
  },
}

function typeLabel(type: string) {
  return INTEGRATION_TYPES[type as IntegrationType]?.label ?? type
}

export function SiemConfig() {
  const qc = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [selectedType, setSelectedType] = useState<IntegrationType>('webhook')
  const [formFields, setFormFields] = useState<Record<string, string>>({})
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => siemApi.list().then((r) => r.data),
  })

  const integrations: Integration[] = data?.integrations ?? []

  const createMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => siemApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['integrations'] })
      setShowAdd(false)
      setFormFields({})
      setName('')
      setError('')
      setTestResult(null)
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
      setError(msg ?? 'Failed to add integration')
    },
  })

  const testMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => siemApi.test(payload),
    onSuccess: (res) =>
      setTestResult({ success: res.data.success, message: res.data.message ?? 'Connection OK' }),
    onError: () => setTestResult({ success: false, message: 'Connection failed' }),
  })

  const buildPayload = () => ({
    type: selectedType,
    name: name || `${typeLabel(selectedType)} ${Date.now()}`,
    ...formFields,
  })

  const typeConfig = INTEGRATION_TYPES[selectedType]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Plug className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">SIEM / Integrations</h1>
        </div>
        <button onClick={() => { setShowAdd(true); setError(''); setTestResult(null) }} className="btn-primary gap-2">
          <Plus className="h-4 w-4" /> Add Integration
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {showAdd && (
        <div className="card p-6 space-y-4">
          <h2 className="text-lg font-semibold text-white">New Integration</h2>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Type</label>
              <select
                value={selectedType}
                onChange={(e) => {
                  setSelectedType(e.target.value as IntegrationType)
                  setFormFields({})
                  setTestResult(null)
                }}
                className="select-field w-full"
              >
                {Object.entries(INTEGRATION_TYPES).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Display Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={`My ${typeLabel(selectedType)}`}
                className="input-field"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {typeConfig.fields.map((f) => (
              <div key={f.key}>
                <label className="block text-sm text-slate-400 mb-1">{f.label}</label>
                <input
                  type={f.type ?? 'text'}
                  value={formFields[f.key] ?? ''}
                  onChange={(e) => setFormFields({ ...formFields, [f.key]: e.target.value })}
                  placeholder={f.placeholder}
                  className="input-field"
                />
              </div>
            ))}
          </div>

          {testResult && (
            <div className={`flex items-center gap-2 rounded-lg border px-4 py-3 text-sm ${
              testResult.success
                ? 'border-green-500/30 bg-green-500/10 text-green-400'
                : 'border-red-500/30 bg-red-500/10 text-red-400'
            }`}>
              {testResult.success
                ? <CheckCircle className="h-4 w-4 flex-shrink-0" />
                : <XCircle className="h-4 w-4 flex-shrink-0" />}
              {testResult.message}
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={() => createMutation.mutate(buildPayload())}
              disabled={createMutation.isPending}
              className="btn-primary"
            >
              {createMutation.isPending ? 'Saving…' : 'Save Integration'}
            </button>
            <button
              onClick={() => testMutation.mutate(buildPayload())}
              disabled={testMutation.isPending}
              className="btn-secondary"
            >
              {testMutation.isPending ? 'Testing…' : 'Test Connection'}
            </button>
            <button
              onClick={() => { setShowAdd(false); setError(''); setTestResult(null) }}
              className="btn-secondary gap-1"
            >
              <X className="h-4 w-4" /> Cancel
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading integrations…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load integrations.</p>
        </div>
      ) : integrations.length === 0 ? (
        <div className="card p-12 text-center space-y-3">
          <Plug className="h-10 w-10 text-slate-600 mx-auto" />
          <p className="text-slate-400">No integrations configured.</p>
          <p className="text-sm text-slate-500">
            Add a SIEM, SOAR, or ticketing integration to route SENTINEL alerts externally.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {integrations.map((integ, idx) => (
            <div key={idx} className="card p-4">
              <button
                className="flex w-full items-center justify-between"
                onClick={() => setExpandedIdx(expandedIdx === idx ? null : idx)}
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10">
                    <Plug className="h-4 w-4 text-cyan-400" />
                  </div>
                  <div className="text-left">
                    <p className="text-sm font-medium text-white">{integ.name}</p>
                    <p className="text-xs text-slate-400">{typeLabel(integ.type)}</p>
                  </div>
                </div>
                {expandedIdx === idx
                  ? <ChevronUp className="h-4 w-4 text-slate-400" />
                  : <ChevronDown className="h-4 w-4 text-slate-400" />}
              </button>
              {expandedIdx === idx && (
                <div className="mt-3 pt-3 border-t border-slate-700">
                  <p className="text-xs text-slate-500 mb-2">Configured keys:</p>
                  <div className="flex flex-wrap gap-2">
                    {integ.config_keys.map((k) => (
                      <span key={k} className="badge bg-slate-700/50 text-slate-300 border border-slate-600/50">
                        {k}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
