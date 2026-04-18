export interface User {
  id: number
  username: string
  email: string
  role: string
  status: string
  created_at: string
  last_login: string | null
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  user: User
}

export interface Threat {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  source_ip?: string
  destination_ip?: string
  confidence?: number
  status: string
  timestamp: string
  description?: string
  details?: Record<string, unknown>
  model_verdicts?: ModelVerdict[]
  explanation?: string
}

export interface ModelVerdict {
  model: string
  verdict: string
  confidence: number
  explanation?: string
}

export interface Alert {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'new' | 'acknowledged' | 'resolved' | 'ignored'
  timestamp: string
  description: string
  details: Record<string, unknown>
  source: string
  tags: string[]
}

export interface Policy {
  id: string
  name: string
  description: string
  source_cidr: string
  destination_cidr: string
  protocol: string
  port_range: string
  action: 'allow' | 'deny'
  priority: number
  is_active: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface PolicyCreateRequest {
  name: string
  description: string
  action: 'allow' | 'deny'
  priority: number
  source_cidr?: string
  destination_cidr?: string
  protocol?: string
  port_range?: string
}

export interface Framework {
  id: string
  name: string
  description: string
  version: string
  score?: number
  last_assessed?: string
  status?: string
  total_controls?: number
  passing_controls?: number
  controls_count?: number
  categories?: string[]
}

export interface AssessmentDetail {
  control_id: string
  control_name: string
  category: string
  status: 'compliant' | 'non_compliant' | 'not_applicable' | string
  findings: string[]
}

export interface AssessmentResult {
  framework: string
  overall_score: number
  status: string
  timestamp: string
  controls_assessed: number
  controls_compliant: number
  controls_non_compliant: number
  controls_not_applicable: number
  details: AssessmentDetail[]
}

export interface ComplianceAssessment {
  framework: string
  score: number
  passing: number
  failing: number
  total: number
  gaps: ComplianceGap[]
  timestamp: string
}

export interface ComplianceGap {
  control_id: string
  title: string
  severity: string
  status: string
  recommendation: string
}

export interface HardeningCheck {
  id: string
  benchmark: string
  category: string
  title: string
  status: 'pass' | 'fail' | 'warning' | 'info'
  severity: string
  description: string
  remediation?: string
}

export interface HardeningPosture {
  score: number
  total_checks: number
  passed: number
  failed: number
  warnings: number
  last_scan?: string
}

export interface HIDSEvent {
  id: string
  event_type: string
  severity: string
  timestamp: string
  source: string
  description: string
  details?: Record<string, unknown>
}

export interface AuditEntry {
  id: string
  event_type: string
  user: string
  resource_type: string
  resource_id?: string
  action: string
  timestamp: string
  details?: Record<string, unknown>
  ip_address?: string
}

export interface Tenant {
  id: number
  tenant_id: string
  name: string
  plan: string
  status: string
  created_at: string
  max_users: number
  max_agents: number
}

export interface MfaStatus {
  enabled: boolean
  enrolled: boolean
  method: string
  has_backup_codes: boolean
}

export interface Integration {
  name: string
  type: string
  config_keys: string[]
}

export interface AuditStats {
  total_events: number
  by_category: Record<string, number>
  retention_days: number
  timestamp: string
}

export interface DetectionResult {
  threat_id: string
  models: ModelVerdict[]
  consensus: string
  confidence: number
  recommendation: string
}

export interface PolicyDecision {
  policy_id: string
  action: string
  reason: string
  applied_at: string
}

export interface DashboardStats {
  totalThreats: number
  blockedThreats: number
  activePolicies: number
  complianceScore: number
}

export interface TrafficDataPoint {
  time: string
  inbound: number
  outbound: number
  blocked: number
}

export interface ThreatDataPoint {
  time: string
  count: number
  severity?: string
}
