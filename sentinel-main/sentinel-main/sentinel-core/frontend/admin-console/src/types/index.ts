// API Response Types
export interface ApiResponse<T> {
  data: T
  message?: string
  error?: string
}

// User Types
export interface User {
  id: number
  username: string
  email: string
  role: UserRole
  status: UserStatus
  created_at: string
  last_login: string | null
}

export type UserRole = 'admin' | 'security_analyst' | 'auditor'
export type UserStatus = 'active' | 'inactive' | 'suspended'

// Auth Types
export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  user: User
  token_type: string
  expires_in: number
}

export interface AuthState {
  isAuthenticated: boolean
  user: User | null
  token: string | null
  refreshToken: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  refreshAccessToken: () => Promise<void>
}

// Threat Types
export interface Threat {
  id: string
  type: ThreatType
  severity: Severity
  status: ThreatStatus
  source_ip: string
  dest_ip: string
  source_port?: number
  dest_port?: number
  timestamp: string
  description: string
  confidence: number
  detection_method: string
  details?: Record<string, unknown>
  /** Alternate field names from API */
  source?: string
  destination?: string
  target?: string
  time?: string
}

export type ThreatType = 
  | 'network_anomaly'
  | 'brute_force'
  | 'malware_detected'
  | 'unauthorized_access'
  | 'ddos_attack'
  | 'port_scan'
  | 'sql_injection'
  | 'xss_attack'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type ThreatStatus = 'new' | 'investigating' | 'mitigated' | 'resolved' | 'false_positive'

// Alert Types
export interface Alert {
  id: string
  type: string
  severity: Severity
  status: AlertStatus
  timestamp: string
  description: string
  details: Record<string, unknown>
  source: string
  assigned_to?: string
  correlation_id?: string
  tags: string[]
}

export type AlertStatus = 'new' | 'acknowledged' | 'resolved' | 'ignored'

// Policy Types
export interface Policy {
  id: string
  name: string
  description: string
  source_cidr?: string
  destination_cidr?: string
  protocol?: string
  port_range?: string
  action: PolicyAction
  priority: number
  is_active: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export type PolicyAction = 'allow' | 'deny' | 'log' | 'rate_limit'

export interface PolicyCreateRequest {
  name: string
  description: string
  source_cidr?: string
  destination_cidr?: string
  protocol?: string
  port_range?: string
  action: PolicyAction
  priority: number
  [key: string]: unknown
}

// Compliance Types
export interface ComplianceFramework {
  id: string
  name: string
  description: string
  version: string
  controls_count: number
  categories: string[]
}

export interface ComplianceAssessment {
  framework_id: string
  score: number
  status: 'compliant' | 'non_compliant' | 'partial'
  last_assessment: string
  controls: ComplianceControl[]
}

export interface ComplianceControl {
  id: string
  name: string
  category: string
  status: 'pass' | 'fail' | 'warning' | 'not_applicable'
  evidence?: string
  recommendation?: string
}

// Dashboard Types
export interface DashboardStats {
  total_threats: number
  blocked_threats: number
  active_policies: number
  compliance_score: number
  threats_by_severity: Record<Severity, number>
  threats_trend: TrendData[]
  traffic_data: TrafficData[]
}

export interface TrendData {
  date: string
  count: number
}

export interface TrafficData {
  time: string
  inbound: number
  outbound: number
  threats: number
}

// Settings Types
export interface SystemSettings {
  notifications: NotificationSettings
  detection: DetectionSettings
  retention: RetentionSettings
}

export interface NotificationSettings {
  email_enabled: boolean
  email_recipients: string[]
  slack_enabled: boolean
  slack_webhook_url?: string
  severity_threshold: Severity
}

export interface DetectionSettings {
  sensitivity_level: 'low' | 'medium' | 'high'
  auto_block_enabled: boolean
  block_threshold: number
  whitelist_ips: string[]
}

export interface RetentionSettings {
  logs_retention_days: number
  alerts_retention_days: number
  reports_retention_days: number
}

// Table/List common types
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  pages: number
}

export interface SortConfig {
  field: string
  direction: 'asc' | 'desc'
}

export interface FilterConfig {
  field: string
  value: string | string[]
  operator: 'eq' | 'ne' | 'contains' | 'in'
}
