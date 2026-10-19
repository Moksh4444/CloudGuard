export type CheckStatus = 'SUCCESS' | 'WARNING' | 'FAILURE' | 'ERROR';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface TroubleshootingFinding {
  symptom: string;
  confidence: 'HIGH' | 'MEDIUM' | 'TENTATIVE';
  likely_explanations: string[];
  diagnostic_evidence: string;
  next_steps: string[];
  limitations?: string;
}

export interface DiagnosticCheck {
  check_type: string;
  status: CheckStatus;
  duration_ms: number;
  details: Record<string, any>;
  error_message?: string;
}

export interface DiagnosticRun {
  id: string;
  target: string;
  target_type: 'domain' | 'url' | 'ip' | 'tls';
  status: CheckStatus;
  summary?: string;
  duration_ms: number;
  created_at: string;
  checks_count?: number;
  findings_count?: number;
  checks?: DiagnosticCheck[];
  findings?: TroubleshootingFinding[];
}

export interface NetworkDiagnosticRequest {
  target: string;
  port: number;
  run_dns: boolean;
  run_port: boolean;
  run_traceroute: boolean;
}

export interface HttpRedirectHop {
  status_code: number;
  url: string;
  location?: string;
}

export interface HttpHeaderItem {
  name: string;
  value: string;
}

export interface HttpAnalysisResponse {
  initial_url: string;
  final_url: string;
  status_code?: number;
  status_phrase?: string;
  duration_ms: number;
  redirect_count: number;
  redirect_hops: HttpRedirectHop[];
  headers: HttpHeaderItem[];
  content_type?: string;
  content_length?: number;
  is_tls: boolean;
  tls_error?: string;
  http_error?: string;
  findings: TroubleshootingFinding[];
}

export interface DnsLookupResponse {
  target: string;
  duration_ms: number;
  status: CheckStatus;
  records: Record<string, string[]>;
  error_message?: string;
  educational_notes: string[];
  findings: TroubleshootingFinding[];
}

export interface TlsCertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  valid_from?: string;
  valid_until?: string;
  days_remaining?: number;
  is_expired: boolean;
  hostname_matches: boolean;
  subject_alt_names: string[];
  serial_number?: string;
  signature_algorithm?: string;
  tls_version_negotiated?: string;
  cipher_suite?: string;
  is_valid: boolean;
  verification_error?: string;
  inspection_limitations: string;
  findings: TroubleshootingFinding[];
}

export interface SecurityFinding {
  title: string;
  severity: SeverityLevel;
  rule_id?: string;
  port_range?: string;
  protocol?: string;
  cidr?: string;
  evidence: string;
  risk_explanation: string;
  remediation: string;
  confidence: string;
}

export interface CloudAnalysisResponse {
  id: string;
  name: string;
  group_name: string;
  group_id?: string;
  description?: string;
  vpc_id?: string;
  total_rules_evaluated: number;
  summary: Record<SeverityLevel, number>;
  findings: SecurityFinding[];
  educational_note: string;
  created_at: string;
}

export interface AnalyticsOverviewResponse {
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  warning_runs: number;
  avg_response_time_ms: number;
  median_response_time_ms: number;
  p95_response_time_ms: number;
  dns_failure_count: number;
  http_status_distribution: Record<string, number>;
  failure_by_module: Record<string, number>;
  most_frequent_issues: { symptom: string; count: number }[];
  runs_over_time: { date: string; runs: number }[];
  cloud_severity_distribution: Record<SeverityLevel, number>;
}

export interface SystemHealth {
  status: 'HEALTHY' | 'DEGRADED';
  version: string;
  platform: string;
  python_version: string;
  database_connected: boolean;
  traceroute_supported: boolean;
  ssrf_protection_active: boolean;
  allowed_ports_count: number;
}
