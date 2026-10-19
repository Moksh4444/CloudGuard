/**
 * API Client for CloudGuard Backend.
 */
import {
  NetworkDiagnosticRequest,
  HttpAnalysisResponse,
  DnsLookupResponse,
  TlsCertificateInfo,
  CloudAnalysisResponse,
  AnalyticsOverviewResponse,
  DiagnosticRun,
  SystemHealth,
} from '../types';

const API_BASE = '/api/v1';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    let errorDetail = 'API request failed';
    try {
      const errorJson = await res.json();
      errorDetail = errorJson.detail || errorJson.message || JSON.stringify(errorJson);
    } catch {
      errorDetail = await res.text();
    }
    throw new Error(errorDetail || `HTTP error ${res.status}`);
  }

  return res.json();
}

export const api = {
  // System Health
  getHealth: () => request<SystemHealth>('/health'),

  // Diagnostics
  runNetworkDiagnostic: (data: NetworkDiagnosticRequest) =>
    request<DiagnosticRun>('/diagnostics/network', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  analyzeHttp: (data: { url: string; allow_redirects: boolean; timeout_seconds: number }) =>
    request<HttpAnalysisResponse>('/diagnostics/http', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  lookupDns: (data: { target: string; record_types: string[] }) =>
    request<DnsLookupResponse>('/diagnostics/dns', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  inspectTls: (data: { hostname: string; port: number; timeout_seconds: number }) =>
    request<TlsCertificateInfo>('/diagnostics/tls', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Cloud Security
  analyzeCloudConfig: (data: { name: string; config_json: string }) =>
    request<CloudAnalysisResponse>('/cloud-security/analyze', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  uploadCloudConfig: async (file: File): Promise<CloudAnalysisResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/cloud-security/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'File upload analysis failed');
    }
    return res.json();
  },

  listCloudAnalyses: () => request<any[]>('/cloud-security/analyses'),

  // Analytics & History
  getAnalyticsOverview: (startDate?: string, endDate?: string) => {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    return request<AnalyticsOverviewResponse>(`/analytics/overview?${params.toString()}`);
  },

  listHistoryRuns: (page = 1, pageSize = 10, status?: string, targetType?: string, search?: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (status) params.append('status', status);
    if (targetType) params.append('target_type', targetType);
    if (search) params.append('search', search);
    return request<{ total: number; page: number; page_size: number; items: DiagnosticRun[] }>(
      `/history/runs?${params.toString()}`
    );
  },

  getRunDetails: (runId: string) => request<DiagnosticRun>(`/history/runs/${runId}`),

  deleteRun: (runId: string) =>
    request<{ message: string }>(`/history/runs/${runId}`, {
      method: 'DELETE',
    }),

  seedDemoData: () =>
    request<{ status: string; message: string; runs_seeded: number }>('/history/seed-demo', {
      method: 'POST',
    }),

  // Reports
  exportReport: (runId: string, format: 'json' | 'csv' | 'html') =>
    request<{ report_uid: string; format: string; filename: string; content: string }>(
      '/reports/export',
      {
        method: 'POST',
        body: JSON.stringify({ run_id: runId, format }),
      }
    ),

  listReports: () => request<any[]>('/reports'),
};
