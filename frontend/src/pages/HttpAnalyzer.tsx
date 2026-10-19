import React, { useState } from 'react';
import {
  Globe,
  Play,
  RotateCw,
  ArrowRight,
  ShieldAlert,
  Lock,
  Layers,
  FileCode,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../services/api';
import { HttpAnalysisResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { FindingCard } from '../components/FindingCard';

export const HttpAnalyzer: React.FC = () => {
  const [url, setUrl] = useState('https://httpbin.org/status/200');
  const [allowRedirects, setAllowRedirects] = useState(true);
  const [timeout, setTimeoutSec] = useState(6.0);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<HttpAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.analyzeHttp({
        url: url.trim(),
        allow_redirects: allowRedirects,
        timeout_seconds: timeout,
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'HTTP analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePreset = (presetUrl: string) => {
    setUrl(presetUrl);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Globe className="w-5 h-5 text-sky-400" /> HTTP / HTTPS Analyzer
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Inspect web responses, redirect hops, headers, and protocol-level errors with SSRF protection boundaries.
        </p>
      </div>

      {/* URL Input Form */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              Target HTTP / HTTPS URL
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/api/health"
              required
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-sm font-mono focus:outline-none focus:border-sky-500 transition"
            />
            {/* Presets */}
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="text-slate-500">Presets:</span>
              <button
                type="button"
                onClick={() => handlePreset('https://httpbin.org/status/200')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
              >
                200 OK
              </button>
              <button
                type="button"
                onClick={() => handlePreset('https://httpbin.org/redirect/3')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
              >
                Redirect Chain (3 hops)
              </button>
              <button
                type="button"
                onClick={() => handlePreset('https://httpbin.org/status/403')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 font-mono transition"
              >
                403 Forbidden
              </button>
              <button
                type="button"
                onClick={() => handlePreset('https://httpbin.org/status/502')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 font-mono transition"
              >
                502 Bad Gateway
              </button>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-6 text-xs text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={allowRedirects}
                  onChange={(e) => setAllowRedirects(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500"
                />
                <span>Follow Redirects (Max 5 hops)</span>
              </label>

              <div className="flex items-center gap-2">
                <span className="text-slate-400">Timeout:</span>
                <input
                  type="range"
                  min="2"
                  max="20"
                  step="1"
                  value={timeout}
                  onChange={(e) => setTimeoutSec(parseFloat(e.target.value))}
                  className="w-24 accent-sky-500"
                />
                <span className="font-mono text-slate-200">{timeout}s</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              <span>{loading ? 'Analyzing Endpoint...' : 'Analyze Endpoint'}</span>
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-sm flex items-start gap-3">
          <XCircle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">HTTP Analysis Error</h4>
            <p className="text-xs text-rose-300/90 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Status & Latency Card */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5 mb-1.5">
                  {result.status_code ? (
                    <span
                      className={`text-sm font-bold font-mono px-3 py-1 rounded-md border ${
                        result.status_code < 300
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                          : result.status_code < 400
                          ? 'bg-sky-950 text-sky-300 border-sky-700'
                          : result.status_code < 500
                          ? 'bg-amber-950 text-amber-300 border-amber-700'
                          : 'bg-rose-950 text-rose-300 border-rose-700'
                      }`}
                    >
                      HTTP {result.status_code} {result.status_phrase || ''}
                    </span>
                  ) : (
                    <span className="text-sm font-bold font-mono px-3 py-1 rounded-md bg-rose-950 text-rose-300 border border-rose-700">
                      Connection Failed
                    </span>
                  )}
                  {result.is_tls && (
                    <span className="text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800 flex items-center gap-1">
                      <Lock className="w-3 h-3" /> TLS Verified
                    </span>
                  )}
                </div>
                <div className="text-xs font-mono text-slate-300 break-all">
                  <span className="text-slate-500">Destination:</span> {result.final_url}
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Latency</span>
                  <span className="font-bold text-sky-400">{result.duration_ms.toFixed(1)} ms</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Redirects</span>
                  <span className="font-bold text-slate-200">{result.redirect_count} hops</span>
                </div>
              </div>
            </div>
          </div>

          {/* TLS Error vs HTTP Error Distinction */}
          {result.tls_error && (
            <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-200 text-xs">
              <div className="flex items-center gap-2 font-bold mb-1">
                <Lock className="w-4 h-4 text-rose-400" />
                <span>TLS Verification Failure Identified</span>
              </div>
              <p className="font-mono text-rose-300">{result.tls_error}</p>
              <p className="text-slate-400 mt-2">
                Note: In accordance with zero-trust security standards, CloudGuard strictly maintains TLS verification
                and does not bypass validation.
              </p>
            </div>
          )}

          {result.http_error && (
            <div className="p-4 rounded-xl border border-amber-800 bg-amber-950/60 text-amber-200 text-xs">
              <div className="flex items-center gap-2 font-bold mb-1">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Protocol or Transport Impediment</span>
              </div>
              <p className="font-mono text-amber-300">{result.http_error}</p>
            </div>
          )}

          {/* Redirect Chain Visualization */}
          {result.redirect_hops.length > 0 && (
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-400" /> Redirect Chain ({result.redirect_hops.length} hops)
              </h3>
              <div className="space-y-2">
                {result.redirect_hops.map((hop, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-lg bg-slate-850/80 border border-slate-800 flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-400 font-bold border border-sky-800">
                        {hop.status_code}
                      </span>
                      <span className="text-slate-300 truncate">{hop.url}</span>
                    </div>
                    {hop.location && (
                      <div className="text-slate-500 flex items-center gap-1 shrink-0">
                        <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                        <span className="text-slate-400 max-w-[200px] truncate">{hop.location}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Response Headers Table */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-sky-400" /> Allowlisted Response Headers
            </h3>
            {result.headers.length === 0 ? (
              <p className="text-xs text-slate-500">No response headers captured.</p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-4 w-1/3">Header Name</th>
                      <th className="py-2.5 px-4">Header Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-900/50">
                    {result.headers.map((h, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition">
                        <td className="py-2 px-4 text-sky-400 font-semibold">{h.name}</td>
                        <td className="py-2 px-4 text-slate-300 break-all">{h.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Troubleshooting Intelligence */}
          {result.findings.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                Troubleshooting Intelligence Findings
              </h3>
              {result.findings.map((f, i) => (
                <FindingCard key={i} finding={f} index={i} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
