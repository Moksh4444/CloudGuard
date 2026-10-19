import React, { useState } from 'react';
import {
  Network,
  Play,
  RotateCw,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Terminal,
  ShieldCheck,
  FileText,
  HelpCircle,
} from 'lucide-react';
import { api } from '../services/api';
import { DiagnosticRun, TroubleshootingFinding } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { FindingCard } from '../components/FindingCard';

const APPROVED_PORTS = [
  { port: 443, label: 'HTTPS (443)' },
  { port: 80, label: 'HTTP (80)' },
  { port: 22, label: 'SSH (22)' },
  { port: 53, label: 'DNS (53)' },
  { port: 8080, label: 'Web Proxy (8080)' },
  { port: 8443, label: 'Alt HTTPS (8443)' },
  { port: 5432, label: 'PostgreSQL (5432)' },
  { port: 3306, label: 'MySQL (3306)' },
];

export const NetworkDiagnostics: React.FC = () => {
  const [target, setTarget] = useState('example.com');
  const [port, setPort] = useState(443);
  const [customPort, setCustomPort] = useState('');
  const [runDns, setRunDns] = useState(true);
  const [runPort, setRunPort] = useState(true);
  const [runTraceroute, setRunTraceroute] = useState(false);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DiagnosticRun | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRun = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const targetPort = customPort ? parseInt(customPort, 10) : port;

    try {
      const data = await api.runNetworkDiagnostic({
        target: target.trim(),
        port: targetPort,
        run_dns: runDns,
        run_port: runPort,
        run_traceroute: runTraceroute,
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Diagnostic failed to execute');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectPreset = (domain: string, p: number) => {
    setTarget(domain);
    setPort(p);
    setCustomPort('');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Network className="w-5 h-5 text-sky-400" /> Network Diagnostics Module
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Perform controlled DNS resolution, TCP three-way handshake verification, and bounded route diagnostics.
        </p>
      </div>

      {/* Target Input Card */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
        <form onSubmit={handleRun} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                Target Hostname or IP
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. example.com or 1.1.1.1"
                  required
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-sm font-mono focus:outline-none focus:border-sky-500 transition"
                />
              </div>
              <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                <span className="text-slate-500">Presets:</span>
                <button
                  type="button"
                  onClick={() => handleSelectPreset('example.com', 443)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
                >
                  example.com:443
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectPreset('cloudflare.com', 443)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
                >
                  cloudflare.com:443
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectPreset('dns.google', 53)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
                >
                  dns.google:53
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                Target Port
              </label>
              <select
                value={customPort ? 'custom' : port}
                onChange={(e) => {
                  if (e.target.value === 'custom') {
                    setCustomPort('8443');
                  } else {
                    setPort(parseInt(e.target.value, 10));
                    setCustomPort('');
                  }
                }}
                className="w-full px-3 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-sm font-mono focus:outline-none focus:border-sky-500 transition"
              >
                {APPROVED_PORTS.map((item) => (
                  <option key={item.port} value={item.port}>
                    {item.label}
                  </option>
                ))}
                <option value="custom">Custom Approved Port...</option>
              </select>

              {customPort && (
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={customPort}
                  onChange={(e) => setCustomPort(e.target.value)}
                  placeholder="Port number"
                  className="mt-2 w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:outline-none focus:border-sky-500"
                />
              )}
            </div>
          </div>

          {/* Diagnostic Options */}
          <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-5 text-xs text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={runDns}
                  onChange={(e) => setRunDns(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500"
                />
                <span>A / AAAA DNS Resolution</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={runPort}
                  onChange={(e) => setRunPort(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500"
                />
                <span>TCP Three-Way Handshake</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer select-none" title="Safe bounded route path probe">
                <input
                  type="checkbox"
                  checked={runTraceroute}
                  onChange={(e) => setRunTraceroute(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500"
                />
                <span>Bounded Traceroute (Max 15 hops)</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading || (!runDns && !runPort && !runTraceroute)}
              className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              <span>{loading ? 'Executing Diagnostics...' : 'Start Diagnostic'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-sm flex items-start gap-3">
          <XCircle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">Diagnostic Execution Error</h4>
            <p className="text-xs text-rose-300/90 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Summary Header Card */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="text-xs text-slate-400 font-medium">Session ID:</span>
                  <span className="font-mono text-xs text-slate-300">{result.id.slice(0, 13)}...</span>
                  <StatusBadge status={result.status} size="md" />
                </div>
                <h3 className="text-lg font-bold text-white font-mono">{result.target}</h3>
                <p className="text-xs text-slate-400 mt-0.5">{result.summary}</p>
              </div>
              <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Latency</span>
                  <span className="font-bold text-sky-400">{result.duration_ms.toFixed(1)} ms</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Checks</span>
                  <span className="font-bold text-slate-200">{(result.checks || []).length} executed</span>
                </div>
              </div>
            </div>
          </div>

          {/* Diagnostic Checks Executed */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-4">
              Executed Diagnostic Layers
            </h3>

            <div className="space-y-3">
              {(result.checks || []).map((chk, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-slate-850/80 border border-slate-800 text-xs flex flex-col md:flex-row md:items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold uppercase tracking-wider text-slate-200">
                        {chk.check_type === 'dns'
                          ? 'DNS Resolution'
                          : chk.check_type === 'port'
                          ? `TCP Port Handshake (${chk.details?.port || port})`
                          : 'Traceroute Path'}
                      </span>
                      <StatusBadge status={chk.status} size="sm" />
                    </div>

                    {chk.error_message ? (
                      <p className="text-rose-400 font-mono">{chk.error_message}</p>
                    ) : (
                      <div className="text-slate-400 font-mono">
                        {chk.check_type === 'dns' && chk.details?.records?.A && (
                          <span>Resolved A: {chk.details.records.A.join(', ') || 'None'}</span>
                        )}
                        {chk.check_type === 'port' && (
                          <span>Target IP: {chk.details?.resolved_ip || 'Resolved'} • Handshake Complete</span>
                        )}
                        {chk.check_type === 'traceroute' && (
                          <span>Hops recorded: {chk.details?.hops_count || 0}</span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px] shrink-0">
                    <span>{chk.duration_ms.toFixed(1)} ms</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Troubleshooting Intelligence Findings */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Troubleshooting Intelligence Engine
                </h3>
                <p className="text-xs text-slate-400">
                  Automated correlation of symptoms, technical explanations, and recommended consultant actions.
                </p>
              </div>
            </div>

            {(!result.findings || result.findings.length === 0) ? (
              <div className="p-4 rounded-xl border border-emerald-800/60 bg-emerald-950/30 text-emerald-300 text-xs flex items-center gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                <span>
                  All diagnostic checks completed successfully. No anomalies or connection impediments were identified.
                </span>
              </div>
            ) : (
              <div className="space-y-3">
                {result.findings.map((f, i) => (
                  <FindingCard key={i} finding={f} index={i} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
