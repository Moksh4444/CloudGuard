import React, { useState } from 'react';
import {
  Lock,
  Play,
  RotateCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Calendar,
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  FileBadge,
} from 'lucide-react';
import { api } from '../services/api';
import { TlsCertificateInfo } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { FindingCard } from '../components/FindingCard';

export const TlsInspector: React.FC = () => {
  const [hostname, setHostname] = useState('cloudflare.com');
  const [port, setPort] = useState(443);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TlsCertificateInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!hostname.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.inspectTls({
        hostname: hostname.trim(),
        port,
        timeout_seconds: 6.0,
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'TLS Inspection failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePreset = (host: string, p: number) => {
    setHostname(host);
    setPort(p);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Lock className="w-5 h-5 text-sky-400" /> TLS Certificate Inspector
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Read-only X.509 certificate validation, expiration countdown, Subject Alternative Names (SAN), and cipher
          suite inspection.
        </p>
      </div>

      {/* Target Input */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
        <form onSubmit={handleInspect} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                Target Hostname
              </label>
              <input
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="e.g. google.com or github.com"
                required
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-sm font-mono focus:outline-none focus:border-sky-500 transition"
              />
              <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                <span className="text-slate-500">Presets:</span>
                <button
                  type="button"
                  onClick={() => handlePreset('cloudflare.com', 443)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
                >
                  cloudflare.com:443
                </button>
                <button
                  type="button"
                  onClick={() => handlePreset('google.com', 443)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
                >
                  google.com:443
                </button>
                <button
                  type="button"
                  onClick={() => handlePreset('badssl.com', 443)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 font-mono transition"
                >
                  badssl.com:443
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                Port
              </label>
              <input
                type="number"
                min="1"
                max="65535"
                value={port}
                onChange={(e) => setPort(parseInt(e.target.value, 10))}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-sm font-mono focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              <span>{loading ? 'Inspecting Certificate...' : 'Inspect TLS Certificate'}</span>
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-sm flex items-start gap-3">
          <XCircle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">TLS Inspection Error</h4>
            <p className="text-xs text-rose-300/90 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Validity Banner */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <StatusBadge status={result.is_valid ? 'SUCCESS' : 'FAILURE'} size="lg" />
                <div>
                  <h3 className="text-base font-bold text-white font-mono">{hostname}:{port}</h3>
                  <p className="text-xs text-slate-400">
                    Negotiated Protocol:{' '}
                    <span className="font-mono text-sky-400 font-bold">{result.tls_version_negotiated || 'Unknown'}</span>
                    {' '}&bull; Cipher: <span className="font-mono text-slate-300">{result.cipher_suite || 'Default'}</span>
                  </p>
                </div>
              </div>

              {/* Days Remaining Countdown Badge */}
              {result.days_remaining !== undefined && result.days_remaining !== null && (
                <div
                  className={`p-3 rounded-lg border flex items-center gap-2.5 ${
                    result.days_remaining > 30
                      ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300'
                      : result.days_remaining >= 0
                      ? 'bg-amber-950/60 border-amber-800/80 text-amber-300'
                      : 'bg-rose-950/60 border-rose-800/80 text-rose-300'
                  }`}
                >
                  <Calendar className="w-5 h-5" />
                  <div>
                    <span className="text-[10px] uppercase font-bold block">
                      {result.days_remaining >= 0 ? 'Days to Expiry' : 'Expired'}
                    </span>
                    <span className="font-mono text-base font-bold">
                      {Math.abs(result.days_remaining)} {Math.abs(result.days_remaining) === 1 ? 'day' : 'days'}
                      {result.days_remaining < 0 ? ' ago' : ''}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Verification Error Box */}
          {result.verification_error && (
            <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-200 text-xs flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-rose-100 block font-semibold mb-0.5">TLS Certificate Verification Failed</strong>
                <p className="font-mono text-rose-300">{result.verification_error}</p>
              </div>
            </div>
          )}

          {/* Certificate Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Subject Details */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
                <FileBadge className="w-4 h-4 text-sky-400" /> Certificate Subject
              </h3>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px] uppercase">Common Name (CN)</span>
                  <span className="text-sky-300 font-bold">{result.subject?.commonName || 'N/A'}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px] uppercase">Organization (O)</span>
                  <span className="text-slate-200">{result.subject?.organizationName || 'N/A'}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px] uppercase">Serial Number</span>
                  <span className="text-slate-400 truncate block">{result.serial_number || 'N/A'}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px] uppercase">Hostname Match Verification</span>
                  <span className={result.hostname_matches ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {result.hostname_matches ? 'Valid Match for SNI' : 'Hostname Mismatch'}
                  </span>
                </div>
              </div>
            </div>

            {/* Issuer & Validity Details */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-sky-400" /> Issuer & Validity Window
              </h3>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px] uppercase">Issuer Common Name</span>
                  <span className="text-slate-200 font-bold">{result.issuer?.commonName || 'N/A'}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px] uppercase">Issuer Organization</span>
                  <span className="text-slate-300">{result.issuer?.organizationName || 'N/A'}</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Valid From</span>
                    <span className="text-slate-300 text-[11px]">
                      {result.valid_from ? new Date(result.valid_from).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Valid Until</span>
                    <span className="text-slate-300 text-[11px]">
                      {result.valid_until ? new Date(result.valid_until).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Subject Alternative Names (SANs) */}
          {result.subject_alt_names.length > 0 && (
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-2">
                Subject Alternative Names ({result.subject_alt_names.length})
              </h3>
              <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto p-1">
                {result.subject_alt_names.map((san, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-sky-300"
                  >
                    {san}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Diagnostic Limitations Notice */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/70 text-xs text-slate-400 flex items-start gap-2.5">
            <HelpCircle className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-300 block font-medium mb-0.5">Zero-Trust Inspection Boundary</strong>
              {result.inspection_limitations}
            </div>
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
