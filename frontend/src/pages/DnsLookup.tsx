import React, { useState } from 'react';
import {
  Search,
  Play,
  RotateCw,
  Copy,
  Check,
  HelpCircle,
  FileText,
  AlertCircle,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { api } from '../services/api';
import { DnsLookupResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { FindingCard } from '../components/FindingCard';

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'];

export const DnsLookup: React.FC = () => {
  const [target, setTarget] = useState('cloudflare.com');
  const [selectedTypes, setSelectedTypes] = useState<string[]>(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DnsLookupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedType, setCopiedType] = useState<string | null>(null);

  const toggleType = (t: string) => {
    if (selectedTypes.includes(t)) {
      if (selectedTypes.length > 1) {
        setSelectedTypes(selectedTypes.filter((x) => x !== t));
      }
    } else {
      setSelectedTypes([...selectedTypes, t]);
    }
  };

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.lookupDns({
        target: target.trim(),
        record_types: selectedTypes,
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'DNS Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const copyRecords = (rtype: string, values: string[]) => {
    navigator.clipboard.writeText(values.join('\n'));
    setCopiedType(rtype);
    setTimeout(() => setCopiedType(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Search className="w-5 h-5 text-sky-400" /> DNS Lookup & Analysis Module
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Query standard authoritative and cached DNS records (A, AAAA, CNAME, MX, NS, TXT) with resolution timing.
        </p>
      </div>

      {/* Target & Record Types */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
        <form onSubmit={handleLookup} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              Domain Name
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. google.com or github.com"
              required
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-sm font-mono focus:outline-none focus:border-sky-500 transition"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Select Record Types to Query
            </label>
            <div className="flex flex-wrap gap-2">
              {RECORD_TYPES.map((t) => {
                const active = selectedTypes.includes(t);
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => toggleType(t)}
                    className={`px-3 py-1 rounded-md text-xs font-mono font-bold transition border ${
                      active
                        ? 'bg-sky-600 text-white border-sky-500 shadow-sm'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {t}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              <span>{loading ? 'Resolving Records...' : 'Execute DNS Query'}</span>
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-sm flex items-start gap-3">
          <XCircle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">DNS Resolution Error</h4>
            <p className="text-xs text-rose-300/90 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Summary Banner */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md flex items-center justify-between">
            <div className="flex items-center gap-3">
              <StatusBadge status={result.status} size="lg" />
              <div>
                <h3 className="text-base font-bold text-white font-mono">{result.target}</h3>
                <p className="text-xs text-slate-400">
                  Queried {selectedTypes.length} record types in {result.duration_ms.toFixed(1)}ms
                </p>
              </div>
            </div>
            <div className="font-mono text-sm text-sky-400 font-bold">{result.duration_ms.toFixed(1)} ms</div>
          </div>

          {/* Records Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(result.records).map(([rtype, vals]) => (
              <div
                key={rtype}
                className="p-4 rounded-xl border border-slate-800 bg-slate-900/90 shadow-sm flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-sky-400 font-mono font-bold text-xs border border-slate-700">
                      {rtype}
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {vals.length} {vals.length === 1 ? 'record' : 'records'}
                    </span>
                  </div>

                  {vals.length === 0 ? (
                    <p className="text-xs text-slate-500 italic py-2">No {rtype} records found for this domain.</p>
                  ) : (
                    <div className="space-y-1 my-2">
                      {vals.map((v, i) => (
                        <div
                          key={i}
                          className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-200 break-all select-all"
                        >
                          {v}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {vals.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80 flex justify-end">
                    <button
                      type="button"
                      onClick={() => copyRecords(rtype, vals)}
                      className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1 transition"
                    >
                      {copiedType === rtype ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400 font-semibold">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Records</span>
                        </>
                      )}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Educational Guide on DNS Troubleshooting */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-sky-400" /> DNS Engineering Knowledge Base
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-400">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/70">
                <strong className="text-slate-200 block mb-1">Non-Existent Domain (NXDOMAIN)</strong>
                The authoritative nameserver asserts the domain does not exist. Verify spelling, registration status in
                Whois, or delegated NS records.
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/70">
                <strong className="text-slate-200 block mb-1">DNS Resolution Timeout</strong>
                Packet loss on UDP port 53 or an unresponsive local resolver. Test secondary resolvers (1.1.1.1 or
                8.8.8.8) using nslookup.
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/70">
                <strong className="text-slate-200 block mb-1">Authoritative vs Recursive Resolver</strong>
                Local OS resolution queries a configured recursive resolver which caches records based on TTL. It does
                not query root or TLD servers directly.
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/70">
                <strong className="text-slate-200 block mb-1">Propagation Delay Disclaimers</strong>
                Do not infer global DNS propagation issues solely from one failed local query; intermediate recursive
                caches may have cached negative responses (NXDOMAIN TTL).
              </div>
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
