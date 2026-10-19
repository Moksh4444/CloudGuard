import React, { useEffect, useState } from 'react';
import {
  Activity,
  Search,
  Filter,
  Download,
  Trash2,
  Eye,
  ChevronLeft,
  ChevronRight,
  RotateCw,
  X,
  FileText,
  Clock,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';
import { DiagnosticRun } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { FindingCard } from '../components/FindingCard';
import { EmptyState } from '../components/EmptyState';

export const HistoryAnalytics: React.FC = () => {
  const [runs, setRuns] = useState<DiagnosticRun[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  // Selected run modal state
  const [selectedRun, setSelectedRun] = useState<DiagnosticRun | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    loadRuns();
  }, [page, statusFilter, typeFilter]);

  const loadRuns = async () => {
    setLoading(true);
    try {
      const data = await api.listHistoryRuns(
        page,
        pageSize,
        statusFilter === 'ALL' ? undefined : statusFilter,
        typeFilter === 'ALL' ? undefined : typeFilter,
        search.trim() ? search.trim() : undefined
      );
      setRuns(data.items);
      setTotal(data.total);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadRuns();
  };

  const handleViewDetails = async (runId: string) => {
    setLoadingDetails(true);
    try {
      const details = await api.getRunDetails(runId);
      setSelectedRun(details);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleDelete = async (runId: string) => {
    if (!confirm('Are you sure you want to delete this diagnostic session?')) return;
    try {
      await api.deleteRun(runId);
      if (selectedRun?.id === runId) setSelectedRun(null);
      await loadRuns();
    } catch (e) {
      console.error(e);
    }
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Activity className="w-5 h-5 text-sky-400" /> Diagnostic Scan History & Audit Logs
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Historical record of all executed diagnostic runs, network checks, and troubleshooting intelligence findings.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md flex flex-col md:flex-row items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 w-full md:w-auto flex-1">
          <div className="relative w-full max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by target domain, IP, or URL..."
              className="w-full pl-9 pr-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:outline-none focus:border-sky-500"
            />
          </div>
          <button
            type="submit"
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition border border-slate-700 shrink-0"
          >
            Search
          </button>
        </form>

        <div className="flex items-center gap-3 w-full md:w-auto justify-end text-xs">
          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-sky-500 font-mono"
            >
              <option value="ALL">All Statuses</option>
              <option value="SUCCESS">Success</option>
              <option value="WARNING">Warning</option>
              <option value="FAILURE">Failure</option>
            </select>
          </div>

          {/* Type Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-sky-500 font-mono"
            >
              <option value="ALL">All Types</option>
              <option value="DOMAIN">Domain</option>
              <option value="URL">URL</option>
              <option value="TLS">TLS</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 shadow-md overflow-hidden">
        {loading ? (
          <div className="p-12 flex items-center justify-center">
            <RotateCw className="w-6 h-6 animate-spin text-sky-400" />
          </div>
        ) : runs.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="No Matching Diagnostic Sessions"
            description="No sessions match the specified filters or search term."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Target Host / URL</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Latency</th>
                  <th className="py-3 px-4">Checks</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {runs.map((run) => (
                  <tr
                    key={run.id}
                    onClick={() => handleViewDetails(run.id)}
                    className="hover:bg-slate-850/60 cursor-pointer transition"
                  >
                    <td className="py-3 px-4 text-slate-200 font-bold max-w-[220px] truncate" title={run.target}>
                      {run.target}
                    </td>
                    <td className="py-3 px-4 text-slate-400 uppercase text-[11px]">{run.target_type}</td>
                    <td className="py-3 px-4">
                      <StatusBadge status={run.status} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-sky-400">{run.duration_ms.toFixed(1)}ms</td>
                    <td className="py-3 px-4 text-slate-300">{run.checks_count || 1}</td>
                    <td className="py-3 px-4">
                      {run.findings_count && run.findings_count > 0 ? (
                        <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold">
                          {run.findings_count}
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(run.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => handleViewDetails(run.id)}
                          className="p-1.5 text-slate-400 hover:text-sky-400 hover:bg-slate-800 rounded transition"
                          title="View Details"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(run.id)}
                          className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition"
                          title="Delete Session"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing {runs.length} of {total} total runs (Page {page} of {totalPages})
          </span>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(p - 1, 1))}
              className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent transition text-slate-300"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 font-mono text-slate-300">{page}</span>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent transition text-slate-300"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Run Detail Modal */}
      {selectedRun && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-850">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <StatusBadge status={selectedRun.status} size="sm" />
                  <span className="font-mono text-xs text-slate-400">{selectedRun.id}</span>
                </div>
                <h3 className="text-lg font-bold text-white font-mono">{selectedRun.target}</h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedRun(null)}
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Latency</span>
                  <span className="font-mono text-sm font-bold text-sky-400">
                    {selectedRun.duration_ms.toFixed(1)} ms
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Target Type</span>
                  <span className="font-mono text-sm font-bold text-slate-200 uppercase">
                    {selectedRun.target_type}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block uppercase font-mono text-[10px]">Recorded At</span>
                  <span className="font-mono text-xs text-slate-300">
                    {new Date(selectedRun.created_at).toLocaleString()}
                  </span>
                </div>
              </div>

              {/* Executed Checks */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Executed Checks ({selectedRun.checks?.length || 0})
                </h4>
                <div className="space-y-2">
                  {selectedRun.checks?.map((chk, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-bold text-slate-200 uppercase">{chk.check_type}</span>
                        <StatusBadge status={chk.status} size="sm" />
                        {chk.error_message && <span className="text-rose-400 text-[11px]">{chk.error_message}</span>}
                      </div>
                      <span className="font-mono text-slate-400">{chk.duration_ms.toFixed(1)} ms</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Troubleshooting Findings */}
              {selectedRun.findings && selectedRun.findings.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Troubleshooting Findings ({selectedRun.findings.length})
                  </h4>
                  {selectedRun.findings.map((f, i) => (
                    <FindingCard key={i} finding={f} index={i} />
                  ))}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setSelectedRun(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
