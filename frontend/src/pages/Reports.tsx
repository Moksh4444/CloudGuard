import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  RotateCw,
  ExternalLink,
  Search,
  CheckCircle2,
  Calendar,
  FileCode,
  FileSpreadsheet,
  Printer,
} from 'lucide-react';
import { api } from '../services/api';
import { DiagnosticRun } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';

export const Reports: React.FC = () => {
  const [runs, setRuns] = useState<DiagnosticRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string>('');
  const [exportFormat, setExportFormat] = useState<'json' | 'csv' | 'html'>('html');
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [generatedReports, setGeneratedReports] = useState<any[]>([]);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    try {
      const [runsData, reportsData] = await Promise.all([
        api.listHistoryRuns(1, 20),
        api.listReports(),
      ]);
      setRuns(runsData.items);
      if (runsData.items.length > 0) {
        setSelectedRunId(runsData.items[0].id);
      }
      setGeneratedReports(reportsData);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async () => {
    if (!selectedRunId) return;

    setExporting(true);
    setExportNotice(null);
    try {
      const data = await api.exportReport(selectedRunId, exportFormat);

      if (exportFormat === 'html') {
        setPreviewHtml(data.content);
      }

      // Trigger browser download
      const blob = new Blob([data.content], {
        type:
          exportFormat === 'json'
            ? 'application/json'
            : exportFormat === 'csv'
            ? 'text/csv'
            : 'text/html',
      });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = data.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);

      setExportNotice(`Generated report ${data.report_uid} (${data.filename})`);
      // Reload reports list
      const refreshedReports = await api.listReports();
      setGeneratedReports(refreshedReports);
    } catch (err: any) {
      setExportNotice(`Export failed: ${err.message}`);
    } finally {
      setExporting(false);
    }
  };

  const handleOpenPrint = () => {
    if (!previewHtml) return;
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(previewHtml);
      printWindow.document.close();
      printWindow.focus();
      printWindow.print();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <FileText className="w-5 h-5 text-sky-400" /> Executive Troubleshooting Reports
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Export structured diagnostic sessions into standardized formats: JSON telemetry, CSV audit tables, and
          printable executive HTML reports.
        </p>
      </div>

      {/* Generator Controls */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              Select Diagnostic Session to Report
            </label>
            {runs.length === 0 ? (
              <p className="text-xs text-slate-500 py-2">
                No diagnostic sessions saved yet. Run a diagnostic check first.
              </p>
            ) : (
              <select
                value={selectedRunId}
                onChange={(e) => setSelectedRunId(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:outline-none focus:border-sky-500"
              >
                {runs.map((r) => (
                  <option key={r.id} value={r.id}>
                    [{r.status}] {r.target} ({r.duration_ms.toFixed(0)}ms) &bull;{' '}
                    {new Date(r.created_at).toLocaleString()}
                  </option>
                ))}
              </select>
            )}
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              Export Format
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setExportFormat('html')}
                className={`py-2 px-3 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition ${
                  exportFormat === 'html'
                    ? 'bg-sky-600 text-white border-sky-500 shadow-sm'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                <FileText className="w-3.5 h-3.5" /> HTML
              </button>
              <button
                type="button"
                onClick={() => setExportFormat('json')}
                className={`py-2 px-3 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition ${
                  exportFormat === 'json'
                    ? 'bg-sky-600 text-white border-sky-500 shadow-sm'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" /> JSON
              </button>
              <button
                type="button"
                onClick={() => setExportFormat('csv')}
                className={`py-2 px-3 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition ${
                  exportFormat === 'csv'
                    ? 'bg-sky-600 text-white border-sky-500 shadow-sm'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                <FileSpreadsheet className="w-3.5 h-3.5" /> CSV
              </button>
            </div>
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-400">
            Reports strictly redact sensitive URL queries, cookies, and authentication headers.
          </span>
          <button
            type="button"
            onClick={handleExport}
            disabled={exporting || !selectedRunId}
            className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50 flex items-center gap-2"
          >
            {exporting ? <RotateCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            <span>{exporting ? 'Generating...' : `Export ${exportFormat.toUpperCase()} Report`}</span>
          </button>
        </div>
      </div>

      {exportNotice && (
        <div className="p-3 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{exportNotice}</span>
        </div>
      )}

      {/* HTML Report Live Preview */}
      {previewHtml && (
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
              Interactive HTML Report Preview
            </h3>
            <button
              type="button"
              onClick={handleOpenPrint}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition border border-slate-700"
            >
              <Printer className="w-3.5 h-3.5 text-sky-400" />
              <span>Print / Save as PDF</span>
            </button>
          </div>
          <div className="rounded-lg overflow-hidden border border-slate-800 bg-slate-950">
            <iframe
              srcDoc={previewHtml}
              title="Report Preview"
              className="w-full h-[450px] border-none"
            />
          </div>
        </div>
      )}

      {/* Generated Reports Table */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
          Previously Generated Reports
        </h3>

        {generatedReports.length === 0 ? (
          <p className="text-xs text-slate-500 py-2">No exported reports generated yet.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Report UID</th>
                  <th className="py-2.5 px-4">Title</th>
                  <th className="py-2.5 px-4">Scope</th>
                  <th className="py-2.5 px-4">Format</th>
                  <th className="py-2.5 px-4">Generated At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {generatedReports.map((r, i) => (
                  <tr key={i} className="hover:bg-slate-800/30 transition">
                    <td className="py-2 px-4 text-sky-400 font-bold">{r.report_uid}</td>
                    <td className="py-2 px-4 text-slate-300">{r.title}</td>
                    <td className="py-2 px-4 text-slate-400">{r.scope}</td>
                    <td className="py-2 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                        {r.format}
                      </span>
                    </td>
                    <td className="py-2 px-4 text-slate-400 text-[11px]">
                      {new Date(r.generated_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
