import React, { useEffect, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ShieldAlert,
  Search,
  Sparkles,
  ArrowRight,
  TrendingUp,
  Calendar,
  PieChart as PieIcon,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { api } from '../services/api';
import { AnalyticsOverviewResponse, DiagnosticRun } from '../types';
import { MetricCard } from '../components/MetricCard';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';

interface OverviewProps {
  onNavigate: (page: any) => void;
  refreshTrigger: number;
}

type DateRangeOption = 'all' | '24h' | '7d' | '30d';

const PIE_COLORS = ['#38bdf8', '#f59e0b', '#ef4444', '#a855f7', '#10b981', '#6366f1'];

export const Overview: React.FC<OverviewProps> = ({ onNavigate, refreshTrigger }) => {
  const [analytics, setAnalytics] = useState<AnalyticsOverviewResponse | null>(null);
  const [recentRuns, setRecentRuns] = useState<DiagnosticRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [dateRange, setDateRange] = useState<DateRangeOption>('all');

  const getDateRangeParams = (range: DateRangeOption): { startDate?: string; endDate?: string } => {
    const now = new Date();
    if (range === '24h') {
      return { startDate: new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString() };
    }
    if (range === '7d') {
      return { startDate: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString() };
    }
    if (range === '30d') {
      return { startDate: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString() };
    }
    return {};
  };

  useEffect(() => {
    loadData(dateRange);
  }, [refreshTrigger]);

  const loadData = async (range: DateRangeOption = dateRange) => {
    setLoading(true);
    try {
      const { startDate, endDate } = getDateRangeParams(range);
      const [overviewData, historyData] = await Promise.all([
        api.getAnalyticsOverview(startDate, endDate),
        api.listHistoryRuns(1, 5),
      ]);
      setAnalytics(overviewData);
      setRecentRuns(historyData.items);
    } catch (err) {
      console.error('Failed to load overview data', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRangeChange = (newRange: DateRangeOption) => {
    setDateRange(newRange);
    loadData(newRange);
  };

  const handleSeed = async () => {
    try {
      await api.seedDemoData();
      await loadData();
    } catch (e) {
      console.error(e);
    }
  };

  if (loading && !analytics) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-sky-400" />
      </div>
    );
  }

  const hasData = analytics && analytics.total_runs > 0;

  // Format HTTP distribution for BarChart
  const httpChartData = analytics?.http_status_distribution
    ? Object.entries(analytics.http_status_distribution).map(([status, count]) => ({
        status,
        count,
      }))
    : [];

  // Format Module Failures for PieChart
  const moduleFailureData = analytics?.failure_by_module
    ? Object.entries(analytics.failure_by_module).map(([module, count]) => ({
        module,
        count,
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* Top Banner with Date-Range Selector */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 rounded-xl bg-gradient-to-r from-slate-900 via-slate-850 to-navy-900 border border-slate-800 shadow-md">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Security & Diagnostic Operations</h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Real-time telemetry and aggregated diagnostic intelligence across network endpoints and cloud configs.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {/* Date-Range Selector */}
          <div className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-lg border border-slate-800 text-xs">
            <Calendar className="w-3.5 h-3.5 text-slate-400 ml-1.5 mr-0.5" />
            {(['all', '24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => handleRangeChange(range)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                  dateRange === range
                    ? 'bg-sky-600 text-white shadow-sm font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {range === 'all'
                  ? 'All Time'
                  : range === '24h'
                  ? 'Last 24h'
                  : range === '7d'
                  ? 'Last 7d'
                  : 'Last 30d'}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => onNavigate('network')}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow transition flex items-center gap-1.5 shrink-0"
          >
            <span>Run Diagnostic</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {!hasData ? (
        <EmptyState
          icon={Activity}
          title="No Diagnostic History Recorded"
          description="CloudGuard calculates all dashboard metrics, distributions, and trends from real diagnostic executions. Run a network check or load the educational demo dataset."
          actionText="Load Educational Demo Dataset"
          onAction={handleSeed}
        />
      ) : (
        <>
          {/* Executive Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <MetricCard
              title="Total Runs"
              value={analytics.total_runs}
              subtitle="Diagnostic sessions"
              icon={Activity}
              color="sky"
            />
            <MetricCard
              title="Successful"
              value={analytics.successful_runs}
              subtitle={`${Math.round((analytics.successful_runs / analytics.total_runs) * 100)}% pass rate`}
              icon={CheckCircle2}
              color="emerald"
            />
            <MetricCard
              title="Failed / Errors"
              value={analytics.failed_runs}
              subtitle="Requires triage"
              icon={XCircle}
              color="rose"
            />
            <MetricCard
              title="Avg Latency"
              value={`${analytics.avg_response_time_ms}ms`}
              subtitle={`Median: ${analytics.median_response_time_ms}ms`}
              icon={Clock}
              color="indigo"
            />
            <MetricCard
              title="DNS Failures"
              value={analytics.dns_failure_count}
              subtitle="NXDOMAIN / Timeouts"
              icon={Search}
              color="amber"
            />
            <MetricCard
              title="Cloud Critical"
              value={analytics.cloud_severity_distribution.CRITICAL || 0}
              subtitle="AWS Security Group risks"
              icon={ShieldAlert}
              color="purple"
            />
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Runs Over Time Area Chart */}
            <div className="lg:col-span-2 p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    Diagnostic Activity Trend
                  </h3>
                  <p className="text-xs text-slate-400">Total diagnostic runs recorded by day</p>
                </div>
                <TrendingUp className="w-4 h-4 text-sky-400" />
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={analytics.runs_over_time}>
                    <defs>
                      <linearGradient id="runsGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                      itemStyle={{ color: '#38bdf8' }}
                    />
                    <Area
                      type="monotone"
                      dataKey="runs"
                      stroke="#38bdf8"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#runsGradient)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* HTTP Status Code Distribution */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-1">
                HTTP Status Distribution
              </h3>
              <p className="text-xs text-slate-400 mb-4">Response codes captured during HTTP checks</p>
              <div className="h-64">
                {httpChartData.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    No HTTP check data yet
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={httpChartData}>
                      <XAxis dataKey="status" stroke="#64748b" fontSize={10} />
                      <YAxis stroke="#64748b" fontSize={10} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                      />
                      <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]}>
                        {httpChartData.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={
                              entry.status.startsWith('2')
                                ? '#10b981'
                                : entry.status.startsWith('3')
                                ? '#38bdf8'
                                : entry.status.startsWith('4')
                                ? '#f59e0b'
                                : '#ef4444'
                            }
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
          </div>

          {/* Module Failures, Top Symptoms & Recent Activity */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Failures by Diagnostic Module */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Failures by Module
                </h3>
                <PieIcon className="w-4 h-4 text-sky-400" />
              </div>
              <p className="text-xs text-slate-400 mb-3">
                Distribution across diagnostic engines
              </p>
              <div className="h-64">
                {moduleFailureData.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    No module failures recorded
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={moduleFailureData}
                        dataKey="count"
                        nameKey="module"
                        cx="50%"
                        cy="45%"
                        outerRadius={75}
                        innerRadius={40}
                        paddingAngle={4}
                      >
                        {moduleFailureData.map((_, index) => (
                          <Cell
                            key={`slice-${index}`}
                            fill={PIE_COLORS[index % PIE_COLORS.length]}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                        }}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={36}
                        formatter={(val) => <span className="text-[11px] text-slate-300">{val}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Most Frequently Observed Issues */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Top Troubleshooting Symptoms
              </h3>
              <p className="text-xs text-slate-400 mb-3">
                Classified by Troubleshooting Engine
              </p>
              <div className="space-y-2.5">
                {analytics.most_frequent_issues.length === 0 ? (
                  <p className="text-xs text-slate-500">No failure findings logged.</p>
                ) : (
                  analytics.most_frequent_issues.map((item, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-850/80 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center gap-2.5 text-slate-300">
                        <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center font-mono font-bold text-[10px]">
                          {idx + 1}
                        </span>
                        <span className="font-medium line-clamp-1">{item.symptom}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono font-bold shrink-0">
                        {item.count} {item.count === 1 ? 'event' : 'events'}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent Diagnostic Activity Table */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    Recent Diagnostic Runs
                  </h3>
                  <p className="text-xs text-slate-400">Latest executed investigations</p>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate('history')}
                  className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1"
                >
                  View all <ArrowRight className="w-3 h-3" />
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2">Target</th>
                      <th className="py-2">Status</th>
                      <th className="py-2">Latency</th>
                      <th className="py-2">Checks</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {recentRuns.map((run) => (
                      <tr key={run.id} className="hover:bg-slate-850/50 transition">
                        <td className="py-2.5 font-mono text-slate-200 max-w-[140px] truncate" title={run.target}>
                          {run.target}
                        </td>
                        <td className="py-2.5">
                          <StatusBadge status={run.status} size="sm" />
                        </td>
                        <td className="py-2.5 font-mono text-slate-400">{run.duration_ms.toFixed(1)}ms</td>
                        <td className="py-2.5 text-slate-400">{run.checks_count || 1}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
