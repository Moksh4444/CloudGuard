import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color?: 'emerald' | 'rose' | 'amber' | 'sky' | 'indigo' | 'purple';
  trend?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'sky',
  trend,
}) => {
  const colorMap = {
    emerald: {
      bg: 'bg-emerald-950/40 border-emerald-800/40',
      iconText: 'text-emerald-400',
      valText: 'text-emerald-300',
    },
    rose: {
      bg: 'bg-rose-950/40 border-rose-800/40',
      iconText: 'text-rose-400',
      valText: 'text-rose-300',
    },
    amber: {
      bg: 'bg-amber-950/40 border-amber-800/40',
      iconText: 'text-amber-400',
      valText: 'text-amber-300',
    },
    sky: {
      bg: 'bg-sky-950/40 border-sky-800/40',
      iconText: 'text-sky-400',
      valText: 'text-sky-300',
    },
    indigo: {
      bg: 'bg-indigo-950/40 border-indigo-800/40',
      iconText: 'text-indigo-400',
      valText: 'text-indigo-300',
    },
    purple: {
      bg: 'bg-purple-950/40 border-purple-800/40',
      iconText: 'text-purple-400',
      valText: 'text-purple-300',
    },
  }[color];

  return (
    <div className={`p-4 rounded-xl border ${colorMap.bg} bg-slate-900/80 shadow-md backdrop-blur-sm transition-all hover:border-slate-600`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</span>
        <div className={`p-2 rounded-lg bg-slate-800/60 ${colorMap.iconText}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className={`text-2xl font-bold tracking-tight ${colorMap.valText}`}>{value}</span>
        {trend && <span className="text-xs text-slate-400">{trend}</span>}
      </div>
      {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
};
