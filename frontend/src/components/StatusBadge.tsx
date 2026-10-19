import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, ShieldAlert } from 'lucide-react';
import { CheckStatus, SeverityLevel } from '../types';

interface StatusBadgeProps {
  status: CheckStatus | SeverityLevel | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  size = 'md',
  showIcon = true,
}) => {
  const norm = status?.toUpperCase() || 'UNKNOWN';

  let bg = 'bg-slate-800 text-slate-300 border-slate-700';
  let Icon = Info;

  switch (norm) {
    case 'SUCCESS':
    case 'HEALTHY':
    case 'PASSED':
      bg = 'bg-emerald-950/70 text-emerald-300 border-emerald-700/60';
      Icon = CheckCircle2;
      break;
    case 'WARNING':
    case 'MEDIUM':
      bg = 'bg-amber-950/70 text-amber-300 border-amber-700/60';
      Icon = AlertTriangle;
      break;
    case 'FAILURE':
    case 'ERROR':
    case 'FAILED':
      bg = 'bg-rose-950/70 text-rose-300 border-rose-700/60';
      Icon = XCircle;
      break;
    case 'CRITICAL':
      bg = 'bg-red-950/90 text-red-200 border-red-600 animate-pulse font-bold';
      Icon = ShieldAlert;
      break;
    case 'HIGH':
      bg = 'bg-orange-950/80 text-orange-300 border-orange-600/70';
      Icon = AlertTriangle;
      break;
    case 'LOW':
      bg = 'bg-sky-950/70 text-sky-300 border-sky-700/60';
      Icon = Info;
      break;
    case 'INFORMATIONAL':
      bg = 'bg-slate-800/80 text-slate-300 border-slate-600';
      Icon = Info;
      break;
  }

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-medium',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-md border font-medium uppercase tracking-wider ${bg} ${sizeClasses}`}
    >
      {showIcon && <Icon className={size === 'sm' ? 'w-3 h-3' : size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />}
      {norm}
    </span>
  );
};
