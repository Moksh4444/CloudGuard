import React, { useEffect, useState } from 'react';
import {
  Shield,
  Database,
  ExternalLink,
  Sparkles,
  RefreshCw,
  CheckCircle2,
  Menu,
} from 'lucide-react';
import { api } from '../services/api';
import { SystemHealth } from '../types';

interface NavbarProps {
  onDataChanged?: () => void;
  onToggleMobileMenu?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onDataChanged, onToggleMobileMenu }) => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedNotice, setSeedNotice] = useState<string | null>(null);

  useEffect(() => {
    checkHealth();
  }, []);

  const checkHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch {
      setHealth(null);
    }
  };

  const handleSeed = async () => {
    setSeeding(true);
    setSeedNotice(null);
    try {
      const res = await api.seedDemoData();
      setSeedNotice(`Seeded ${res.runs_seeded} educational runs.`);
      if (onDataChanged) onDataChanged();
      setTimeout(() => setSeedNotice(null), 4000);
    } catch (err: any) {
      setSeedNotice(`Seed failed: ${err.message}`);
    } finally {
      setSeeding(false);
    }
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/95 backdrop-blur px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        {/* Mobile Hamburger Menu Toggle */}
        <button
          type="button"
          onClick={onToggleMobileMenu}
          className="md:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          title="Open Navigation Menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-white">CloudGuard</h1>
            <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
              v1.0 &bull; Enterprise
            </span>
          </div>
          <p className="text-xs text-slate-400 hidden sm:block">
            Cloud Security & Network Troubleshooting Platform
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2.5 sm:gap-3">
        {/* Seed Demo Data Button */}
        <button
          type="button"
          onClick={handleSeed}
          disabled={seeding}
          className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-medium bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white shadow-sm transition disabled:opacity-50"
          title="Seed realistic educational test scenarios and security group findings"
        >
          {seeding ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Sparkles className="w-3.5 h-3.5 text-amber-300" />
          )}
          <span className="hidden xs:inline">{seeding ? 'Seeding...' : 'Load Demo Scenarios'}</span>
          <span className="xs:hidden">{seeding ? '...' : 'Demo'}</span>
        </button>

        {seedNotice && (
          <span className="hidden lg:flex text-xs text-emerald-400 bg-emerald-950/80 border border-emerald-800 px-2.5 py-1 rounded-md items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> {seedNotice}
          </span>
        )}

        {/* System Health Pill */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full border border-slate-800 bg-slate-950/70 text-xs text-slate-400">
          <span
            className={`w-2 h-2 rounded-full ${
              health?.status === 'HEALTHY' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'
            }`}
          />
          <span>{health?.status === 'HEALTHY' ? 'Backend Live' : 'Backend Offline'}</span>
          {health?.database_connected && (
            <span className="text-slate-500 flex items-center gap-1">
              &bull; <Database className="w-3 h-3 text-slate-400" /> SQLite
            </span>
          )}
        </div>

        {/* API Docs Link */}
        <a
          href="/api/v1/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="p-2 text-slate-400 hover:text-sky-400 hover:bg-slate-800 rounded-lg transition"
          title="FastAPI Swagger OpenAPI Docs"
        >
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>
    </header>
  );
};
