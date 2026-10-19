import React, { useEffect, useState } from 'react';
import {
  Sliders,
  Shield,
  Server,
  Database,
  Lock,
  Network,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Info,
  ExternalLink,
  HelpCircle,
  FileText,
} from 'lucide-react';
import { api } from '../services/api';
import { SystemHealth } from '../types';

export const SettingsAbout: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadHealth();
  }, []);

  const loadHealth = async () => {
    setLoading(true);
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Sliders className="w-5 h-5 text-sky-400" /> Platform Settings & Portfolio Architecture
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Operational boundaries, active security policies, runtime environment diagnostics, and portfolio engineering
          documentation.
        </p>
      </div>

      {/* Runtime Environment & Health */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <Server className="w-4 h-4 text-sky-400" /> System Runtime & Security Boundaries
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block uppercase text-[10px]">Backend Status</span>
            <span
              className={`font-bold flex items-center gap-1.5 mt-0.5 ${
                health?.status === 'HEALTHY' ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              {health?.status || 'Connecting...'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block uppercase text-[10px]">SSRF Protection Policy</span>
            <span className="font-bold text-emerald-400 flex items-center gap-1.5 mt-0.5">
              <Shield className="w-3.5 h-3.5" /> Strict (Private/Loopback Blocked)
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block uppercase text-[10px]">Persistence Store</span>
            <span className="font-bold text-slate-200 flex items-center gap-1.5 mt-0.5">
              <Database className="w-3.5 h-3.5 text-sky-400" /> SQLite (SQLAlchemy ORM)
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block uppercase text-[10px]">Route Diagnostics</span>
            <span className="font-bold text-sky-300 flex items-center gap-1.5 mt-0.5">
              <Network className="w-3.5 h-3.5" />
              {health?.traceroute_supported ? 'Tracert Available' : 'Not Detected in PATH'}
            </span>
          </div>
        </div>

        {health && (
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 font-mono space-y-1">
            <div>
              <strong className="text-slate-300">OS Platform:</strong> {health.platform}
            </div>
            <div>
              <strong className="text-slate-300">Python Runtime:</strong> Python {health.python_version} &bull; CloudGuard
              Engine v{health.version}
            </div>
            <div>
              <strong className="text-slate-300">Approved Port Diagnostic Boundary:</strong>{' '}
              {health.allowed_ports_count} validated ports (arbitrary port range scanning strictly disallowed)
            </div>
          </div>
        )}
      </div>

      {/* Portfolio & Cloud Security Alignment Context */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-4">
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <Shield className="w-5 h-5 text-sky-400" /> Associate Technical Consultant Portfolio Context
        </h3>

        <p className="text-xs text-slate-300 leading-relaxed">
          CloudGuard was developed as an educational and technical portfolio demonstration for an{' '}
          <strong>Associate Technical Consultant</strong> position at enterprise cloud security leaders such as{' '}
          <strong>Skyhigh Security</strong>, <strong>Netskope</strong>, <strong>Zscaler</strong>, and{' '}
          <strong>Cloudflare</strong>.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 text-xs">
            <div className="font-bold text-sky-300 mb-1 flex items-center gap-1.5">
              <Network className="w-4 h-4 text-sky-400" /> Network & ZTNA Triage
            </div>
            <p className="text-slate-400 leading-relaxed">
              Differentiates TCP socket RST (connection refused) vs packet drops (timeout/firewall rules), resolving DNS
              anomalies without inventing root causes.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 text-xs">
            <div className="font-bold text-emerald-300 mb-1 flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-emerald-400" /> TLS & Secure Web Gateway
            </div>
            <p className="text-slate-400 leading-relaxed">
              Validates certificate expiration windows, Subject Alternative Names (SAN), and HTTP redirection loops
              while enforcing strict per-hop SSRF validation.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 text-xs">
            <div className="font-bold text-purple-300 mb-1 flex items-center gap-1.5">
              <Server className="w-4 h-4 text-purple-400" /> CSPM Least-Privilege
            </div>
            <p className="text-slate-400 leading-relaxed">
              Identifies over-permissive AWS Security Group rules (SSH 22, RDP 3389, DB 3306 open to 0.0.0.0/0) with
              clear severity tiers and remediation guidance.
            </p>
          </div>
        </div>
      </div>

      {/* Security Architecture & Responsible Use Statement */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-sky-400" /> Responsible-Use & Security Architecture Statement
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          CloudGuard is built from the ground up with defensive security principles:
        </p>
        <ul className="list-disc list-inside space-y-1 text-xs text-slate-300 leading-relaxed">
          <li>
            <strong>SSRF Mitigation:</strong> All targets are validated prior to socket binding. Access to loopback
            (127.0.0.1/8, ::1), RFC1918 private subnets, and AWS Instance Metadata Service (169.254.169.254) is
            strictly prohibited by default.
          </li>
          <li>
            <strong>No Unrestricted Port Scanning:</strong> TCP connectivity tests are restricted to approved service
            ports or validated single ports to prevent weaponization.
          </li>
          <li>
            <strong>Safe Subprocess Execution:</strong> Route path utilities (tracert/traceroute) use explicit argument
            vectors without shell invocation (shell=False) and strict hop/timeout limits.
          </li>
          <li>
            <strong>Data Minimization:</strong> URL query parameters, authorization headers, and cookie jars are
            redacted from application audit logs and report exports.
          </li>
        </ul>
      </div>
    </div>
  );
};
