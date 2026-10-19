import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  RotateCw,
  Upload,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Info,
  Terminal,
  HelpCircle,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '../services/api';
import { CloudAnalysisResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const SAMPLE_VULNERABLE = `{
  "Description": "Overly Permissive Ingress Security Group - Non-Compliant",
  "GroupName": "sg-vulnerable-database-and-bastion",
  "GroupId": "sg-01a2b3c4d5e6f7890",
  "VpcId": "vpc-0987654321fedcba0",
  "IpPermissions": [
    {
      "FromPort": 22,
      "ToPort": 22,
      "IpProtocol": "tcp",
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "Temporary admin access - forgot to remove"
        }
      ]
    },
    {
      "FromPort": 3389,
      "ToPort": 3389,
      "IpProtocol": "tcp",
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
    },
    {
      "FromPort": 3306,
      "ToPort": 3306,
      "IpProtocol": "tcp",
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
    },
    {
      "FromPort": 27017,
      "ToPort": 27017,
      "IpProtocol": "tcp",
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
    },
    {
      "IpProtocol": "-1",
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }],
      "Ipv6Ranges": [{ "CidrIpv6": "::/0" }]
    },
    {
      "FromPort": 1000,
      "ToPort": 3000,
      "IpProtocol": "tcp",
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
    }
  ],
  "IpPermissionsEgress": [
    {
      "IpProtocol": "-1",
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
    }
  ]
}`;

const SAMPLE_HARDENED = `{
  "Description": "Hardened Database Security Group - Least Privilege Compliant",
  "GroupName": "sg-hardened-db-cluster",
  "GroupId": "sg-09988776655443322",
  "VpcId": "vpc-0987654321fedcba0",
  "IpPermissions": [
    {
      "FromPort": 5432,
      "ToPort": 5432,
      "IpProtocol": "tcp",
      "IpRanges": [
        {
          "CidrIp": "10.0.10.0/24",
          "Description": "Authorized App-Tier Subnet A only"
        },
        {
          "CidrIp": "10.0.11.0/24",
          "Description": "Authorized App-Tier Subnet B only"
        }
      ]
    }
  ],
  "IpPermissionsEgress": []
}`;

const SAMPLE_WEB_DMZ = `{
  "Description": "Public Application Load Balancer Ingress Security Group",
  "GroupName": "sg-public-alb-dmz",
  "GroupId": "sg-04438080112233445",
  "VpcId": "vpc-0987654321fedcba0",
  "IpPermissions": [
    {
      "FromPort": 80,
      "ToPort": 80,
      "IpProtocol": "tcp",
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "Public HTTP Ingress (Redirected to HTTPS)"
        }
      ]
    },
    {
      "FromPort": 443,
      "ToPort": 443,
      "IpProtocol": "tcp",
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "Public HTTPS Secure Ingress"
        }
      ],
      "Ipv6Ranges": [
        {
          "CidrIpv6": "::/0",
          "Description": "Public IPv6 HTTPS Ingress"
        }
      ]
    }
  ],
  "IpPermissionsEgress": [
    {
      "FromPort": 8080,
      "ToPort": 8080,
      "IpProtocol": "tcp",
      "IpRanges": [
        {
          "CidrIp": "10.0.20.0/24",
          "Description": "Forwarding to internal target group ECS tasks"
        }
      ]
    }
  ]
}`;

export const CloudSecAnalyzer: React.FC = () => {
  const [configJson, setConfigJson] = useState(SAMPLE_VULNERABLE);
  const [analysisName, setAnalysisName] = useState('AWS Bastion & Database Analysis');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CloudAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!configJson.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.analyzeCloudConfig({
        name: analysisName.trim(),
        config_json: configJson.trim(),
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Verify JSON format.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    try {
      const data = await api.uploadCloudConfig(file);
      setResult(data);
      setAnalysisName(data.name);
      // Read file into textarea preview
      const reader = new FileReader();
      reader.onload = (e) => setConfigJson(e.target?.result as string);
      reader.readAsText(file);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze uploaded file.');
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (sample: string, name: string) => {
    setConfigJson(sample);
    setAnalysisName(name);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-sky-400" /> Cloud Security Configuration Analyzer
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Heuristic least-privilege analysis for AWS Security Groups, identifying open administrative ports, public
          database exposures, and overly broad CIDR ingress.
        </p>
      </div>

      {/* Input & Sample Selector */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold uppercase">Preloaded Samples:</span>
            <button
              type="button"
              onClick={() => loadSample(SAMPLE_VULNERABLE, 'Vulnerable Bastion & DB SG')}
              className="px-2.5 py-1 rounded bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800 text-rose-300 text-xs font-medium transition"
            >
              Overly Permissive Ingress
            </button>
            <button
              type="button"
              onClick={() => loadSample(SAMPLE_HARDENED, 'Hardened DB Cluster SG')}
              className="px-2.5 py-1 rounded bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-800 text-emerald-300 text-xs font-medium transition"
            >
              Hardened Private DB
            </button>
            <button
              type="button"
              onClick={() => loadSample(SAMPLE_WEB_DMZ, 'Public ALB DMZ SG')}
              className="px-2.5 py-1 rounded bg-sky-950/60 hover:bg-sky-900/80 border border-sky-800 text-sky-300 text-xs font-medium transition"
            >
              Public ALB Web DMZ
            </button>
          </div>

          <label className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium cursor-pointer flex items-center gap-1.5 transition border border-slate-700">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload JSON File</span>
            <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>

        <form onSubmit={handleAnalyze} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              Analysis Name
            </label>
            <input
              type="text"
              value={analysisName}
              onChange={(e) => setAnalysisName(e.target.value)}
              required
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:outline-none focus:border-sky-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              AWS Security Group JSON
            </label>
            <textarea
              rows={9}
              value={configJson}
              onChange={(e) => setConfigJson(e.target.value)}
              placeholder="Paste AWS DescribeSecurityGroups JSON here..."
              required
              className="w-full p-3.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs font-mono leading-relaxed focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              <span>{loading ? 'Evaluating Rules...' : 'Analyze Configuration'}</span>
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-sm flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">Validation Error</h4>
            <p className="text-xs text-rose-300/90 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
              <div>
                <span className="text-xs text-slate-400 font-medium">Evaluated Group:</span>
                <h3 className="text-lg font-bold text-white font-mono">{result.group_name}</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  ID: <span className="font-mono text-slate-300">{result.group_id || 'N/A'}</span> &bull; VPC:{' '}
                  <span className="font-mono text-slate-300">{result.vpc_id || 'N/A'}</span> &bull; Total Rules:{' '}
                  <span className="font-bold text-white">{result.total_rules_evaluated}</span>
                </p>
              </div>
            </div>

            {/* Severity Distribution Pills */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-3 border-t border-slate-800">
              <div className="p-2.5 rounded-lg bg-red-950/50 border border-red-800 text-center">
                <span className="text-[10px] uppercase font-bold text-red-400 block">Critical</span>
                <span className="font-mono text-xl font-bold text-red-200">{result.summary.CRITICAL}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-orange-950/50 border border-orange-800 text-center">
                <span className="text-[10px] uppercase font-bold text-orange-400 block">High</span>
                <span className="font-mono text-xl font-bold text-orange-200">{result.summary.HIGH}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-amber-950/50 border border-amber-800 text-center">
                <span className="text-[10px] uppercase font-bold text-amber-400 block">Medium</span>
                <span className="font-mono text-xl font-bold text-amber-200">{result.summary.MEDIUM}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-sky-950/50 border border-sky-800 text-center">
                <span className="text-[10px] uppercase font-bold text-sky-400 block">Low</span>
                <span className="font-mono text-xl font-bold text-sky-200">{result.summary.LOW}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-800/50 border border-slate-700 text-center">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">Info</span>
                <span className="font-mono text-xl font-bold text-slate-300">{result.summary.INFORMATIONAL}</span>
              </div>
            </div>
          </div>

          {/* Educational Note */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/70 text-xs text-slate-400 flex items-start gap-2.5">
            <HelpCircle className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-300 block font-medium mb-0.5">Static Evaluation Scope</strong>
              {result.educational_note}
            </div>
          </div>

          {/* Findings List */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
              Security Findings ({result.findings.length})
            </h3>

            {result.findings.length === 0 ? (
              <div className="p-6 rounded-xl border border-emerald-800/60 bg-emerald-950/30 text-emerald-300 text-sm flex items-center gap-3">
                <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                <div>
                  <h4 className="font-bold text-emerald-200">Least-Privilege Compliant</h4>
                  <p className="text-xs text-emerald-300/90 mt-0.5">
                    No unrestricted public administrative ports, public database ingress, or protocol wildcards were
                    identified in this configuration.
                  </p>
                </div>
              </div>
            ) : (
              result.findings.map((f, i) => (
                <div
                  key={i}
                  className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md space-y-3 hover:border-slate-700 transition"
                >
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <StatusBadge status={f.severity} size="sm" />
                      <h4 className="text-base font-bold text-slate-100">{f.title}</h4>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
                      <span>Port: {f.port_range || 'All'}</span>
                      <span>&bull;</span>
                      <span>CIDR: {f.cidr || 'N/A'}</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{f.risk_explanation}</p>

                  {/* Evidence Snippet */}
                  <div>
                    <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider block mb-1">
                      Rule Evidence (JSON)
                    </span>
                    <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                      {f.evidence}
                    </pre>
                  </div>

                  {/* Remediation */}
                  <div className="p-3 rounded-lg bg-sky-950/40 border border-sky-800/60 text-xs">
                    <strong className="text-sky-300 block font-semibold mb-1 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-sky-400" /> Recommended Remediation
                    </strong>
                    <p className="text-slate-300 leading-relaxed">{f.remediation}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};
