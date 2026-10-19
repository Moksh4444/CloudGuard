import React, { useState } from 'react';
import { AlertCircle, ChevronDown, ChevronUp, Copy, Check, Terminal, HelpCircle } from 'lucide-react';
import { TroubleshootingFinding } from '../types';

interface FindingCardProps {
  finding: TroubleshootingFinding;
  index?: number;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const [expanded, setExpanded] = useState(true);
  const [copied, setCopied] = useState(false);

  const confidenceColors = {
    HIGH: 'text-emerald-400 bg-emerald-950/60 border-emerald-800',
    MEDIUM: 'text-amber-400 bg-amber-950/60 border-amber-800',
    TENTATIVE: 'text-slate-400 bg-slate-900 border-slate-700',
  }[finding.confidence] || 'text-slate-400 bg-slate-900 border-slate-700';

  const handleCopy = () => {
    const text = `Symptom: ${finding.symptom}\nEvidence: ${finding.diagnostic_evidence}\nLikely Explanations:\n${finding.likely_explanations.map((e) => `- ${e}`).join('\n')}\nNext Steps:\n${finding.next_steps.map((s) => `- ${s}`).join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-slate-700/80 bg-slate-900/90 shadow-md overflow-hidden transition-all hover:border-slate-600">
      <div
        className="p-4 flex items-start justify-between cursor-pointer select-none bg-slate-850/50"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-md bg-amber-950/40 border border-amber-800/40 text-amber-400 mt-0.5">
            <AlertCircle className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Finding {index !== undefined ? `#${index + 1}` : ''}
              </span>
              <span className={`text-[11px] px-2 py-0.5 rounded border uppercase font-medium ${confidenceColors}`}>
                Confidence: {finding.confidence}
              </span>
            </div>
            <h4 className="text-base font-semibold text-slate-100">{finding.symptom}</h4>
          </div>
        </div>
        <div className="flex items-center gap-2 text-slate-400">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              handleCopy();
            }}
            title="Copy Finding Details"
            className="p-1.5 hover:text-slate-200 hover:bg-slate-800 rounded transition"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          </button>
          <div className="p-1.5 hover:text-slate-200">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="p-4 pt-2 border-t border-slate-800 space-y-4 text-sm">
          {/* Diagnostic Evidence */}
          <div>
            <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center gap-1.5 mb-1.5">
              <Terminal className="w-3.5 h-3.5 text-sky-400" /> Diagnostic Evidence
            </span>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
              {finding.diagnostic_evidence}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Likely Explanations */}
            <div>
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider block mb-1.5">
                Likely Explanations
              </span>
              <ul className="space-y-1.5 list-disc list-inside text-slate-300 text-xs leading-relaxed">
                {finding.likely_explanations.map((exp, i) => (
                  <li key={i} className="text-slate-300">
                    <span className="text-slate-300">{exp}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Recommended Next Steps */}
            <div>
              <span className="text-xs font-semibold uppercase text-sky-400 tracking-wider block mb-1.5">
                Recommended Actionable Next Steps
              </span>
              <ul className="space-y-1.5 text-xs">
                {finding.next_steps.map((step, i) => (
                  <li
                    key={i}
                    className="p-1.5 rounded bg-slate-800/80 border border-slate-700/60 font-mono text-sky-300 break-all"
                  >
                    {step}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Boundaries & Limitations */}
          {finding.limitations && (
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 text-xs text-slate-400 flex items-start gap-2">
              <HelpCircle className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
              <span>
                <strong className="text-slate-300 font-medium">Diagnostic Boundary:</strong>{' '}
                {finding.limitations}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
