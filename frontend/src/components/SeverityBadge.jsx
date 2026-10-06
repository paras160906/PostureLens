import React from 'react';

export default function SeverityBadge({ severity }) {
  const sev = (severity || 'low').toLowerCase();

  switch (sev) {
    case 'critical':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#271113] text-[#EF4444] border border-[#7F1D1D] font-mono text-[11px] font-bold tracking-wider uppercase">
          <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-ping shrink-0" />
          CRITICAL
        </span>
      );
    case 'high':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#24140D] text-[#F97316] border border-[#7C2D12] font-mono text-[11px] font-bold tracking-wider uppercase">
          <span className="w-1.5 h-1.5 rounded-full bg-[#F97316] shrink-0" />
          HIGH
        </span>
      );
    case 'medium':
      return (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#211D0E] text-[#EAB308] border border-[#713F12] font-mono text-[11px] font-semibold tracking-wider uppercase">
          <span className="w-1.5 h-1.5 rounded-full bg-[#EAB308] shrink-0" />
          MEDIUM
        </span>
      );
    case 'clean':
    case 'low':
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#0A2118] text-[#10B981] border border-[#065F46] font-mono text-[11px] font-semibold tracking-wider uppercase">
          <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] shrink-0" />
          {sev === 'clean' ? 'CLEAN' : 'LOW'}
        </span>
      );
  }
}
