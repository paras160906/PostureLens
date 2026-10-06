import React, { useEffect, useState } from 'react';
import { fetchScans } from '../api';
import SeverityBadge from '../components/SeverityBadge';
import RadialScoreGauge from '../components/RadialScoreGauge';

export default function DashboardView({ onSelectScan, onNewScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchScans();
      setScans(data);
    } catch (err) {
      setError(err.message || 'Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const totalScans = scans.length;
  const avgScore = totalScans > 0
    ? Math.round(scans.reduce((acc, s) => acc + s.risk_score, 0) / totalScans)
    : 0;

  const criticalCount = scans.filter(s => s.risk_level === 'CRITICAL').length;
  const highCount = scans.filter(s => s.risk_level === 'HIGH').length;
  const medCount = scans.filter(s => s.risk_level === 'MEDIUM').length;
  const lowCount = scans.filter(s => s.risk_level === 'LOW' || s.risk_level === 'CLEAN').length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans text-[#EDEDED]">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-[#EDEDED] tracking-tight font-sans">Dashboard Overview</h2>
          <p className="text-sm text-[#A3A3A3] mt-1 font-sans">
            Security posture metrics across scanned Dockerfiles and Kubernetes manifests.
          </p>
        </div>
        <button
          onClick={onNewScan}
          className="bg-[#EDEDED] text-[#0A0A0A] font-sans text-xs font-bold px-4 py-2.5 rounded flex items-center gap-2 hover:bg-[#FFFFFF] transition-all cursor-pointer self-start sm:self-auto shadow-sm"
        >
          <span className="material-symbols-outlined text-base">security_update_good</span>
          Initialize New Scan
        </button>
      </div>

      {/* Asymmetrical Metrics Grid */}
      <div className="grid grid-cols-12 gap-6">
        {/* HERO Risk Panel (5 columns) */}
        <div className="col-span-12 lg:col-span-5 bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col justify-between">
          <div className="flex justify-between items-start mb-3">
            <div>
              <span className="text-xs font-bold text-[#A3A3A3] uppercase tracking-wider font-sans">
                Average Portfolio Risk Score
              </span>
              <div className="text-xs text-[#737373] mt-0.5 font-sans">Across {totalScans} audit reports</div>
            </div>
          </div>

          <div className="flex items-center justify-between py-2 my-auto">
            <div>
              <div className="text-5xl font-bold font-sans text-[#EDEDED] tracking-tight">
                {avgScore}
                <span className="text-base font-normal text-[#737373] font-mono ml-1">/100</span>
              </div>
              <div className="text-xs font-sans text-[#A3A3A3] mt-2">
                {avgScore > 50 ? 'High risk baseline.' : 'Stable portfolio posture.'}
              </div>
            </div>

            {/* Functional Radial Gauge */}
            <RadialScoreGauge score={avgScore} size={96} />
          </div>

          <div className="pt-3 border-t border-[#262626] flex items-center justify-between text-xs text-[#737373] font-mono">
            <span>Evaluator: PostureLens Engine</span>
            <span>Total Scans: {totalScans}</span>
          </div>
        </div>

        {/* Secondary Stat Cards (7 columns) */}
        <div className="col-span-12 lg:col-span-7 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Total Audits */}
          <div className="bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-bold text-[#A3A3A3] uppercase tracking-wider font-sans">
                Total Audit Scans
              </span>
              <span className="material-symbols-outlined text-[#EDEDED] text-xl">analytics</span>
            </div>
            <div className="flex items-end justify-between">
              <span className="text-4xl font-bold font-sans text-[#EDEDED]">{totalScans}</span>
              <span className="font-sans text-xs text-[#A3A3A3] flex items-center mb-1">
                <span className="material-symbols-outlined text-xs mr-1 text-[#10B981]">trending_up</span>
                Active History
              </span>
            </div>
          </div>

          {/* Severity Counts */}
          <div className="bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col justify-between">
            <span className="text-xs font-bold text-[#A3A3A3] uppercase tracking-wider font-sans mb-3">
              Scan Severity Breakdown
            </span>
            <div className="grid grid-cols-2 gap-2.5 font-mono text-xs flex-1">
              <div className="bg-[#271113] p-2.5 rounded border border-[#7F1D1D] flex justify-between items-center">
                <span className="text-[#EF4444] font-bold">CRIT</span>
                <span className="text-[#EF4444] font-bold">{criticalCount}</span>
              </div>
              <div className="bg-[#24140D] p-2.5 rounded border border-[#7C2D12] flex justify-between items-center">
                <span className="text-[#F97316] font-bold">HIGH</span>
                <span className="text-[#F97316] font-bold">{highCount}</span>
              </div>
              <div className="bg-[#211D0E] p-2.5 rounded border border-[#713F12] flex justify-between items-center">
                <span className="text-[#EAB308] font-semibold">MED</span>
                <span className="text-[#EAB308] font-semibold">{medCount}</span>
              </div>
              <div className="bg-[#0A2118] p-2.5 rounded border border-[#065F46] flex justify-between items-center">
                <span className="text-[#10B981] font-semibold">LOW</span>
                <span className="text-[#10B981] font-semibold">{lowCount}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-[#121212] rounded-xl border border-[#262626] overflow-hidden">
        <div className="p-5 border-b border-[#262626] flex items-center justify-between">
          <h3 className="text-base font-bold text-[#EDEDED] font-sans flex items-center gap-2">
            <span className="material-symbols-outlined text-[#EDEDED] text-xl">history</span>
            Recent Audit Reports
          </h3>
          <button
            onClick={loadData}
            className="text-[#A3A3A3] hover:text-[#EDEDED] font-sans text-xs hover:underline flex items-center gap-1 cursor-pointer"
          >
            <span className="material-symbols-outlined text-sm">refresh</span>
            Refresh History
          </button>
        </div>

        {loading ? (
          <div className="p-12 text-center font-sans text-sm text-[#A3A3A3] flex flex-col items-center gap-3">
            <span className="material-symbols-outlined text-3xl animate-spin text-[#EDEDED]">progress_activity</span>
            <span className="font-mono text-xs text-[#737373]">Loading audit history...</span>
          </div>
        ) : error ? (
          <div className="p-8 text-center font-sans text-sm text-[#EF4444] bg-[#271113] m-4 rounded border border-[#7F1D1D]">
            {error}
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center font-sans text-sm text-[#A3A3A3]">
            No security scans performed yet. Click "Initialize New Scan" to run your first audit.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse font-sans text-sm">
              <thead>
                <tr className="bg-[#0A0A0A] border-b border-[#262626] text-xs font-semibold text-[#A3A3A3] uppercase tracking-wider font-sans">
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">File Name</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Severity Rating</th>
                  <th className="py-3 px-4">Violations</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#262626]">
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className="hover:bg-[#171717] transition-colors cursor-pointer"
                  >
                    <td className="py-3.5 px-4 font-mono text-xs text-[#EDEDED] font-bold">
                      #{scan.id}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-[#EDEDED] font-semibold">
                      {scan.filename}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded bg-[#0A0A0A] border border-[#262626] text-[#A3A3A3] uppercase">
                        {scan.file_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-[#EDEDED] text-sm">
                      {scan.risk_score} <span className="text-xs text-[#737373]">/ 100</span>
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={scan.risk_level} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-[#A3A3A3]">
                      {scan.total_violations} rules flagged
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectScan(scan.id);
                        }}
                        className="text-[#EDEDED] font-sans font-semibold text-xs hover:underline inline-flex items-center gap-1"
                      >
                        View Details
                        <span className="material-symbols-outlined text-xs">arrow_forward</span>
                      </button>
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
}
