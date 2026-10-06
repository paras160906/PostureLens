import React, { useEffect, useState } from 'react';
import { fetchScanDetail } from '../api';
import SeverityBadge from '../components/SeverityBadge';
import RadialScoreGauge from '../components/RadialScoreGauge';

export default function ScanDetailView({ scanId, onBack }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('violations');

  useEffect(() => {
    const loadDetail = async () => {
      try {
        setLoading(true);
        setError(null);
        const res = await fetchScanDetail(scanId);
        setData(res);
      } catch (err) {
        setError(err.message || 'Failed to fetch scan details');
      } finally {
        setLoading(false);
      }
    };
    if (scanId) {
      loadDetail();
    }
  }, [scanId]);

  if (loading) {
    return (
      <div className="p-16 text-center font-sans text-sm text-[#A3A3A3] flex flex-col items-center gap-3">
        <span className="material-symbols-outlined text-4xl animate-spin text-[#EDEDED]">progress_activity</span>
        <span className="font-mono text-xs text-[#737373]">Loading report details for Scan #{scanId}...</span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-8 max-w-2xl mx-auto my-8 font-sans text-xs text-[#EF4444] bg-[#271113] border border-[#7F1D1D] rounded text-center space-y-4">
        <p>{error || 'Scan not found.'}</p>
        <button onClick={onBack} className="bg-[#EDEDED] text-[#0A0A0A] px-4 py-2 rounded font-sans font-bold cursor-pointer">
          Back to Dashboard
        </button>
      </div>
    );
  }

  const { filename, file_type, risk_score, risk_level, total_violations, created_at, scan_result } = data;
  const parsedData = scan_result?.parsed_data || {};
  const policyReport = scan_result?.policy_report || {};
  const violations = policyReport.violations || [];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans text-[#EDEDED]">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#262626]">
        <div className="flex items-center gap-4">
          <button
            onClick={onBack}
            className="p-2 rounded bg-[#121212] hover:bg-[#1C1C1C] text-[#A3A3A3] hover:text-[#EDEDED] transition-colors cursor-pointer border border-[#262626]"
            title="Back to Dashboard"
          >
            <span className="material-symbols-outlined text-xl">arrow_back</span>
          </button>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-2xl font-bold text-[#EDEDED] font-sans tracking-tight">{filename}</h2>
              <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-[#171717] border border-[#262626] text-[#A3A3A3] uppercase">
                {file_type}
              </span>
              <SeverityBadge severity={risk_level} />
            </div>
            <p className="text-xs text-[#737373] font-mono mt-1">
              Scan ID: #{data.id} • Date: {new Date(created_at).toLocaleString()}
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            const str = JSON.stringify(data, null, 2);
            const blob = new Blob([str], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_${data.id}_report.json`;
            a.click();
          }}
          className="bg-[#121212] text-[#EDEDED] font-sans text-xs font-semibold px-4 py-2 rounded border border-[#262626] hover:border-[#525252] transition-colors flex items-center gap-2 cursor-pointer self-start sm:self-auto"
        >
          <span className="material-symbols-outlined text-sm">download</span>
          Export JSON Report
        </button>
      </div>

      {/* Asymmetrical Top Layout: Hero Panel vs Secondary Cards */}
      <div className="grid grid-cols-12 gap-6">
        {/* HERO Risk Panel (5 columns) */}
        <div className="col-span-12 lg:col-span-5 bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col justify-between relative overflow-hidden">
          <div className="flex justify-between items-start mb-4">
            <div>
              <span className="text-xs font-bold text-[#A3A3A3] uppercase tracking-wider font-sans">
                Overall Risk Assessment
              </span>
              <div className="text-xs text-[#737373] mt-0.5 font-sans">CVSS-weighted score (0 - 100)</div>
            </div>
            <SeverityBadge severity={risk_level} />
          </div>

          <div className="flex items-center justify-between py-3 my-auto">
            <div>
              <div className="text-5xl font-bold font-sans text-[#EDEDED] tracking-tight">
                {risk_score}
                <span className="text-base font-normal text-[#737373] font-mono ml-1">/100</span>
              </div>
              <div className="text-xs font-mono text-[#A3A3A3] mt-2">
                {risk_score === 0
                  ? 'Zero threat posture detected.'
                  : risk_score > 50
                  ? 'Requires immediate mitigation.'
                  : 'Action recommended for medium risks.'}
              </div>
            </div>

            {/* Functional Radial Gauge */}
            <RadialScoreGauge score={risk_score} size={104} />
          </div>

          <div className="pt-3 border-t border-[#262626] flex items-center justify-between text-xs text-[#737373] font-mono">
            <span>Evaluator: OPA Rego Engine</span>
            <span>Target: {file_type.toUpperCase()}</span>
          </div>
        </div>

        {/* Secondary Stat Cards (7 columns) */}
        <div className="col-span-12 lg:col-span-7 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Policy Violations Flagged */}
          <div className="bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-bold text-[#A3A3A3] uppercase tracking-wider font-sans">
                  Violations Flagged
                </span>
                <span className="material-symbols-outlined text-[#EDEDED] text-xl">gavel</span>
              </div>
              <div className="text-4xl font-bold font-sans text-[#EDEDED] mt-1">
                {total_violations}
              </div>
            </div>
            <div className="text-xs text-[#737373] font-mono mt-4">
              Across 5 Rego policy categories
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col justify-between">
            <span className="text-xs font-bold text-[#A3A3A3] uppercase tracking-wider font-sans mb-3">
              Severity Distribution
            </span>
            <div className="grid grid-cols-2 gap-2.5 font-mono text-xs flex-1">
              <div className="bg-[#271113] p-2.5 rounded border border-[#7F1D1D] flex justify-between items-center">
                <span className="text-[#EF4444] font-bold">CRIT</span>
                <span className="text-[#EF4444] font-bold">{policyReport.risk_score?.breakdown?.critical || 0}</span>
              </div>
              <div className="bg-[#24140D] p-2.5 rounded border border-[#7C2D12] flex justify-between items-center">
                <span className="text-[#F97316] font-bold">HIGH</span>
                <span className="text-[#F97316] font-bold">{policyReport.risk_score?.breakdown?.high || 0}</span>
              </div>
              <div className="bg-[#211D0E] p-2.5 rounded border border-[#713F12] flex justify-between items-center">
                <span className="text-[#EAB308] font-semibold">MED</span>
                <span className="text-[#EAB308] font-semibold">{policyReport.risk_score?.breakdown?.medium || 0}</span>
              </div>
              <div className="bg-[#0A2118] p-2.5 rounded border border-[#065F46] flex justify-between items-center">
                <span className="text-[#10B981] font-semibold">LOW</span>
                <span className="text-[#10B981] font-semibold">{policyReport.risk_score?.breakdown?.low || 0}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs Header */}
      <div className="border-b border-[#262626] flex gap-6 font-sans text-sm pt-2">
        <button
          onClick={() => setActiveTab('violations')}
          className={`pb-3 font-semibold transition-all border-b-2 cursor-pointer ${
            activeTab === 'violations'
              ? 'border-[#EDEDED] text-[#EDEDED]'
              : 'border-transparent text-[#A3A3A3] hover:text-[#EDEDED]'
          }`}
        >
          OPA Policy Violations ({violations.length})
        </button>
        <button
          onClick={() => setActiveTab('parsed')}
          className={`pb-3 font-semibold transition-all border-b-2 cursor-pointer ${
            activeTab === 'parsed'
              ? 'border-[#EDEDED] text-[#EDEDED]'
              : 'border-transparent text-[#A3A3A3] hover:text-[#EDEDED]'
          }`}
        >
          Parsed Metadata Specifications
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === 'violations' && (
        <div className="bg-[#121212] rounded-xl border border-[#262626] overflow-hidden">
          {violations.length === 0 ? (
            <div className="p-12 text-center font-sans text-sm text-[#10B981] flex flex-col items-center gap-2">
              <span className="material-symbols-outlined text-4xl">check_circle</span>
              <span className="font-bold">Zero Violations Found</span>
              <span className="text-xs text-[#737373] font-mono">This specification passed all active OPA Rego security rules.</span>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-sans text-sm">
                <thead>
                  <tr className="bg-[#0A0A0A] border-b border-[#262626] text-xs font-semibold text-[#A3A3A3] uppercase tracking-wider">
                    <th className="py-3 px-4">Rule ID</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Violation Details</th>
                    <th className="py-3 px-4">Target Field Path</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#262626]">
                  {violations.map((v, idx) => (
                    <tr key={idx} className="hover:bg-[#171717] transition-colors">
                      <td className="py-3.5 px-4 font-mono text-xs text-[#EDEDED] font-bold whitespace-nowrap">
                        {v.rule_id}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-[#EDEDED] text-sm font-sans">{v.title}</div>
                        <div className="text-xs text-[#A3A3A3] mt-0.5 leading-relaxed font-sans">{v.description}</div>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs text-[#A3A3A3] whitespace-nowrap">
                        <code className="px-2 py-1 bg-[#050505] rounded border border-[#262626] text-[#EDEDED]">
                          {v.field_path}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'parsed' && (
        <div className="bg-[#121212] rounded-xl p-6 border border-[#262626] space-y-6">
          <h3 className="text-base font-bold text-[#EDEDED] font-sans">Extracted Specification Data</h3>

          {file_type === 'dockerfile' ? (
            <div className="space-y-4 font-mono text-xs">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-[#0A0A0A] p-4 rounded border border-[#262626]">
                  <div className="text-[#A3A3A3] font-sans font-semibold mb-1">Final Base Image</div>
                  <div className="text-[#EDEDED] font-mono font-bold text-sm">{parsedData.final_base_image || 'N/A'}</div>
                </div>
                <div className="bg-[#0A0A0A] p-4 rounded border border-[#262626]">
                  <div className="text-[#A3A3A3] font-sans font-semibold mb-1">Final User Directive</div>
                  <div className={`font-mono font-bold text-sm ${parsedData.is_root_user ? 'text-[#EF4444]' : 'text-[#10B981]'}`}>
                    {parsedData.final_user} {parsedData.is_root_user && '(ROOT Execution)'}
                  </div>
                </div>
              </div>

              <div className="bg-[#0A0A0A] p-4 rounded border border-[#262626]">
                <div className="text-[#A3A3A3] font-sans font-semibold mb-2">Exposed Ports</div>
                {parsedData.exposed_ports && parsedData.exposed_ports.length > 0 ? (
                  <div className="flex gap-2 flex-wrap">
                    {parsedData.exposed_ports.map((p, i) => (
                      <span key={i} className="px-2.5 py-1 bg-[#171717] border border-[#262626] rounded text-[#EDEDED]">
                        {p.port}/{p.protocol}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="text-[#737373] font-sans">No EXPOSE directives declared.</div>
                )}
              </div>

              <div className="bg-[#0A0A0A] p-4 rounded border border-[#262626]">
                <div className="text-[#A3A3A3] font-sans font-semibold mb-2">
                  Environment Variables ({parsedData.env_vars?.length || 0})
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {parsedData.env_vars?.map((env, i) => (
                    <div
                      key={i}
                      className={`flex justify-between p-2 rounded border ${
                        env.is_potentially_sensitive
                          ? 'bg-[#271113] text-[#EF4444] border-[#7F1D1D]'
                          : 'bg-[#171717] border-[#262626] text-[#EDEDED]'
                      }`}
                    >
                      <span>{env.key}</span>
                      <span className="opacity-80 font-mono">{env.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-4 font-mono text-xs">
              <div className="bg-[#0A0A0A] p-4 rounded border border-[#262626]">
                <div className="text-[#A3A3A3] font-sans font-semibold mb-3">
                  Pod Specs & Container Security Contexts ({parsedData.pod_specs?.length || 0})
                </div>
                {parsedData.pod_specs?.map((pod, i) => (
                  <div key={i} className="p-3 bg-[#171717] rounded mb-2 border border-[#262626] space-y-2">
                    <div className="flex justify-between font-sans font-bold text-[#EDEDED]">
                      <span>{pod.workload_kind}: {pod.pod_name}</span>
                      <span className="text-[#A3A3A3] font-mono text-xs">Namespace: {pod.namespace}</span>
                    </div>
                    <div className="flex gap-4 text-[#A3A3A3] text-xs">
                      <span>hostNetwork: <strong className={pod.host_network ? 'text-[#EF4444]' : 'text-[#10B981]'}>{String(pod.host_network)}</strong></span>
                      <span>hostPID: <strong className={pod.host_pid ? 'text-[#EF4444]' : 'text-[#10B981]'}>{String(pod.host_pid)}</strong></span>
                      <span>hostIPC: <strong className={pod.host_ipc ? 'text-[#EF4444]' : 'text-[#10B981]'}>{String(pod.host_ipc)}</strong></span>
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-[#0A0A0A] p-4 rounded border border-[#262626]">
                <div className="text-[#A3A3A3] font-sans font-semibold mb-3">
                  RBAC Bindings ({parsedData.rbac_bindings?.length || 0})
                </div>
                {parsedData.rbac_bindings?.map((b, i) => (
                  <div key={i} className="p-3 bg-[#171717] rounded mb-2 border border-[#262626] flex justify-between items-center">
                    <div>
                      <div className="font-sans font-bold text-[#EDEDED]">{b.kind}: {b.name}</div>
                      <div className="text-[#A3A3A3] text-xs mt-0.5">roleRef: {b.role_ref?.name}</div>
                    </div>
                    <div>
                      {b.binds_cluster_admin && <span className="mr-2 px-2 py-0.5 bg-[#271113] text-[#EF4444] border border-[#7F1D1D] rounded text-[10px] font-bold">cluster-admin</span>}
                      {b.binds_default_service_account && <span className="px-2 py-0.5 bg-[#24140D] text-[#F97316] border border-[#7C2D12] rounded text-[10px] font-bold">default SA</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
