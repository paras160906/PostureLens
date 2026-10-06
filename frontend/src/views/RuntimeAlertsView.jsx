import React, { useEffect, useState, useRef } from 'react';
import { fetchRuntimeAlerts, simulateFalcoAlert } from '../api';
import SeverityBadge from '../components/SeverityBadge';

export default function RuntimeAlertsView() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pollingActive, setPollingActive] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const timerRef = useRef(null);

  const loadAlerts = async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      setError(null);
      const data = await fetchRuntimeAlerts();
      setAlerts(data);
    } catch (err) {
      if (!isSilent) setError(err.message || 'Failed to fetch runtime alerts.');
    } finally {
      if (!isSilent) setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();

    if (pollingActive) {
      timerRef.current = setInterval(() => {
        loadAlerts(true);
      }, 5000);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [pollingActive]);

  const handleSimulateAlert = async () => {
    try {
      setSimulating(true);
      await simulateFalcoAlert();
      await loadAlerts(true);
    } catch (err) {
      alert('Failed to simulate Falco alert: ' + (err.message || err));
    } finally {
      setSimulating(false);
    }
  };

  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  const highCount = alerts.filter(a => a.severity === 'high').length;
  const medCount = alerts.filter(a => a.severity === 'medium').length;
  const lowCount = alerts.filter(a => a.severity === 'low').length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans text-[#EDEDED]">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl font-bold text-[#EDEDED] font-sans tracking-tight">Falco Runtime Alerts</h2>
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#271113] text-[#EF4444] border border-[#7F1D1D] font-mono text-[11px] font-bold tracking-wider">
              <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-ping shrink-0" />
              LIVE MONITORING
            </span>
          </div>
          <p className="text-sm text-[#A3A3A3] mt-1 font-sans">
            Real-time kernel container security alerts streamed from Falco to PostureLens.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setPollingActive(!pollingActive)}
            className={`font-mono text-xs px-3 py-2 rounded border flex items-center gap-2 cursor-pointer transition-all ${
              pollingActive
                ? 'bg-[#171717] border-[#525252] text-[#EDEDED]'
                : 'bg-[#121212] border-[#262626] text-[#737373]'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${pollingActive ? 'bg-[#10B981] animate-ping' : 'bg-[#525252]'}`} />
            {pollingActive ? 'Polling Active (5s)' : 'Polling Paused'}
          </button>

          <button
            onClick={handleSimulateAlert}
            disabled={simulating}
            className="bg-[#EDEDED] text-[#0A0A0A] font-sans text-xs font-bold px-4 py-2 rounded hover:bg-[#FFFFFF] transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50 shadow-sm"
          >
            {simulating ? (
              <span className="material-symbols-outlined text-sm animate-spin">progress_activity</span>
            ) : (
              <span className="material-symbols-outlined text-sm">bolt</span>
            )}
            Simulate Falco Alert
          </button>
        </div>
      </div>

      {/* Top Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-sans">
        <div className="bg-[#121212] rounded-xl p-4 border border-[#262626] flex justify-between items-center">
          <div>
            <div className="text-xs text-[#A3A3A3] uppercase font-bold">Total Ingested Events</div>
            <div className="text-2xl font-bold font-sans text-[#EDEDED] mt-1">{alerts.length}</div>
          </div>
          <span className="material-symbols-outlined text-[#EDEDED] text-2xl">shield</span>
        </div>

        <div className="bg-[#271113] rounded-xl p-4 border border-[#7F1D1D] flex justify-between items-center">
          <div>
            <div className="text-xs text-[#EF4444] uppercase font-bold">Critical Severity</div>
            <div className="text-2xl font-bold font-sans text-[#EF4444] mt-1">{criticalCount}</div>
          </div>
          <span className="material-symbols-outlined text-[#EF4444] text-2xl">warning</span>
        </div>

        <div className="bg-[#24140D] rounded-xl p-4 border border-[#7C2D12] flex justify-between items-center">
          <div>
            <div className="text-xs text-[#F97316] uppercase font-bold">High Severity</div>
            <div className="text-2xl font-bold font-sans text-[#F97316] mt-1">{highCount}</div>
          </div>
          <span className="material-symbols-outlined text-[#F97316] text-2xl">error_med</span>
        </div>

        <div className="bg-[#121212] rounded-xl p-4 border border-[#262626] flex justify-between items-center">
          <div>
            <div className="text-xs text-[#A3A3A3] uppercase font-bold">Med / Low Severity</div>
            <div className="text-2xl font-bold font-sans text-[#EAB308] mt-1">{medCount + lowCount}</div>
          </div>
          <span className="material-symbols-outlined text-[#A3A3A3] text-2xl">info</span>
        </div>
      </div>

      {/* Runtime Alerts Table */}
      <div className="bg-[#121212] rounded-xl border border-[#262626] overflow-hidden">
        <div className="p-4 border-b border-[#262626] flex justify-between items-center">
          <h3 className="text-base font-bold text-[#EDEDED] font-sans flex items-center gap-2">
            <span className="material-symbols-outlined text-[#EF4444]">graphic_eq</span>
            Live Streamed Falco Events
          </h3>
          <span className="text-xs text-[#737373] font-mono">
            Showing latest {alerts.length} events
          </span>
        </div>

        {loading ? (
          <div className="p-12 text-center font-sans text-sm text-[#A3A3A3] flex flex-col items-center gap-3">
            <span className="material-symbols-outlined text-3xl animate-spin text-[#EDEDED]">progress_activity</span>
            <span className="font-mono text-xs text-[#737373]">Connecting to runtime alert stream...</span>
          </div>
        ) : error ? (
          <div className="p-8 text-center font-sans text-xs text-[#EF4444] bg-[#271113] m-4 rounded border border-[#7F1D1D]">
            {error}
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center font-sans text-sm text-[#A3A3A3] space-y-3">
            <span className="material-symbols-outlined text-4xl text-[#EDEDED] opacity-60">verified_user</span>
            <p className="font-sans">No runtime alerts detected. Falco has not observed any active kernel security violations.</p>
            <button
              onClick={handleSimulateAlert}
              className="text-[#EDEDED] hover:underline font-mono text-xs inline-flex items-center gap-1 cursor-pointer"
            >
              Click here to simulate a Falco alert for live testing
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse font-sans text-sm">
              <thead>
                <tr className="bg-[#0A0A0A] border-b border-[#262626] text-xs font-semibold text-[#A3A3A3] uppercase tracking-wider font-sans">
                  <th className="py-3 px-4">Rule ID</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Rule Name & Details</th>
                  <th className="py-3 px-4">Container / Pod Spec</th>
                  <th className="py-3 px-4">Ingested At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#262626]">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-[#171717] transition-colors">
                    <td className="py-3.5 px-4 font-mono text-xs text-[#EDEDED] font-bold whitespace-nowrap">
                      #{alert.id} • {alert.rule_id}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-[#EDEDED] text-sm font-sans">{alert.rule_name}</div>
                      <div className="text-xs text-[#A3A3A3] font-mono mt-1 line-clamp-2 leading-relaxed">
                        {alert.description}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs">
                      <div className="text-[#EDEDED] font-semibold font-sans">
                        Pod: <span className="text-[#EDEDED] font-mono">{alert.pod_name}</span> ({alert.namespace})
                      </div>
                      <div className="text-[#737373] text-[11px] mt-0.5">
                        Container: {alert.container_id}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-[#737373] whitespace-nowrap">
                      {new Date(alert.created_at).toLocaleTimeString()}
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
