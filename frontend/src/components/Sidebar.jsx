import React from 'react';

export default function Sidebar({ activeView, setActiveView }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
    { id: 'new_scan', label: 'New Scan', icon: 'security_update_good' },
    { id: 'scan_history', label: 'Scan History', icon: 'history' },
    { id: 'runtime_alerts', label: 'Runtime Alerts', icon: 'graphic_eq' },
    { id: 'policies', label: 'Policy Library', icon: 'policy' },
  ];

  return (
    <aside className="fixed left-0 top-0 h-full w-64 bg-[#121212] border-r border-[#262626] flex flex-col py-6 px-4 z-20">
      <div className="mb-8 flex items-center gap-3 cursor-pointer" onClick={() => setActiveView('dashboard')}>
        <span className="material-symbols-outlined text-[#EDEDED] text-3xl">shield_with_heart</span>
        <div>
          <h1 className="font-sans text-xl font-bold text-[#EDEDED] tracking-tight">PostureLens</h1>
          <p className="font-mono text-xs text-[#A3A3A3] uppercase tracking-wider">Monochrome Engine</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1.5 font-sans">
        {navItems.map((item) => {
          const isActive = activeView === item.id || (activeView === 'scan_detail' && item.id === 'scan_history');
          return (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 rounded text-sm font-semibold transition-all duration-200 text-left cursor-pointer ${
                isActive
                  ? 'text-[#EDEDED] bg-[#1F1F1F] border-r-2 border-[#EDEDED]'
                  : 'text-[#A3A3A3] hover:bg-[#1A1A1A] hover:text-[#EDEDED]'
              }`}
            >
              <span className="material-symbols-outlined text-xl">{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="mt-auto pt-4 border-t border-[#262626] text-xs text-[#737373] font-mono">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#10B981] animate-ping" />
          <span>OPA + Falco Engine Active</span>
        </div>
      </div>
    </aside>
  );
}
