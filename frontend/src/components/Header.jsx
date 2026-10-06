import React from 'react';

export default function Header({ title, searchFilter, setSearchFilter }) {
  return (
    <header className="h-16 px-6 bg-[#121212] border-b border-[#262626] flex justify-between items-center z-10 w-full sticky top-0 font-sans">
      <div className="flex items-center gap-4 flex-1">
        <h2 className="text-lg font-bold text-[#EDEDED] tracking-tight">{title}</h2>
        {setSearchFilter && (
          <div className="relative w-64 ml-4">
            <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-[#737373] text-sm">
              search
            </span>
            <input
              type="text"
              value={searchFilter || ''}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Search resource or rule..."
              className="w-full bg-[#0A0A0A] border border-[#262626] rounded pl-8 pr-3 py-1.5 text-xs text-[#EDEDED] focus:outline-none focus:border-[#525252] transition-colors font-mono"
            />
          </div>
        )}
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1 bg-[#171717] border border-[#262626] rounded text-xs font-mono text-[#EDEDED]">
          <span className="material-symbols-outlined text-sm text-[#10B981]">check_circle</span>
          API Connected
        </div>
        <button className="text-[#A3A3A3] hover:text-[#EDEDED] transition-colors p-2 rounded-full cursor-pointer">
          <span className="material-symbols-outlined">notifications</span>
        </button>
        <button className="text-[#A3A3A3] hover:text-[#EDEDED] transition-colors p-2 rounded-full cursor-pointer">
          <span className="material-symbols-outlined">account_circle</span>
        </button>
      </div>
    </header>
  );
}
