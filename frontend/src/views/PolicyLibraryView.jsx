import React, { useEffect, useState } from 'react';
import { fetchPolicies } from '../api';
import SeverityBadge from '../components/SeverityBadge';

export default function PolicyLibraryView({ searchFilter }) {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [localSearch, setLocalSearch] = useState('');

  useEffect(() => {
    const loadPolicies = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await fetchPolicies();
        setPolicies(data);
      } catch (err) {
        setError(err.message || 'Failed to load policy rules catalog.');
      } finally {
        setLoading(false);
      }
    };
    loadPolicies();
  }, []);

  const categories = ['ALL', 'container', 'resources', 'network', 'secrets', 'rbac'];
  const searchTerm = (searchFilter || localSearch || '').toLowerCase();

  const filtered = policies.filter((p) => {
    const matchesCategory = selectedCategory === 'ALL' || p.category.toLowerCase() === selectedCategory.toLowerCase();
    const matchesSearch = !searchTerm || (
      p.id.toLowerCase().includes(searchTerm) ||
      p.title.toLowerCase().includes(searchTerm) ||
      p.description.toLowerCase().includes(searchTerm) ||
      p.category.toLowerCase().includes(searchTerm)
    );
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans text-[#EDEDED]">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-[#EDEDED] font-sans tracking-tight">OPA Rego Policy Library</h2>
          <p className="text-sm text-[#A3A3A3] mt-1 font-sans">
            Catalog of active security policy rules evaluated against Dockerfiles and Kubernetes manifests.
          </p>
        </div>
        <div className="relative w-full md:w-72">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-[#737373] text-sm">
            search
          </span>
          <input
            type="text"
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
            placeholder="Search rules..."
            className="w-full bg-[#0A0A0A] border border-[#262626] rounded pl-9 pr-3 py-2 text-xs font-mono text-[#EDEDED] focus:outline-none focus:border-[#525252]"
          />
        </div>
      </div>

      {/* Category Pills Filter */}
      <div className="flex gap-2 flex-wrap font-mono text-xs">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded transition-all cursor-pointer uppercase ${
              selectedCategory === cat
                ? 'bg-[#EDEDED] text-[#0A0A0A] font-bold shadow-sm'
                : 'bg-[#121212] text-[#A3A3A3] hover:text-[#EDEDED] border border-[#262626]'
            }`}
          >
            {cat} {cat !== 'ALL' && `(${policies.filter(p => p.category.toLowerCase() === cat.toLowerCase()).length})`}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="p-16 text-center font-sans text-sm text-[#A3A3A3] flex flex-col items-center gap-3">
          <span className="material-symbols-outlined text-4xl animate-spin text-[#EDEDED]">progress_activity</span>
          <span className="font-mono text-xs text-[#737373]">Loading OPA Rego policy catalog...</span>
        </div>
      ) : error ? (
        <div className="p-8 text-center font-sans text-sm text-[#EF4444] bg-[#271113] border border-[#7F1D1D] rounded">
          {error}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {filtered.map((policy) => (
            <div
              key={policy.id}
              className="bg-[#121212] rounded-xl p-5 border border-[#262626] flex flex-col justify-between hover:border-[#525252] transition-colors space-y-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-[#EDEDED] px-2 py-0.5 rounded bg-[#0A0A0A] border border-[#262626]">
                    {policy.id}
                  </span>
                  <span className="font-mono text-[11px] text-[#A3A3A3] uppercase px-2 py-0.5 rounded bg-[#171717] border border-[#262626]">
                    {policy.category}
                  </span>
                </div>
                <SeverityBadge severity={policy.severity} />
              </div>

              <div>
                <h3 className="text-base font-bold text-[#EDEDED] font-sans mb-1">{policy.title}</h3>
                <p className="text-xs text-[#A3A3A3] leading-relaxed font-sans">{policy.description}</p>
              </div>

              <div className="pt-2.5 border-t border-[#262626] flex items-center justify-between font-mono text-[11px] text-[#737373]">
                <span>Evaluator: OPA Engine</span>
                <span className="text-[#EDEDED] font-semibold">Active Rego Rule</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
