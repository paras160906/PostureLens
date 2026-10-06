import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import DashboardView from './views/DashboardView';
import NewScanView from './views/NewScanView';
import ScanDetailView from './views/ScanDetailView';
import PolicyLibraryView from './views/PolicyLibraryView';
import RuntimeAlertsView from './views/RuntimeAlertsView';

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [searchFilter, setSearchFilter] = useState('');

  const viewTitles = {
    dashboard: 'Dashboard Overview',
    new_scan: 'Initialize New Scan',
    scan_history: 'Scan History',
    scan_detail: `Scan Detail #${selectedScanId || ''}`,
    runtime_alerts: 'Falco Runtime Security Alerts',
    policies: 'OPA Rego Policy Library',
  };

  const handleSelectScan = (id) => {
    setSelectedScanId(id);
    setActiveView('scan_detail');
  };

  const handleScanComplete = (id) => {
    setSelectedScanId(id);
    setActiveView('scan_detail');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background text-on-background font-sans">
      {/* Sidebar */}
      <Sidebar activeView={activeView} setActiveView={setActiveView} />

      {/* Main Content Area */}
      <div className="flex-1 ml-64 flex flex-col h-screen overflow-hidden">
        {/* Top Header */}
        <Header
          title={viewTitles[activeView] || 'PostureLens Security'}
          searchFilter={searchFilter}
          setSearchFilter={setSearchFilter}
        />

        {/* View Router Canvas */}
        <main className="flex-1 overflow-y-auto bg-background">
          {(activeView === 'dashboard' || activeView === 'scan_history') && (
            <DashboardView
              onSelectScan={handleSelectScan}
              onNewScan={() => setActiveView('new_scan')}
            />
          )}

          {activeView === 'new_scan' && (
            <NewScanView onScanComplete={handleScanComplete} />
          )}

          {activeView === 'scan_detail' && (
            <ScanDetailView
              scanId={selectedScanId}
              onBack={() => setActiveView('dashboard')}
            />
          )}

          {activeView === 'runtime_alerts' && (
            <RuntimeAlertsView />
          )}

          {activeView === 'policies' && (
            <PolicyLibraryView searchFilter={searchFilter} />
          )}
        </main>
      </div>
    </div>
  );
}
