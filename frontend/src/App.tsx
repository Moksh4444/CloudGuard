import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavPage } from './components/Sidebar';
import { Overview } from './pages/Overview';
import { NetworkDiagnostics } from './pages/NetworkDiagnostics';
import { HttpAnalyzer } from './pages/HttpAnalyzer';
import { DnsLookup } from './pages/DnsLookup';
import { TlsInspector } from './pages/TlsInspector';
import { CloudSecAnalyzer } from './pages/CloudSecAnalyzer';
import { Reports } from './pages/Reports';
import { HistoryAnalytics } from './pages/HistoryAnalytics';
import { SettingsAbout } from './pages/SettingsAbout';

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<NavPage>('overview');
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleDataChanged = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'overview':
        return <Overview onNavigate={setCurrentPage} refreshTrigger={refreshTrigger} />;
      case 'network':
        return <NetworkDiagnostics />;
      case 'http':
        return <HttpAnalyzer />;
      case 'dns':
        return <DnsLookup />;
      case 'tls':
        return <TlsInspector />;
      case 'cloud-sec':
        return <CloudSecAnalyzer />;
      case 'reports':
        return <Reports />;
      case 'history':
        return <HistoryAnalytics />;
      case 'settings':
        return <SettingsAbout />;
      default:
        return <Overview onNavigate={setCurrentPage} refreshTrigger={refreshTrigger} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans">
      <Navbar
        onDataChanged={handleDataChanged}
        onToggleMobileMenu={() => setMobileMenuOpen((prev) => !prev)}
      />

      <div className="flex flex-1">
        <Sidebar
          currentPage={currentPage}
          onSelectPage={setCurrentPage}
          mobileOpen={mobileMenuOpen}
          onCloseMobile={() => setMobileMenuOpen(false)}
        />

        <main className="flex-1 p-6 lg:p-8 max-w-7xl mx-auto w-full overflow-y-auto">
          {renderPage()}
        </main>
      </div>

      <footer className="border-t border-slate-800 bg-slate-950/80 px-6 py-4 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-400">CloudGuard Platform</span>
          <span>&bull;</span>
          <span>Cloud Security & Network Troubleshooting Intelligence</span>
        </div>
        <div>
          <span>Zero-Trust SSRF Boundaries Active &bull; SQLite Persistence</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
