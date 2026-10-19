import React from 'react';
import {
  LayoutDashboard,
  Network,
  Globe,
  Search,
  Lock,
  ShieldAlert,
  FileText,
  Activity,
  Sliders,
  ChevronRight,
  X,
} from 'lucide-react';

export type NavPage =
  | 'overview'
  | 'network'
  | 'http'
  | 'dns'
  | 'tls'
  | 'cloud-sec'
  | 'reports'
  | 'history'
  | 'settings';

interface SidebarProps {
  currentPage: NavPage;
  onSelectPage: (page: NavPage) => void;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

const navItems = [
  { id: 'overview' as NavPage, label: 'Overview Dashboard', icon: LayoutDashboard },
  { id: 'network' as NavPage, label: 'Network Diagnostics', icon: Network },
  { id: 'http' as NavPage, label: 'HTTP/HTTPS Analyzer', icon: Globe },
  { id: 'dns' as NavPage, label: 'DNS Lookup', icon: Search },
  { id: 'tls' as NavPage, label: 'TLS Inspector', icon: Lock },
  { id: 'cloud-sec' as NavPage, label: 'Cloud Security (AWS)', icon: ShieldAlert },
  { id: 'reports' as NavPage, label: 'Troubleshooting Reports', icon: FileText },
  { id: 'history' as NavPage, label: 'History & Analytics', icon: Activity },
  { id: 'settings' as NavPage, label: 'Settings & Portfolio', icon: Sliders },
];

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  mobileOpen = false,
  onCloseMobile,
}) => {
  const content = (
    <div className="flex flex-col h-full">
      <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          Diagnostic Intelligence
        </span>
        {onCloseMobile && (
          <button
            type="button"
            onClick={onCloseMobile}
            className="md:hidden p-1 text-slate-400 hover:text-white rounded"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      <nav className="p-3 space-y-1 flex-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                onSelectPage(item.id);
                if (onCloseMobile) onCloseMobile();
              }}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                isActive
                  ? 'bg-sky-600/15 text-sky-400 border border-sky-500/30 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {isActive && <ChevronRight className="w-3.5 h-3.5 text-sky-400" />}
            </button>
          );
        })}
      </nav>

      {/* Portfolio Context Tag */}
      <div className="p-4 border-t border-slate-800 text-xs text-slate-500 bg-slate-950/40">
        <p className="font-semibold text-slate-300 mb-0.5">Skyhigh Security Portfolio</p>
        <p className="text-[11px] leading-tight text-slate-400">
          Associate Technical Consultant Demo Project
        </p>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex w-64 bg-slate-900 border-r border-slate-800 flex-col shrink-0 min-h-[calc(100vh-4rem)]">
        {content}
      </aside>

      {/* Mobile Drawer Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={onCloseMobile}
        />
      )}

      {/* Mobile Slide-in Drawer */}
      <div
        className={`fixed top-0 bottom-0 left-0 z-50 w-72 bg-slate-900 border-r border-slate-800 md:hidden transition-transform duration-300 ease-in-out ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {content}
      </div>
    </>
  );
};
