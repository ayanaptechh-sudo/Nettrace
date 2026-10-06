import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Scale,
  FileBarChart2,
  Crosshair,
  Terminal,
  Cpu,
} from 'lucide-react';

interface SidebarProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  alertCount: number;
  suspiciousCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  setCurrentView,
  alertCount,
  suspiciousCount,
}) => {
  const navItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'traffic',
      label: 'Live Traffic',
      icon: Activity,
      badge: suspiciousCount > 0 ? `${suspiciousCount} Susp` : null,
      badgeColor: 'bg-rose-950 text-rose-400 border border-rose-800/60',
    },
    {
      id: 'alerts',
      label: 'Security Alerts',
      icon: ShieldAlert,
      badge: alertCount > 0 ? `${alertCount}` : null,
      badgeColor: 'bg-rose-600 text-white',
    },
    {
      id: 'baseline',
      label: 'Port Baselines',
      icon: Scale,
      badge: null,
    },
    {
      id: 'reports',
      label: 'Reports & Audit',
      icon: FileBarChart2,
      badge: null,
    },
    {
      id: 'threat_intel',
      label: 'Threat Intel & Inject',
      icon: Crosshair,
      badge: null,
    },
    {
      id: 'python_source',
      label: 'Python Code & Docs',
      icon: Terminal,
      badge: 'Flet',
      badgeColor: 'bg-cyan-950 text-cyan-400 border border-cyan-800',
    },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0">
      {/* Navigation Links */}
      <div className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[11px] font-semibold tracking-wider text-slate-500 uppercase">
          Monitoring Views
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentView(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'
                  }`}
                />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full ${
                    item.badgeColor || 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Engine Status / System Specs Info Card */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/40 m-3 rounded-xl">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 mb-2">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Capture Engine</span>
        </div>
        <div className="space-y-1.5 text-[11px] text-slate-400 font-mono">
          <div className="flex justify-between">
            <span className="text-slate-500">Filter:</span>
            <span>ip (TCP/UDP/ICMP)</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Anomaly Sigma:</span>
            <span>3.0 σ</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Learning Limit:</span>
            <span>5 hits</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Payload Storage:</span>
            <span className="text-emerald-400">Zero (Metadata Only)</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
