import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  Activity,
  ArrowUpRight,
  TrendingUp,
  PieChart as PieIcon,
  Clock,
  Layers,
} from 'lucide-react';
import { TrafficStats, PacketRecord, AlertRecord } from '../types';

interface DashboardViewProps {
  stats: TrafficStats;
  recentPackets: PacketRecord[];
  recentAlerts: AlertRecord[];
  onSelectPacket: (packet: PacketRecord) => void;
  onNavigate: (view: string) => void;
  rateHistory: number[];
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  recentPackets,
  recentAlerts,
  onSelectPacket,
  onNavigate,
  rateHistory,
}) => {
  const knownPct = stats.total > 0 ? ((stats.known / stats.total) * 100).toFixed(1) : '0';
  const unknownPct = stats.total > 0 ? ((stats.unknown / stats.total) * 100).toFixed(1) : '0';
  const suspiciousPct = stats.total > 0 ? ((stats.suspicious / stats.total) * 100).toFixed(1) : '0';

  const riskBg =
    stats.riskLevel === 'LOW'
      ? 'from-emerald-950/80 to-slate-900 border-emerald-800/80 text-emerald-300'
      : stats.riskLevel === 'MEDIUM'
      ? 'from-amber-950/80 to-slate-900 border-amber-800/80 text-amber-300'
      : 'from-rose-950/80 to-slate-900 border-rose-800/80 text-rose-300';

  const riskBadge =
    stats.riskLevel === 'LOW'
      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
      : stats.riskLevel === 'MEDIUM'
      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
      : 'bg-rose-500/20 text-rose-300 border-rose-500/40';

  // Find max in rateHistory for chart scaling
  const maxRate = Math.max(...rateHistory, 5);

  return (
    <div className="space-y-6">
      {/* Risk Banner */}
      <div
        className={`p-4 rounded-2xl border bg-gradient-to-r ${riskBg} flex flex-wrap items-center justify-between gap-4 shadow-lg`}
      >
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-slate-950/50 border border-white/10">
            {stats.riskLevel === 'LOW' ? (
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-6 h-6 text-rose-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-wider font-semibold opacity-75">
                Current Risk Assessment
              </span>
              <span
                className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${riskBadge}`}
              >
                {stats.riskLevel} THREAT
              </span>
            </div>
            <p className="text-sm font-medium mt-0.5 text-white">
              {stats.riskLevel === 'LOW'
                ? 'Network posture is healthy. Normal traffic patterns conforming to learned baselines.'
                : stats.riskLevel === 'MEDIUM'
                ? 'Elevated anomalies observed. New unknown ports or moderate payload variances detected.'
                : 'High threat detected! Suspicious port reconnaissance, rapid spikes, or severe alerts triggered.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6 px-4 py-2 bg-slate-950/60 rounded-xl border border-white/5 font-mono text-xs">
          <div>
            <span className="text-slate-400 block text-[10px] uppercase">Risk Score</span>
            <span className="text-lg font-bold text-white">{stats.riskScore}</span>
          </div>
          <div className="h-6 w-px bg-slate-800" />
          <div>
            <span className="text-slate-400 block text-[10px] uppercase">Formula</span>
            <span className="text-slate-300 text-[11px]">Susp×10 + Unk×3 + Alerts</span>
          </div>
        </div>
      </div>

      {/* Top 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Packets */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>TOTAL CAPTURED</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{stats.total}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between font-mono">
            <span>Volume: {(stats.totalBytes / 1024).toFixed(1)} KB</span>
            <span className="text-cyan-400">Metadata only</span>
          </div>
        </div>

        {/* Known Traffic */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm hover:border-emerald-900/40 transition">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-medium mb-1">
            <span>KNOWN TRAFFIC</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400 font-mono">{stats.known}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between font-mono">
            <span>{knownPct}% of total</span>
            <span className="text-emerald-500/80">Baselines met</span>
          </div>
        </div>

        {/* Unknown Traffic */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm hover:border-amber-900/40 transition">
          <div className="flex items-center justify-between text-amber-400 text-xs font-medium mb-1">
            <span>UNKNOWN TRAFFIC</span>
            <HelpCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400 font-mono">{stats.unknown}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between font-mono">
            <span>{unknownPct}% of total</span>
            <span className="text-amber-500/80">Learning phase</span>
          </div>
        </div>

        {/* Suspicious Traffic */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm hover:border-rose-900/40 transition">
          <div className="flex items-center justify-between text-rose-400 text-xs font-medium mb-1">
            <span>SUSPICIOUS TRAFFIC</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-400 font-mono">{stats.suspicious}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between font-mono">
            <span>{suspiciousPct}% of total</span>
            <span className="text-rose-500/80">Risky / Spikes</span>
          </div>
        </div>
      </div>

      {/* Real-time Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Traffic Rate Chart (Last 30-60 samples) */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Traffic Rate (Sliding Window)
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Peak: {maxRate} pkt/s
            </span>
          </div>

          <div className="h-44 w-full flex items-end gap-1.5 pt-4 pb-2 px-1 border-b border-slate-800">
            {rateHistory.map((val, idx) => {
              const heightPct = Math.max(8, (val / maxRate) * 100);
              return (
                <div
                  key={idx}
                  className="flex-1 flex flex-col items-center gap-1 group relative h-full justify-end"
                >
                  <div
                    style={{ height: `${heightPct}%` }}
                    className={`w-full rounded-t transition-all duration-300 ${
                      val > 15
                        ? 'bg-rose-500 group-hover:bg-rose-400'
                        : val > 6
                        ? 'bg-cyan-500 group-hover:bg-cyan-400'
                        : 'bg-cyan-800/60 group-hover:bg-cyan-700'
                    }`}
                  />
                  {/* Tooltip */}
                  <div className="opacity-0 group-hover:opacity-100 absolute -top-7 bg-slate-800 text-[10px] text-white font-mono px-1.5 py-0.5 rounded shadow pointer-events-none transition z-10 whitespace-nowrap">
                    {val} pkt/s
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono mt-2">
            <span>60s ago</span>
            <span>30s ago</span>
            <span>Now (Live)</span>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <PieIcon className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Protocol Breakdown
              </h3>
            </div>

            <div className="space-y-4 font-mono text-xs">
              {(['TCP', 'UDP', 'ICMP'] as const).map((proto) => {
                const count = stats.protocolCounts[proto] || 0;
                const pct = stats.total > 0 ? ((count / stats.total) * 100).toFixed(1) : '0';
                const color =
                  proto === 'TCP'
                    ? 'bg-cyan-500'
                    : proto === 'UDP'
                    ? 'bg-purple-500'
                    : 'bg-emerald-500';

                return (
                  <div key={proto} className="space-y-1.5">
                    <div className="flex justify-between items-center text-slate-300">
                      <span className="font-bold flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${color}`} />
                        {proto}
                      </span>
                      <span>
                        {count} <span className="text-slate-500">({pct}%)</span>
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-full ${color} transition-all duration-500`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-400 flex justify-between items-center">
            <span>Alerts Logged:</span>
            <span className="font-bold font-mono text-rose-400">{stats.alertsTotal} events</span>
          </div>
        </div>
      </div>

      {/* Two Feed Panels: Recent Traffic & Security Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Recent Traffic Feed */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Recent Traffic
              </h3>
            </div>
            <button
              onClick={() => onNavigate('traffic')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
            >
              View All ({stats.total}) <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 overflow-y-auto max-h-[360px] pr-1">
            {recentPackets.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No packets captured yet. Click "Start Monitoring" above.
              </div>
            ) : (
              recentPackets.slice(0, 10).map((pkt) => (
                <div
                  key={pkt.id}
                  onClick={() => onSelectPacket(pkt)}
                  className="py-2.5 px-2 hover:bg-slate-800/40 rounded-lg cursor-pointer transition flex items-center justify-between text-xs font-mono"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 text-slate-300">
                      <span className="font-semibold">{pkt.src_ip}</span>
                      <span className="text-slate-500">→</span>
                      <span className="font-semibold text-white">
                        {pkt.dst_ip}:{pkt.dst_port}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-2">
                      <span className="text-cyan-400">{pkt.protocol}</span>
                      <span>·</span>
                      <span>{pkt.length} B</span>
                      <span>·</span>
                      <span className="truncate max-w-[200px] text-slate-400">{pkt.reason}</span>
                    </div>
                  </div>

                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      pkt.classification === 'KNOWN'
                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                        : pkt.classification === 'UNKNOWN'
                        ? 'bg-amber-950/60 text-amber-400 border-amber-800/60'
                        : 'bg-rose-950/60 text-rose-400 border-rose-800/60'
                    }`}
                  >
                    {pkt.classification}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Security Alerts Feed */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Security Alerts
              </h3>
            </div>
            <button
              onClick={() => onNavigate('alerts')}
              className="text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 transition"
            >
              All Alerts ({stats.alertsTotal}) <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 overflow-y-auto max-h-[360px] pr-1">
            {recentAlerts.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No alerts detected. Clean network traffic so far.
              </div>
            ) : (
              recentAlerts.slice(0, 10).map((alert) => (
                <div
                  key={alert.id}
                  className="py-2.5 px-2 hover:bg-slate-800/40 rounded-lg transition text-xs font-mono"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        alert.severity === 'CRITICAL'
                          ? 'bg-purple-950 text-purple-300 border-purple-800'
                          : alert.severity === 'HIGH'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : 'bg-amber-950 text-amber-300 border-amber-800'
                      }`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-[10px] text-slate-500">{alert.timestamp.slice(11)}</span>
                  </div>
                  <div className="text-slate-200 text-xs font-sans font-medium line-clamp-1 mb-1">
                    {alert.message}
                  </div>
                  <div className="text-[11px] text-slate-400 flex items-center gap-2">
                    <span>Src: {alert.src_ip}</span>
                    <span>→</span>
                    <span>
                      Target: {alert.dst_port} ({alert.protocol})
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
