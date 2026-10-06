import React, { useState } from 'react';
import { Scale, Search, CheckCircle2, Clock, AlertTriangle } from 'lucide-react';
import { BaselineEntry } from '../types';
import { PORT_NAMES, LEARNING_THRESHOLD, RISKY_PORTS } from '../services/config';

interface BaselineViewProps {
  baselines: BaselineEntry[];
}

export const BaselineView: React.FC<BaselineViewProps> = ({ baselines }) => {
  const [search, setSearch] = useState('');

  const filtered = baselines.filter((b) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    const portName = (PORT_NAMES[b.dst_port] || '').toLowerCase();
    return (
      b.dst_port.toString().includes(q) ||
      b.protocol.toLowerCase().includes(q) ||
      portName.includes(q)
    );
  });

  return (
    <div className="space-y-4">
      {/* Search and Summary Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Scale className="w-5 h-5 text-cyan-400" />
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Statistical Port Baselines
            </h2>
            <p className="text-xs text-slate-400">
              Profiles dynamically computed per (Destination Port, Protocol) pair
            </p>
          </div>
        </div>

        <div className="relative min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter port or service..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
          />
        </div>
      </div>

      {/* Baselines Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
        <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
          <span>
            Total Profiled Endpoints: <strong className="text-white">{baselines.length}</strong>
          </span>
          <span className="text-slate-500">Learning threshold: {LEARNING_THRESHOLD} packets</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <th className="py-3 px-4 font-semibold">Port & Service</th>
                <th className="py-3 px-4 font-semibold">Protocol</th>
                <th className="py-3 px-4 font-semibold">Hits</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold">Mean Size</th>
                <th className="py-3 px-4 font-semibold">StdDev (σ)</th>
                <th className="py-3 px-4 font-semibold">3σ Upper Bound</th>
                <th className="py-3 px-4 font-semibold">Total Vol</th>
                <th className="py-3 px-4 font-semibold">First / Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500 font-sans">
                    No statistical baselines established yet. Traffic monitoring will populate this table automatically.
                  </td>
                </tr>
              ) : (
                filtered.map((b) => {
                  const isLearning = b.hit_count < LEARNING_THRESHOLD;
                  const isRisky = RISKY_PORTS.has(b.dst_port);
                  const serviceName = PORT_NAMES[b.dst_port] || 'Unknown / Unassigned';
                  const upperBound3Sigma =
                    b.stddev_bytes > 0
                      ? Math.round(b.mean_bytes + 3 * b.stddev_bytes)
                      : 'N/A';

                  return (
                    <tr key={`${b.dst_port}-${b.protocol}`} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white text-sm">
                            {b.dst_port === 0 ? 'ICMP' : b.dst_port}
                          </span>
                          <span className="text-[11px] text-slate-400 font-sans truncate max-w-[150px]">
                            {serviceName}
                          </span>
                          {isRisky && (
                            <span className="text-[9px] bg-rose-950 text-rose-400 border border-rose-800 px-1.5 py-0.2 rounded font-mono font-bold">
                              RISKY
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 border border-slate-700">
                          {b.protocol}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-200 font-semibold">{b.hit_count}</td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {isLearning ? (
                          <div className="flex items-center gap-1.5 text-amber-400">
                            <Clock className="w-3.5 h-3.5" />
                            <span>
                              Learning ({b.hit_count}/{LEARNING_THRESHOLD})
                            </span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5 text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>Established</span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 text-cyan-400 font-semibold">
                        {b.mean_bytes} B
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {b.stddev_bytes > 0 ? `${b.stddev_bytes} B` : '—'}
                      </td>
                      <td className="py-3 px-4 text-purple-400 font-semibold">
                        {typeof upperBound3Sigma === 'number' ? `${upperBound3Sigma} B` : upperBound3Sigma}
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {(b.total_bytes / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-3 px-4 text-[11px] text-slate-400 whitespace-nowrap">
                        <div>First: {b.first_seen.slice(11)}</div>
                        <div className="text-slate-500">Last: {b.last_seen.slice(11)}</div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
