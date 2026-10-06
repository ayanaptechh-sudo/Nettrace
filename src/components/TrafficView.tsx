import React, { useState } from 'react';
import { Search, Filter, Eye, ArrowUpDown, Download, CheckCircle2 } from 'lucide-react';
import { PacketRecord } from '../types';
import { storage } from '../services/storage';

interface TrafficViewProps {
  packets: PacketRecord[];
  onSelectPacket: (packet: PacketRecord) => void;
}

export const TrafficView: React.FC<TrafficViewProps> = ({ packets, onSelectPacket }) => {
  const [search, setSearch] = useState('');
  const [classFilter, setClassFilter] = useState<string>('ALL');
  const [protoFilter, setProtoFilter] = useState<string>('ALL');
  const [sortAsc, setSortAsc] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Filter
  const filtered = packets.filter((p) => {
    if (classFilter !== 'ALL' && p.classification !== classFilter) return false;
    if (protoFilter !== 'ALL' && p.protocol !== protoFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        p.src_ip.includes(q) ||
        p.dst_ip.includes(q) ||
        p.dst_port.toString().includes(q) ||
        p.src_port.toString().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.reason.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const sorted = [...filtered].sort((a, b) => {
    return sortAsc
      ? a.timestamp.localeCompare(b.timestamp)
      : b.timestamp.localeCompare(a.timestamp);
  });

  const copyRow = (pkt: PacketRecord, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(JSON.stringify(pkt, null, 2));
    setCopiedId(pkt.id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const exportCsv = () => {
    const headers = ['Timestamp', 'Src_IP', 'Src_Port', 'Dst_IP', 'Dst_Port', 'Protocol', 'Length_Bytes', 'Classification', 'Reason'];
    const rows = sorted.map((p) => [
      p.timestamp,
      p.src_ip,
      p.src_port,
      p.dst_ip,
      p.dst_port,
      p.protocol,
      p.length,
      p.classification,
      `"${p.reason.replace(/"/g, '""')}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `nettrace_traffic_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-4">
      {/* Search and Filters Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, Port, Protocol, or Anomaly Reason..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
          />
        </div>

        {/* Classification Filter */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          {(['ALL', 'KNOWN', 'UNKNOWN', 'SUSPICIOUS'] as const).map((cls) => (
            <button
              key={cls}
              onClick={() => setClassFilter(cls)}
              className={`px-3 py-1.5 rounded-lg transition ${
                classFilter === cls
                  ? cls === 'KNOWN'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold'
                    : cls === 'UNKNOWN'
                    ? 'bg-amber-950 text-amber-400 border border-amber-800 font-bold'
                    : cls === 'SUSPICIOUS'
                    ? 'bg-rose-950 text-rose-400 border border-rose-800 font-bold'
                    : 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cls}
            </button>
          ))}
        </div>

        {/* Protocol Filter */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          {(['ALL', 'TCP', 'UDP', 'ICMP'] as const).map((proto) => (
            <button
              key={proto}
              onClick={() => setProtoFilter(proto)}
              className={`px-2.5 py-1.5 rounded-lg transition ${
                protoFilter === proto
                  ? 'bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {proto}
            </button>
          ))}
        </div>

        {/* Export CSV */}
        <button
          onClick={exportCsv}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Traffic Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
        <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span className="font-mono">
            Showing <strong className="text-white">{sorted.length}</strong> packets
          </span>
          <button
            onClick={() => setSortAsc(!sortAsc)}
            className="flex items-center gap-1 hover:text-white transition font-mono"
          >
            Sort by Time <ArrowUpDown className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Source</th>
                <th className="py-3 px-4 font-semibold">Destination</th>
                <th className="py-3 px-4 font-semibold">Proto</th>
                <th className="py-3 px-4 font-semibold">Bytes</th>
                <th className="py-3 px-4 font-semibold">Classification</th>
                <th className="py-3 px-4 font-semibold">Classification Reason</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {sorted.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                    No packet records matched the selected query or filter.
                  </td>
                </tr>
              ) : (
                sorted.slice(0, 150).map((pkt) => (
                  <tr
                    key={pkt.id}
                    onClick={() => onSelectPacket(pkt)}
                    className="hover:bg-slate-800/40 cursor-pointer transition group"
                  >
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {pkt.timestamp.slice(11)}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 whitespace-nowrap">
                      {pkt.src_ip}
                      <span className="text-slate-500">:{pkt.src_port}</span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 whitespace-nowrap font-semibold">
                      {pkt.dst_ip}
                      <span className="text-cyan-400">:{pkt.dst_port}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 border border-slate-700">
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 font-semibold">{pkt.length}</td>
                    <td className="py-2.5 px-4">
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
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs">{pkt.reason}</td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={(e) => copyRow(pkt, e)}
                          title="Copy JSON record"
                          className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white transition"
                        >
                          {copiedId === pkt.id ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <span className="text-[10px]">Copy</span>
                          )}
                        </button>
                        <button
                          onClick={() => onSelectPacket(pkt)}
                          className="p-1 rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-400 text-slate-300 transition"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
