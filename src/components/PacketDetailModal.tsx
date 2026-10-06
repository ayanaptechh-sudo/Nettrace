import React from 'react';
import { X, ShieldCheck, ShieldAlert, HelpCircle, Layers, Server, Hash, FileCode } from 'lucide-react';
import { PacketRecord, BaselineEntry } from '../types';
import { PORT_NAMES, RISKY_PORTS } from '../services/config';
import { storage } from '../services/storage';

interface PacketDetailModalProps {
  packet: PacketRecord | null;
  onClose: () => void;
}

export const PacketDetailModal: React.FC<PacketDetailModalProps> = ({ packet, onClose }) => {
  if (!packet) return null;

  const baseline: BaselineEntry | undefined = storage.getBaseline(
    packet.dst_port,
    packet.protocol
  );

  const isRisky = RISKY_PORTS.has(packet.dst_port);
  const serviceName = PORT_NAMES[packet.dst_port] || 'Unassigned / Dynamic Service';

  const zScore =
    baseline && baseline.stddev_bytes > 0
      ? ((packet.length - baseline.mean_bytes) / baseline.stddev_bytes).toFixed(2)
      : null;

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-slate-800 border border-slate-700">
              {packet.classification === 'KNOWN' ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : packet.classification === 'UNKNOWN' ? (
                <HelpCircle className="w-5 h-5 text-amber-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              )}
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                Packet Inspector
                <span className="text-xs font-normal text-slate-400">({packet.id})</span>
              </h3>
              <p className="text-xs text-slate-400">{packet.timestamp}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Classification Banner */}
        <div
          className={`p-3 rounded-xl border flex items-center justify-between text-xs font-mono ${
            packet.classification === 'KNOWN'
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
              : packet.classification === 'UNKNOWN'
              ? 'bg-amber-950/40 border-amber-800/80 text-amber-300'
              : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
          }`}
        >
          <div>
            <span className="font-bold uppercase tracking-wider block text-[10px]">
              CLASSIFICATION DECISION
            </span>
            <span className="text-sm font-black">{packet.classification}</span>
          </div>
          <span className="text-xs font-sans text-right max-w-[260px]">{packet.reason}</span>
        </div>

        {/* Key Network Fields */}
        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block mb-0.5">
              Source Socket
            </span>
            <div className="font-bold text-slate-200">
              {packet.src_ip}
              <span className="text-slate-400 font-normal">:{packet.src_port}</span>
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block mb-0.5">
              Destination Socket
            </span>
            <div className="font-bold text-white">
              {packet.dst_ip}
              <span className="text-cyan-400">:{packet.dst_port}</span>
            </div>
            <div className="text-[10px] text-slate-400 font-sans mt-0.5 truncate">
              {serviceName}
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block mb-0.5">
              Protocol & Framing
            </span>
            <div className="font-bold text-cyan-400">
              {packet.protocol} <span className="text-slate-400 font-normal">IPv4</span>
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block mb-0.5">
              Captured Payload Size
            </span>
            <div className="font-bold text-slate-200">
              {packet.length} <span className="text-slate-400 font-normal">Bytes</span>
            </div>
          </div>
        </div>

        {/* Baseline Evaluation Metrics */}
        {baseline && (
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs font-mono">
            <span className="text-[10px] text-slate-500 uppercase font-bold block mb-2">
              Learned Baseline Comparison (Port {baseline.dst_port})
            </span>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Baseline Mean</span>
                <span className="text-slate-200 font-bold">{baseline.mean_bytes} B</span>
              </div>
              <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">StdDev (σ)</span>
                <span className="text-slate-200 font-bold">{baseline.stddev_bytes} B</span>
              </div>
              <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Z-Score</span>
                <span
                  className={`font-bold ${
                    zScore && Number(zScore) > 3.0 ? 'text-rose-400' : 'text-emerald-400'
                  }`}
                >
                  {zScore ? `${zScore}σ` : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Metadata-Only Notice */}
        <div className="text-[11px] text-slate-400 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 text-center font-mono">
          🔒 NetTrace stores metadata strictly without packet payload bytes to protect user privacy.
        </div>
      </div>
    </div>
  );
};
