import React, { useState } from 'react';
import {
  Crosshair,
  Search,
  ShieldCheck,
  ShieldAlert,
  Send,
  Zap,
  Globe,
  Radio,
  Sliders,
  CheckCircle,
} from 'lucide-react';
import { checkIpReputation } from '../services/reputation';
import { ReputationResult } from '../types';
import { trafficEngine } from '../services/trafficEngine';
import { PORT_NAMES } from '../services/config';

interface ThreatIntelViewProps {
  onPacketInjected: () => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({ onPacketInjected }) => {
  // IP query state
  const [queryIp, setQueryIp] = useState('185.220.101.5');
  const [ipResult, setIpResult] = useState<ReputationResult | null>(() =>
    checkIpReputation('185.220.101.5')
  );

  // Manual packet crafting state
  const [srcIp, setSrcIp] = useState('192.168.1.105');
  const [dstIp, setDstIp] = useState('142.250.190.46');
  const [dstPort, setDstPort] = useState(443);
  const [protocol, setProtocol] = useState<'TCP' | 'UDP' | 'ICMP'>('TCP');
  const [length, setLength] = useState(720);
  const [lastInjectedResult, setLastInjectedResult] = useState<any | null>(null);

  const handleLookup = () => {
    if (!queryIp.trim()) return;
    const res = checkIpReputation(queryIp.trim());
    setIpResult(res);
  };

  const handleQuickLookup = (ip: string) => {
    setQueryIp(ip);
    const res = checkIpReputation(ip);
    setIpResult(res);
  };

  const handleInjectPacket = (e: React.FormEvent) => {
    e.preventDefault();
    const pkt = trafficEngine.injectPacket(
      srcIp,
      dstIp,
      Number(dstPort),
      protocol,
      Number(length)
    );
    setLastInjectedResult(pkt);
    onPacketInjected();
  };

  return (
    <div className="space-y-6">
      {/* 1. IP Threat Reputation Lookup */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <Globe className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white tracking-tight">
            IP Threat Intelligence & Reputation Analyzer
          </h2>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          Query suspicious source/destination IP addresses against private RFC-1918 space, bogon allocations, and known malicious threat actors.
        </p>

        {/* Input & Quick Chips */}
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <div className="relative flex-1 min-w-[280px]">
            <input
              type="text"
              value={queryIp}
              onChange={(e) => setQueryIp(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
              placeholder="Enter IPv4 Address (e.g. 185.220.101.5)..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={handleLookup}
            className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs font-mono transition flex items-center gap-2"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Check IP</span>
          </button>
        </div>

        {/* Quick Example Chips */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 mb-5">
          <span className="text-[11px] text-slate-500">Quick Test Samples:</span>
          {[
            { ip: '185.220.101.5', label: 'Tor Scanner' },
            { ip: '91.240.118.234', label: 'Mirai C2' },
            { ip: '45.33.32.156', label: 'Nmap Scanme' },
            { ip: '8.8.8.8', label: 'Google DNS' },
            { ip: '192.168.1.1', label: 'Local LAN' },
          ].map((sample) => (
            <button
              key={sample.ip}
              onClick={() => handleQuickLookup(sample.ip)}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 hover:text-white border border-slate-700/60 transition text-[11px]"
            >
              {sample.ip} <span className="text-slate-500">({sample.label})</span>
            </button>
          ))}
        </div>

        {/* Result Card */}
        {ipResult && (
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 font-mono text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-white">{ipResult.ip}</span>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
                    ipResult.status === 'CLEAN'
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      : ipResult.status === 'INTERNAL'
                      ? 'bg-blue-950 text-blue-400 border-blue-800'
                      : ipResult.status === 'SUSPICIOUS'
                      ? 'bg-amber-950 text-amber-400 border-amber-800'
                      : 'bg-rose-950 text-rose-400 border-rose-800'
                  }`}
                >
                  {ipResult.status} ({ipResult.score}/100)
                </span>
              </div>
              <span className="text-slate-400 text-[11px]">
                Category: <strong className="text-white">{ipResult.category}</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 bg-slate-900/60 rounded-lg border border-slate-800/80 mb-2">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Address Class</span>
                <span className="text-slate-200">
                  {ipResult.isPrivate ? 'RFC-1918 Private' : 'Public Routable'}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Country / Geo</span>
                <span className="text-slate-200">{ipResult.country || 'N/A'}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Bogon Status</span>
                <span className={ipResult.isBogon ? 'text-rose-400' : 'text-emerald-400'}>
                  {ipResult.isBogon ? 'BOGON / RESERVED' : 'Allocated Space'}
                </span>
              </div>
            </div>

            <div className="text-slate-300 font-sans text-xs pt-1">{ipResult.details}</div>
          </div>
        )}
      </div>

      {/* 2. Manual Packet Crafting & Injection Sandbox */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <Crosshair className="w-5 h-5 text-purple-400" />
          <h2 className="text-base font-bold text-white tracking-tight">
            Manual Packet Injector & Baseline Rule Verifier
          </h2>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          Craft arbitrary packet metadata to test how NetTrace's statistical baseline rules (Risky Port, First-seen, Rate spike, Byte outlier, Learning phase) react in real time.
        </p>

        <form onSubmit={handleInjectPacket} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 font-mono text-xs">
            <div>
              <label className="block text-slate-400 text-[11px] mb-1">Source IP</label>
              <input
                type="text"
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 text-[11px] mb-1">Destination IP</label>
              <input
                type="text"
                value={dstIp}
                onChange={(e) => setDstIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 text-[11px] mb-1">
                Dest Port <span className="text-slate-500">(0 = ICMP)</span>
              </label>
              <input
                type="number"
                value={dstPort}
                onChange={(e) => setDstPort(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 text-[11px] mb-1">Protocol</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 text-[11px] mb-1">Payload Length (Bytes)</label>
              <input
                type="number"
                value={length}
                onChange={(e) => setLength(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Quick Preset:</span>
              <button
                type="button"
                onClick={() => {
                  setDstPort(23);
                  setProtocol('TCP');
                  setLength(64);
                }}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-rose-300"
              >
                Port 23 (Telnet Risky)
              </button>
              <button
                type="button"
                onClick={() => {
                  setDstPort(9999);
                  setProtocol('TCP');
                  setLength(256);
                }}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-amber-300"
              >
                Port 9999 (First Seen)
              </button>
              <button
                type="button"
                onClick={() => {
                  setDstPort(443);
                  setProtocol('TCP');
                  setLength(14500);
                }}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-purple-300"
              >
                443 (Giant Outlier 14KB)
              </button>
            </div>

            <button
              type="submit"
              className="px-5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs font-mono transition flex items-center gap-2 shadow-lg shadow-purple-950/30"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Inject Packet Now</span>
            </button>
          </div>
        </form>

        {/* Injection Evaluation Feedback */}
        {lastInjectedResult && (
          <div className="mt-4 bg-slate-950 border border-purple-900/60 rounded-xl p-4 font-mono text-xs">
            <div className="flex items-center justify-between mb-2">
              <span className="text-purple-400 font-bold flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                Packet Injected & Evaluated
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  lastInjectedResult.classification === 'KNOWN'
                    ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                    : lastInjectedResult.classification === 'UNKNOWN'
                    ? 'bg-amber-950 text-amber-400 border-amber-800'
                    : 'bg-rose-950 text-rose-400 border-rose-800'
                }`}
              >
                {lastInjectedResult.classification}
              </span>
            </div>
            <div className="text-slate-300 font-sans text-xs">
              <strong>Evaluation Result:</strong> {lastInjectedResult.reason}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
