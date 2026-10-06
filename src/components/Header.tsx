import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  Square,
  RefreshCw,
  FileText,
  FileCode,
  Trash2,
  Zap,
  ChevronDown,
  Gauge,
} from 'lucide-react';
import { trafficEngine } from '../services/trafficEngine';
import { downloadHtmlReport, openPrintReport } from '../services/reportGenerator';
import { storage } from '../services/storage';

interface HeaderProps {
  isRunning: boolean;
  setIsRunning: (running: boolean) => void;
  onRefresh: () => void;
  packetRate: number;
}

export const Header: React.FC<HeaderProps> = ({
  isRunning,
  setIsRunning,
  onRefresh,
  packetRate,
}) => {
  const [speed, setSpeed] = useState<number>(1000);
  const [showSimMenu, setShowSimMenu] = useState(false);
  const [showConfirmReset, setShowConfirmReset] = useState(false);

  const toggleCapture = () => {
    if (isRunning) {
      trafficEngine.stop();
      setIsRunning(false);
    } else {
      trafficEngine.start();
      setIsRunning(true);
    }
  };

  const handleSpeedChange = (newSpeed: number) => {
    setSpeed(newSpeed);
    trafficEngine.setSpeed(newSpeed);
  };

  const handleResetDb = () => {
    storage.resetDb();
    setShowConfirmReset(false);
    onRefresh();
  };

  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur px-5 py-3 sticky top-0 z-30 flex flex-wrap items-center justify-between gap-4">
      {/* Brand & Status */}
      <div className="flex items-center gap-3">
        <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 shadow-lg shadow-cyan-500/20 text-white font-bold">
          <ShieldAlert className="w-6 h-6 text-white" />
          {isRunning && (
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
            </span>
          )}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-bold text-lg tracking-tight text-white flex items-center gap-2">
              NetTrace
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-normal">
                v1.0.0
              </span>
            </h1>
            <div
              className={`flex items-center gap-1.5 text-xs font-mono font-medium px-2.5 py-0.5 rounded-full border ${
                isRunning
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/80'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  isRunning ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                }`}
              />
              {isRunning ? 'SNIFFING' : 'IDLE'}
            </div>
          </div>
          <p className="text-xs text-slate-400 hidden sm:block">
            Network Security Baseline & Unknown Traffic Detector
          </p>
        </div>
      </div>

      {/* Main Actions Bar */}
      <div className="flex items-center flex-wrap gap-2">
        {/* Speed Selector */}
        <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1 text-xs text-slate-300">
          <Gauge className="w-3.5 h-3.5 mx-1.5 text-slate-500" />
          <button
            onClick={() => handleSpeedChange(2000)}
            className={`px-2 py-0.5 rounded transition ${
              speed === 2000 ? 'bg-slate-800 text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            0.5x
          </button>
          <button
            onClick={() => handleSpeedChange(1000)}
            className={`px-2 py-0.5 rounded transition ${
              speed === 1000 ? 'bg-slate-800 text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            1x
          </button>
          <button
            onClick={() => handleSpeedChange(300)}
            className={`px-2 py-0.5 rounded transition ${
              speed === 300 ? 'bg-slate-800 text-cyan-400 font-semibold' : 'hover:text-white'
            }`}
          >
            3x
          </button>
        </div>

        {/* Start / Stop Button */}
        <button
          onClick={toggleCapture}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-medium text-xs shadow transition active:scale-95 ${
            isRunning
              ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-900/30'
              : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-900/30'
          }`}
        >
          {isRunning ? (
            <>
              <Square className="w-3.5 h-3.5 fill-current" /> Stop
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" /> Start Monitoring
            </>
          )}
        </button>

        {/* Refresh */}
        <button
          onClick={onRefresh}
          title="Reload data from database"
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Refresh</span>
        </button>

        {/* Attack / Anomaly Trigger Menu */}
        <div className="relative">
          <button
            onClick={() => setShowSimMenu(!showSimMenu)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-600/50 bg-amber-950/40 hover:bg-amber-900/50 text-amber-300 text-xs font-medium transition"
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Simulate Anomaly</span>
            <ChevronDown className="w-3 h-3 text-amber-400" />
          </button>

          {showSimMenu && (
            <div
              className="absolute right-0 mt-1 w-56 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-1.5 z-50 text-xs"
              onMouseLeave={() => setShowSimMenu(false)}
            >
              <div className="px-2 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Trigger Test Anomaly
              </div>
              <button
                onClick={() => {
                  trafficEngine.simulatePortScan();
                  setShowSimMenu(false);
                }}
                className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-200 flex items-center justify-between"
              >
                <span>Port Scan Probe</span>
                <span className="text-[10px] text-rose-400 font-mono">Risky Ports</span>
              </button>
              <button
                onClick={() => {
                  trafficEngine.simulateTrafficSpike();
                  setShowSimMenu(false);
                }}
                className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-200 flex items-center justify-between"
              >
                <span>Rate Spike Burst</span>
                <span className="text-[10px] text-amber-400 font-mono">Rule 6 Spike</span>
              </button>
              <button
                onClick={() => {
                  trafficEngine.simulateByteSizeAnomaly();
                  setShowSimMenu(false);
                }}
                className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-200 flex items-center justify-between"
              >
                <span>Payload Size Outlier</span>
                <span className="text-[10px] text-purple-400 font-mono">z-score &gt; 3.0</span>
              </button>
              <button
                onClick={() => {
                  trafficEngine.simulateUnknownService();
                  setShowSimMenu(false);
                }}
                className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-200 flex items-center justify-between"
              >
                <span>Unknown Port (9999)</span>
                <span className="text-[10px] text-cyan-400 font-mono">First-seen</span>
              </button>
            </div>
          )}
        </div>

        {/* Generate Reports */}
        <button
          onClick={openPrintReport}
          title="Printable / PDF Report"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
        >
          <FileText className="w-3.5 h-3.5 text-rose-400" />
          <span className="hidden sm:inline">PDF Report</span>
        </button>

        <button
          onClick={downloadHtmlReport}
          title="Export Standalone HTML Report"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
        >
          <FileCode className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">HTML Report</span>
        </button>

        {/* Reset DB */}
        <button
          onClick={() => setShowConfirmReset(true)}
          title="Reset database (clear all packets, alerts, baselines)"
          className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-rose-950/60 hover:border-rose-900 text-slate-400 hover:text-rose-400 transition"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>

      {/* Confirmation Modal for Reset DB */}
      {showConfirmReset && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-sm w-full p-5 shadow-2xl">
            <h3 className="text-base font-bold text-white mb-2 flex items-center gap-2">
              <Trash2 className="w-4 h-4 text-rose-500" /> Reset Database?
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              This will erase all recorded packets, security alerts, and learned port statistical baselines. This matches the <code className="text-cyan-400">reset_db()</code> function from NetTrace.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowConfirmReset(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:bg-slate-800 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleResetDb}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-rose-600 hover:bg-rose-500 text-white transition"
              >
                Yes, Reset All Data
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
