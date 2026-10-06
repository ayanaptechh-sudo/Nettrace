import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, Check, ShieldCheck } from 'lucide-react';
import { AlertRecord } from '../types';
import { PORT_NAMES } from '../services/config';

interface AlertsViewProps {
  alerts: AlertRecord[];
}

export const AlertsView: React.FC<AlertsViewProps> = ({ alerts }) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [acknowledged, setAcknowledged] = useState<Set<string>>(new Set());

  const filtered = alerts.filter((a) => {
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    return true;
  });

  const toggleAcknowledge = (id: string) => {
    const updated = new Set(acknowledged);
    if (updated.has(id)) {
      updated.delete(id);
    } else {
      updated.add(id);
    }
    setAcknowledged(updated);
  };

  const getRemediation = (alert: AlertRecord) => {
    if (alert.message.includes('sensitive/risky port')) {
      return `Firewall Recommendation: Block inbound ingress traffic to port ${alert.dst_port} (${PORT_NAMES[alert.dst_port] || alert.protocol}) from unauthenticated sources. Verify whether this host should run listening services.`;
    }
    if (alert.message.includes('rate spike')) {
      return `DDoS / Brute-Force Triage: Host is originating abnormal burst rates (>3x baseline mean). Rate limit source IP ${alert.src_ip} at edge gateway or inspect for automated scanning tool scripts.`;
    }
    if (alert.message.includes('outlier')) {
      return `Exfiltration / Tunneling Audit: Unusually large packet payload exceeding 3σ statistical baseline. Verify if port ${alert.dst_port} is being abused for covert data staging or encapsulation.`;
    }
    return `Inspect host ${alert.src_ip} connection state and cross-reference with security event logging.`;
  };

  return (
    <div className="space-y-4">
      {/* Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-500" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
            Security Alerts Incident Feed
          </h2>
          <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
            {alerts.length} Total
          </span>
        </div>

        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg transition ${
                severityFilter === sev
                  ? sev === 'CRITICAL'
                    ? 'bg-purple-950 text-purple-300 border border-purple-800 font-bold'
                    : sev === 'HIGH'
                    ? 'bg-rose-950 text-rose-300 border border-rose-800 font-bold'
                    : sev === 'MEDIUM'
                    ? 'bg-amber-950 text-amber-300 border border-amber-800 font-bold'
                    : 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Alert Feed Cards */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
            <ShieldCheck className="w-12 h-12 text-emerald-500 mx-auto mb-3 opacity-80" />
            <h3 className="text-sm font-bold text-white mb-1">No Alerts for Current Filter</h3>
            <p className="text-xs text-slate-400">
              Either no threats have triggered or no incidents match the selected severity.
            </p>
          </div>
        ) : (
          filtered.map((alert) => {
            const isAck = acknowledged.has(alert.id);
            const severityColor =
              alert.severity === 'CRITICAL'
                ? 'border-purple-600/60 bg-purple-950/20 text-purple-300'
                : alert.severity === 'HIGH'
                ? 'border-rose-600/60 bg-rose-950/20 text-rose-300'
                : alert.severity === 'MEDIUM'
                ? 'border-amber-600/60 bg-amber-950/20 text-amber-300'
                : 'border-blue-600/60 bg-blue-950/20 text-blue-300';

            const Icon =
              alert.severity === 'CRITICAL' || alert.severity === 'HIGH'
                ? ShieldAlert
                : alert.severity === 'MEDIUM'
                ? AlertTriangle
                : AlertCircle;

            return (
              <div
                key={alert.id}
                className={`bg-slate-900 border rounded-2xl p-4 transition shadow-sm ${
                  isAck ? 'opacity-50 border-slate-800' : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border flex items-center gap-1 font-mono ${severityColor}`}
                    >
                      <Icon className="w-3 h-3" />
                      {alert.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{alert.timestamp}</span>
                  </div>

                  <button
                    onClick={() => toggleAcknowledge(alert.id)}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-mono transition ${
                      isAck
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                    }`}
                  >
                    <Check className="w-3 h-3" />
                    <span>{isAck ? 'Acknowledged' : 'Mark Reviewed'}</span>
                  </button>
                </div>

                <h4 className="text-sm font-semibold text-white mb-2">{alert.message}</h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-slate-950/60 p-3 rounded-xl border border-slate-800/80 font-mono text-xs mb-3">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">
                      Source Attacker / Prober
                    </span>
                    <span className="text-rose-400 font-bold">{alert.src_ip}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">
                      Destination Target Service
                    </span>
                    <span className="text-slate-200">
                      {alert.dst_ip}:{alert.dst_port} ({PORT_NAMES[alert.dst_port] || alert.protocol})
                    </span>
                  </div>
                </div>

                {/* Remediation Box */}
                <div className="bg-slate-800/40 border border-slate-700/50 rounded-xl p-3 text-xs text-slate-300 flex items-start gap-2">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-cyan-400 font-mono mr-1">
                      Actionable Mitigation:
                    </span>
                    {getRemediation(alert)}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
