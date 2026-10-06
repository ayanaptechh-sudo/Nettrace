import { PacketRecord, AlertRecord, BaselineEntry, TrafficStats } from '../types';
import {
  RISK_WEIGHT_SUSPICIOUS,
  RISK_WEIGHT_UNKNOWN,
  RISK_WEIGHT_ALERT_HIGH,
  RISK_WEIGHT_ALERT_MEDIUM,
  RISK_LOW_MAX,
  RISK_MEDIUM_MAX,
} from './config';

const STORAGE_KEY_PACKETS = 'nettrace_packets';
const STORAGE_KEY_ALERTS = 'nettrace_alerts';
const STORAGE_KEY_BASELINES = 'nettrace_baselines';

class NetTraceStorage {
  private packets: PacketRecord[] = [];
  private alerts: AlertRecord[] = [];
  private baselines: Map<string, BaselineEntry> = new Map();
  private isLoaded = false;

  constructor() {
    this.loadFromStorage();
  }

  private getKey(dst_port: number, protocol: string): string {
    return `${dst_port}_${protocol.toUpperCase()}`;
  }

  private loadFromStorage() {
    try {
      const storedPackets = localStorage.getItem(STORAGE_KEY_PACKETS);
      if (storedPackets) {
        this.packets = JSON.parse(storedPackets);
      }

      const storedAlerts = localStorage.getItem(STORAGE_KEY_ALERTS);
      if (storedAlerts) {
        this.alerts = JSON.parse(storedAlerts);
      }

      const storedBaselines = localStorage.getItem(STORAGE_KEY_BASELINES);
      if (storedBaselines) {
        const rawBaselines: BaselineEntry[] = JSON.parse(storedBaselines);
        this.baselines.clear();
        rawBaselines.forEach((b) => {
          this.baselines.set(this.getKey(b.dst_port, b.protocol), b);
        });
      }
      this.isLoaded = true;
    } catch (e) {
      console.warn('Could not load NetTrace state from storage, using memory:', e);
      this.packets = [];
      this.alerts = [];
      this.baselines = new Map();
    }
  }

  private saveToStorage() {
    try {
      // Keep most recent 500 packets in local storage to stay within quotas
      const savedPackets = this.packets.slice(0, 500);
      localStorage.setItem(STORAGE_KEY_PACKETS, JSON.stringify(savedPackets));

      const savedAlerts = this.alerts.slice(0, 300);
      localStorage.setItem(STORAGE_KEY_ALERTS, JSON.stringify(savedAlerts));

      const baselineList = Array.from(this.baselines.values());
      localStorage.setItem(STORAGE_KEY_BASELINES, JSON.stringify(baselineList));
    } catch (e) {
      console.warn('Storage save error:', e);
    }
  }

  public insertPacket(packet: PacketRecord): void {
    this.packets.unshift(packet);
    if (this.packets.length > 2000) {
      this.packets.pop();
    }
    this.saveToStorage();
  }

  public insertAlert(alert: AlertRecord): void {
    this.alerts.unshift(alert);
    if (this.alerts.length > 1000) {
      this.alerts.pop();
    }
    this.saveToStorage();
  }

  public upsertBaseline(entry: BaselineEntry): void {
    this.baselines.set(this.getKey(entry.dst_port, entry.protocol), entry);
    this.saveToStorage();
  }

  public getBaseline(dst_port: number, protocol: string): BaselineEntry | undefined {
    return this.baselines.get(this.getKey(dst_port, protocol));
  }

  public getAllBaselines(): BaselineEntry[] {
    return Array.from(this.baselines.values()).sort((a, b) => b.hit_count - a.hit_count);
  }

  public getPackets(filter?: {
    classification?: string;
    protocol?: string;
    query?: string;
    limit?: number;
  }): PacketRecord[] {
    let result = this.packets;

    if (filter?.classification && filter.classification !== 'ALL') {
      result = result.filter((p) => p.classification === filter.classification);
    }

    if (filter?.protocol && filter.protocol !== 'ALL') {
      result = result.filter((p) => p.protocol === filter.protocol);
    }

    if (filter?.query && filter.query.trim()) {
      const q = filter.query.toLowerCase().trim();
      result = result.filter(
        (p) =>
          p.src_ip.includes(q) ||
          p.dst_ip.includes(q) ||
          p.dst_port.toString().includes(q) ||
          p.src_port.toString().includes(q) ||
          p.reason.toLowerCase().includes(q) ||
          p.protocol.toLowerCase().includes(q)
      );
    }

    if (filter?.limit) {
      return result.slice(0, filter.limit);
    }

    return result;
  }

  public getAlerts(filter?: { severity?: string; query?: string; limit?: number }): AlertRecord[] {
    let result = this.alerts;

    if (filter?.severity && filter.severity !== 'ALL') {
      result = result.filter((a) => a.severity === filter.severity);
    }

    if (filter?.query && filter.query.trim()) {
      const q = filter.query.toLowerCase().trim();
      result = result.filter(
        (a) =>
          a.src_ip.includes(q) ||
          a.dst_ip.includes(q) ||
          a.message.toLowerCase().includes(q) ||
          a.dst_port.toString().includes(q)
      );
    }

    if (filter?.limit) {
      return result.slice(0, filter.limit);
    }

    return result;
  }

  public getStats(): TrafficStats {
    let known = 0;
    let unknown = 0;
    let suspicious = 0;
    let totalBytes = 0;
    const protocolCounts: Record<string, number> = { TCP: 0, UDP: 0, ICMP: 0 };

    for (const p of this.packets) {
      if (p.classification === 'KNOWN') known++;
      else if (p.classification === 'UNKNOWN') unknown++;
      else if (p.classification === 'SUSPICIOUS') suspicious++;

      totalBytes += p.length;
      protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
    }

    let alertsHigh = 0;
    let alertsMedium = 0;
    let alertsLow = 0;

    for (const a of this.alerts) {
      if (a.severity === 'CRITICAL' || a.severity === 'HIGH') alertsHigh++;
      else if (a.severity === 'MEDIUM') alertsMedium++;
      else alertsLow++;
    }

    // Exact formula from config.py / report_pdf.py / report_html.py:
    // risk_score = (SUSPICIOUS * 10) + (UNKNOWN * 3) + (HIGH_alerts * 8) + (MEDIUM_alerts * 3)
    const riskScore =
      suspicious * RISK_WEIGHT_SUSPICIOUS +
      unknown * RISK_WEIGHT_UNKNOWN +
      alertsHigh * RISK_WEIGHT_ALERT_HIGH +
      alertsMedium * RISK_WEIGHT_ALERT_MEDIUM;

    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (riskScore > RISK_MEDIUM_MAX * 2) {
      riskLevel = 'CRITICAL';
    } else if (riskScore > RISK_MEDIUM_MAX) {
      riskLevel = 'HIGH';
    } else if (riskScore > RISK_LOW_MAX) {
      riskLevel = 'MEDIUM';
    }

    return {
      total: this.packets.length,
      known,
      unknown,
      suspicious,
      alertsTotal: this.alerts.length,
      alertsHigh,
      alertsMedium,
      alertsLow,
      totalBytes,
      protocolCounts,
      riskScore,
      riskLevel,
    };
  }

  public resetDb(): void {
    this.packets = [];
    this.alerts = [];
    this.baselines.clear();
    localStorage.removeItem(STORAGE_KEY_PACKETS);
    localStorage.removeItem(STORAGE_KEY_ALERTS);
    localStorage.removeItem(STORAGE_KEY_BASELINES);
  }

  public exportJson(): string {
    return JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        version: '1.0.0',
        packets: this.packets,
        alerts: this.alerts,
        baselines: Array.from(this.baselines.values()),
        stats: this.getStats(),
      },
      null,
      2
    );
  }
}

export const storage = new NetTraceStorage();
