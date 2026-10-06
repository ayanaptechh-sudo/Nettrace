import { AlertRecord, BaselineEntry, PacketRecord, Protocol, Severity, ConfigSettings } from '../types';
import { DEFAULT_CONFIG } from '../config';
import { nowTimestamp } from '../utils';

const STORAGE_KEY_PACKETS = 'nettrace_packets';
const STORAGE_KEY_ALERTS = 'nettrace_alerts';
const STORAGE_KEY_BASELINE = 'nettrace_baseline';
const STORAGE_KEY_CONFIG = 'nettrace_config';

class DatabaseService {
  private packets: PacketRecord[] = [];
  private alerts: AlertRecord[] = [];
  private baselineMap = new Map<string, BaselineEntry>();
  private config: ConfigSettings = { ...DEFAULT_CONFIG };
  private listeners: Set<() => void> = new Set();
  private initialized = false;

  constructor() {
    this.init();
  }

  public init(): void {
    if (this.initialized) return;

    try {
      const storedConfig = localStorage.getItem(STORAGE_KEY_CONFIG);
      if (storedConfig) {
        this.config = { ...DEFAULT_CONFIG, ...JSON.parse(storedConfig) };
      }

      const storedPackets = localStorage.getItem(STORAGE_KEY_PACKETS);
      if (storedPackets) {
        this.packets = JSON.parse(storedPackets);
      }

      const storedAlerts = localStorage.getItem(STORAGE_KEY_ALERTS);
      if (storedAlerts) {
        this.alerts = JSON.parse(storedAlerts);
      }

      const storedBaseline = localStorage.getItem(STORAGE_KEY_BASELINE);
      if (storedBaseline) {
        const list: BaselineEntry[] = JSON.parse(storedBaseline);
        list.forEach((b) => {
          this.baselineMap.set(`${b.dst_port}:${b.protocol}`, b);
        });
      }
    } catch (e) {
      console.warn('Could not load storage, using in-memory defaults:', e);
    }

    if (this.packets.length === 0) {
      this.seedInitialData();
    }

    this.initialized = true;
  }

  public subscribe(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  private notify(): void {
    this.saveToStorage();
    this.listeners.forEach((cb) => {
      try {
        cb();
      } catch (err) {
        console.error('Listener callback error:', err);
      }
    });
  }

  private saveToStorage(): void {
    try {
      localStorage.setItem(STORAGE_KEY_CONFIG, JSON.stringify(this.config));
      // store last 300 packets and alerts in localStorage to preserve performance
      localStorage.setItem(STORAGE_KEY_PACKETS, JSON.stringify(this.packets.slice(0, 300)));
      localStorage.setItem(STORAGE_KEY_ALERTS, JSON.stringify(this.alerts.slice(0, 200)));
      localStorage.setItem(STORAGE_KEY_BASELINE, JSON.stringify(Array.from(this.baselineMap.values())));
    } catch (e) {
      // localStorage quota or private mode protection
    }
  }

  public getConfig(): ConfigSettings {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<ConfigSettings>): void {
    this.config = { ...this.config, ...newConfig };
    this.notify();
  }

  // ─── Packets ────────────────────────────────────────────────────────
  public insertPacket(p: PacketRecord): PacketRecord {
    const record: PacketRecord = {
      ...p,
      id: (this.packets[0]?.id || 0) + 1,
    };
    this.packets.unshift(record);
    if (this.packets.length > 1000) {
      this.packets = this.packets.slice(0, 1000);
    }
    this.notify();
    return record;
  }

  public getRecentPackets(limit = 100): PacketRecord[] {
    return this.packets.slice(0, limit);
  }

  public getPacketStats(): { total: number; known: number; unknown: number; suspicious: number } {
    let known = 0;
    let unknown = 0;
    let suspicious = 0;

    for (const p of this.packets) {
      if (p.classification === 'KNOWN') known++;
      else if (p.classification === 'UNKNOWN') unknown++;
      else if (p.classification === 'SUSPICIOUS') suspicious++;
    }

    return {
      total: this.packets.length,
      known,
      unknown,
      suspicious,
    };
  }

  public getProtocolStats(): { protocol: Protocol; count: number }[] {
    const counts: Record<string, number> = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
    for (const p of this.packets) {
      counts[p.protocol] = (counts[p.protocol] || 0) + 1;
    }
    return (Object.keys(counts) as Protocol[])
      .map((proto) => ({ protocol: proto, count: counts[proto] }))
      .sort((a, b) => b.count - a.count);
  }

  public getTopUnknownSources(limit = 20): { src_ip: string; count: number }[] {
    const counts: Record<string, number> = {};
    for (const p of this.packets) {
      if (p.classification === 'UNKNOWN' || p.classification === 'SUSPICIOUS') {
        counts[p.src_ip] = (counts[p.src_ip] || 0) + 1;
      }
    }
    return Object.entries(counts)
      .map(([src_ip, count]) => ({ src_ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  // ─── Alerts ─────────────────────────────────────────────────────────
  public insertAlert(a: AlertRecord): AlertRecord {
    const record: AlertRecord = {
      ...a,
      id: (this.alerts[0]?.id || 0) + 1,
      resolved: false,
    };
    this.alerts.unshift(record);
    if (this.alerts.length > 500) {
      this.alerts = this.alerts.slice(0, 500);
    }
    this.notify();
    return record;
  }

  public getRecentAlerts(limit = 100): AlertRecord[] {
    return this.alerts.slice(0, limit);
  }

  public getAlertCountsBySeverity(): Record<Severity, number> {
    const counts: Record<Severity, number> = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };
    for (const a of this.alerts) {
      if (counts[a.severity] !== undefined) {
        counts[a.severity]++;
      }
    }
    return counts;
  }

  public resolveAlert(id: number): void {
    const alert = this.alerts.find((a) => a.id === id);
    if (alert) {
      alert.resolved = true;
      this.notify();
    }
  }

  public clearAlerts(): void {
    this.alerts = [];
    this.notify();
  }

  // ─── Baseline ───────────────────────────────────────────────────────
  public getBaselineEntry(dst_port: number, protocol: Protocol): BaselineEntry | null {
    const entry = this.baselineMap.get(`${dst_port}:${protocol}`);
    return entry ? { ...entry } : null;
  }

  public upsertBaseline(entry: BaselineEntry): void {
    const key = `${entry.dst_port}:${entry.protocol}`;
    this.baselineMap.set(key, { ...entry });
    this.notify();
  }

  public getAllBaseline(): BaselineEntry[] {
    return Array.from(this.baselineMap.values()).sort((a, b) => b.hit_count - a.hit_count);
  }

  // ─── Maintenance ────────────────────────────────────────────────────
  public clearAll(): void {
    this.packets = [];
    this.alerts = [];
    this.baselineMap.clear();
    localStorage.removeItem(STORAGE_KEY_PACKETS);
    localStorage.removeItem(STORAGE_KEY_ALERTS);
    localStorage.removeItem(STORAGE_KEY_BASELINE);
    this.notify();
  }

  // ─── Seed Data for Realistic Demo ──────────────────────────────────
  public seedInitialData(): void {
    const now = Date.now();
    const ports = [
      { port: 443, proto: 'TCP' as Protocol, hits: 84, baseBytes: 1250 },
      { port: 80, proto: 'TCP' as Protocol, hits: 28, baseBytes: 820 },
      { port: 53, proto: 'UDP' as Protocol, hits: 45, baseBytes: 128 },
      { port: 22, proto: 'TCP' as Protocol, hits: 18, baseBytes: 512 },
      { port: 123, proto: 'UDP' as Protocol, hits: 12, baseBytes: 90 },
      { port: 8443, proto: 'TCP' as Protocol, hits: 7, baseBytes: 1400 },
      { port: 50505, proto: 'TCP' as Protocol, hits: 3, baseBytes: 420 }, // Learning
      { port: 23, proto: 'TCP' as Protocol, hits: 4, baseBytes: 64 }, // Risky port
      { port: 3389, proto: 'TCP' as Protocol, hits: 2, baseBytes: 180 }, // Risky port
    ];

    ports.forEach((p, idx) => {
      const byteHistory: number[] = [];
      const rateWindow: number[] = [];
      for (let i = 0; i < Math.min(p.hits, 40); i++) {
        const jitter = Math.floor((Math.random() - 0.5) * 120);
        byteHistory.push(Math.max(40, p.baseBytes + jitter));
        rateWindow.push(now / 1000 - (40 - i) * 15);
      }

      const totalBytes = byteHistory.reduce((a, b) => a + b, 0);
      const timePast = new Date(now - (idx + 1) * 3600000).toISOString().replace('T', ' ').substring(0, 19);

      this.baselineMap.set(`${p.port}:${p.proto}`, {
        id: idx + 1,
        dst_port: p.port,
        protocol: p.proto,
        hit_count: p.hits,
        total_bytes: totalBytes,
        byte_history: byteHistory,
        rate_window: rateWindow,
        first_seen: timePast,
        last_seen: nowTimestamp(),
      });
    });

    // Seed recent packets
    const samplePackets: {
      src: string;
      dst: string;
      sPort: number;
      dPort: number;
      proto: Protocol;
      len: number;
      cls: 'KNOWN' | 'UNKNOWN' | 'SUSPICIOUS';
      reason: string;
      agoMins: number;
    }[] = [
      { src: '185.220.101.5', dst: '192.168.1.105', sPort: 48921, dPort: 23, proto: 'TCP', len: 64, cls: 'SUSPICIOUS', reason: 'Risky port 23 (TCP) | Reputation: ThreatIntel score=95', agoMins: 1 },
      { src: '192.168.1.105', dst: '142.250.190.46', sPort: 52140, dPort: 443, proto: 'TCP', len: 1248, cls: 'KNOWN', reason: 'Baseline established', agoMins: 2 },
      { src: '10.0.0.45', dst: '192.168.1.105', sPort: 59310, dPort: 50505, proto: 'TCP', len: 410, cls: 'UNKNOWN', reason: 'Learning phase (3/5)', agoMins: 3 },
      { src: '192.168.1.105', dst: '8.8.8.8', sPort: 61002, dPort: 53, proto: 'UDP', len: 142, cls: 'KNOWN', reason: 'Baseline established', agoMins: 4 },
      { src: '194.26.29.112', dst: '192.168.1.105', sPort: 37190, dPort: 3389, proto: 'TCP', len: 180, cls: 'SUSPICIOUS', reason: 'Risky port 3389 (TCP)', agoMins: 5 },
      { src: '192.168.1.105', dst: '172.217.16.206', sPort: 53210, dPort: 443, proto: 'TCP', len: 1180, cls: 'KNOWN', reason: 'Baseline established', agoMins: 6 },
      { src: '10.0.0.88', dst: '192.168.1.105', sPort: 51230, dPort: 80, proto: 'TCP', len: 850, cls: 'KNOWN', reason: 'Baseline established', agoMins: 7 },
      { src: '10.0.0.12', dst: '192.168.1.105', sPort: 0, dPort: 0, proto: 'ICMP', len: 84, cls: 'KNOWN', reason: 'Common service port', agoMins: 8 },
      { src: '10.0.0.99', dst: '192.168.1.105', sPort: 49102, dPort: 9999, proto: 'TCP', len: 320, cls: 'UNKNOWN', reason: 'First-seen port — learning', agoMins: 9 },
    ];

    samplePackets.forEach((p, idx) => {
      const ts = new Date(now - p.agoMins * 60000).toISOString().replace('T', ' ').substring(0, 19);
      const record: PacketRecord = {
        id: samplePackets.length - idx,
        timestamp: ts,
        src_ip: p.src,
        dst_ip: p.dst,
        src_port: p.sPort,
        dst_port: p.dPort,
        protocol: p.proto,
        length: p.len,
        classification: p.cls,
        reason: p.reason,
      };
      this.packets.push(record);

      if (p.cls === 'SUSPICIOUS') {
        this.alerts.push({
          id: this.alerts.length + 1,
          timestamp: ts,
          severity: 'HIGH',
          src_ip: p.src,
          dst_ip: p.dst,
          dst_port: p.dPort,
          protocol: p.proto,
          message: `HIGH: ${p.cls} — ${p.reason} (${p.src} → ${p.dst}:${p.dPort}/${p.proto}, ${p.len} B)`,
        });
      } else if (p.cls === 'UNKNOWN') {
        this.alerts.push({
          id: this.alerts.length + 1,
          timestamp: ts,
          severity: 'MEDIUM',
          src_ip: p.src,
          dst_ip: p.dst,
          dst_port: p.dPort,
          protocol: p.proto,
          message: `MEDIUM: ${p.cls} — ${p.reason} (${p.src} → ${p.dst}:${p.dPort}/${p.proto}, ${p.len} B)`,
        });
      }
    });

    this.saveToStorage();
  }
}

export const db = new DatabaseService();
