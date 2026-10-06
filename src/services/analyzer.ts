import { AlertRecord, PacketRecord, Protocol } from '../types';
import { db } from './database';
import { classifyPacket } from './baseline';
import { checkIpReputation } from './reputation';
import { nowTimestamp } from '../utils';

export interface IncomingPacketMeta {
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: Protocol;
  length?: number;
}

export class TrafficAnalyzer {
  public analyze(packetInfo: IncomingPacketMeta): PacketRecord {
    const src_ip = packetInfo.src_ip || '192.168.1.100';
    const dst_ip = packetInfo.dst_ip || '192.168.1.1';
    const src_port = Number(packetInfo.src_port) || 0;
    const dst_port = Number(packetInfo.dst_port) || 0;
    const protocol: Protocol = (packetInfo.protocol?.toUpperCase() as Protocol) || 'OTHER';
    const length = Number(packetInfo.length) || 64;

    const config = db.getConfig();
    const existingEntry = db.getBaselineEntry(dst_port, protocol);

    // 1. Core baseline classification
    const { classification: baseClass, reason: baseReason, updatedEntry } = classifyPacket(
      dst_port,
      protocol,
      length,
      src_ip,
      existingEntry,
      config
    );

    let classification = baseClass;
    let reason = baseReason;

    // 2. IP Reputation check
    const rep = checkIpReputation(src_ip, config);
    if (rep.malicious) {
      classification = 'SUSPICIOUS';
      reason = `${reason} | Reputation: ${rep.source} score=${rep.score}`;
    }

    // 3. Persist baseline entry
    db.upsertBaseline(updatedEntry);

    // 4. Record packet
    const record: PacketRecord = {
      timestamp: nowTimestamp(),
      src_ip,
      dst_ip,
      src_port,
      dst_port,
      protocol,
      length,
      classification,
      reason,
    };
    const savedPacket = db.insertPacket(record);

    // 5. Emit alert if necessary
    if (classification === 'SUSPICIOUS') {
      this.alert(savedPacket, 'HIGH');
    } else if (classification === 'UNKNOWN') {
      this.alert(savedPacket, 'MEDIUM');
    }

    return savedPacket;
  }

  private alert(record: PacketRecord, severity: 'HIGH' | 'MEDIUM'): void {
    const alert: AlertRecord = {
      timestamp: record.timestamp,
      severity,
      src_ip: record.src_ip,
      dst_ip: record.dst_ip,
      dst_port: record.dst_port,
      protocol: record.protocol,
      message: `${severity}: ${record.classification} — ${record.reason} (${record.src_ip} → ${record.dst_ip}:${record.dst_port}/${record.protocol}, ${record.length} B)`,
    };
    db.insertAlert(alert);
  }
}

export const analyzer = new TrafficAnalyzer();
