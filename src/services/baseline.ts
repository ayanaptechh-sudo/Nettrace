import {
  RISKY_PORTS,
  COMMON_PORTS,
  LEARNING_THRESHOLD,
  ANOMALY_SIGMA,
  MIN_STDDEV_SAMPLES,
  RATE_WINDOW_SECONDS,
  RATE_SPIKE_MULTIPLIER,
  RATE_SPIKE_MIN_PACKETS,
  MAX_BYTE_HISTORY,
  MAX_RATE_SAMPLES,
} from './config';
import { BaselineEntry, AlertRecord, PacketRecord } from '../types';

export function calculateMean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((acc, val) => acc + val, 0) / arr.length;
}

export function calculateStdDev(arr: number[], mean: number): number {
  if (arr.length < 2) return 0;
  const variance = arr.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / arr.length;
  return Math.sqrt(variance);
}

export function formatTimestamp(date: Date = new Date()): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  const year = date.getFullYear();
  const month = pad(date.getMonth() + 1);
  const day = pad(date.getDate());
  const hours = pad(date.getHours());
  const minutes = pad(date.getMinutes());
  const seconds = pad(date.getSeconds());
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

export interface ClassificationResult {
  classification: 'KNOWN' | 'UNKNOWN' | 'SUSPICIOUS';
  reason: string;
  updatedBaseline: BaselineEntry;
  alert?: AlertRecord;
}

export function classifyPacket(
  dst_port: number,
  protocol: 'TCP' | 'UDP' | 'ICMP',
  length: number,
  src_ip: string,
  dst_ip: string,
  existingEntry?: BaselineEntry
): ClassificationResult {
  const nowSec = Date.now() / 1000;
  const nowStr = formatTimestamp();

  // Rule 1: Risky port check
  if (RISKY_PORTS.has(dst_port)) {
    const reason = `Risky port ${dst_port} (${protocol})`;
    const updatedBaseline = updateEntry(existingEntry, dst_port, protocol, length, nowSec, nowStr);
    const alert: AlertRecord = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: nowStr,
      severity: dst_port === 23 || dst_port === 445 || dst_port === 3389 || dst_port === 4444 ? 'HIGH' : 'MEDIUM',
      src_ip,
      dst_ip,
      dst_port,
      protocol,
      message: `Detected traffic on sensitive/risky port ${dst_port} (${protocol})`,
    };
    return {
      classification: 'SUSPICIOUS',
      reason,
      updatedBaseline,
      alert,
    };
  }

  // Rule 3: First-seen port
  if (!existingEntry) {
    const isCommon = COMMON_PORTS.has(dst_port);
    const newEntry: BaselineEntry = {
      dst_port,
      protocol,
      hit_count: 1,
      total_bytes: length,
      byte_history: [length],
      rate_window: [nowSec],
      first_seen: nowStr,
      last_seen: nowStr,
      mean_bytes: length,
      stddev_bytes: 0,
    };

    if (isCommon) {
      return {
        classification: 'KNOWN',
        reason: 'Common service port',
        updatedBaseline: newEntry,
      };
    } else {
      return {
        classification: 'UNKNOWN',
        reason: 'First-seen port — learning',
        updatedBaseline: newEntry,
      };
    }
  }

  // Prune rate window older than RATE_WINDOW_SECONDS
  const cutoff = nowSec - RATE_WINDOW_SECONDS;
  const prunedRateWindow = existingEntry.rate_window.filter((t) => t >= cutoff);
  prunedRateWindow.push(nowSec);
  if (prunedRateWindow.length > MAX_RATE_SAMPLES) {
    prunedRateWindow.shift();
  }

  // Prepare updated history
  const updatedHistory = [...existingEntry.byte_history, length];
  if (updatedHistory.length > MAX_BYTE_HISTORY) {
    updatedHistory.shift();
  }

  const mean = calculateMean(updatedHistory);
  const stddev = calculateStdDev(updatedHistory, mean);

  const updatedBaseline: BaselineEntry = {
    ...existingEntry,
    hit_count: existingEntry.hit_count + 1,
    total_bytes: existingEntry.total_bytes + length,
    byte_history: updatedHistory,
    rate_window: prunedRateWindow,
    last_seen: nowStr,
    mean_bytes: Math.round(mean * 10) / 10,
    stddev_bytes: Math.round(stddev * 10) / 10,
  };

  // Rule 6: Rate spike check
  const ratePerMin = prunedRateWindow.length;
  if (
    existingEntry.hit_count >= LEARNING_THRESHOLD &&
    ratePerMin >= RATE_SPIKE_MIN_PACKETS &&
    ratePerMin > RATE_SPIKE_MULTIPLIER * Math.max(1, existingEntry.hit_count / 10)
  ) {
    const alert: AlertRecord = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: nowStr,
      severity: ratePerMin > 45 ? 'CRITICAL' : 'HIGH',
      src_ip,
      dst_ip,
      dst_port,
      protocol,
      message: `Traffic surge: rate spike detected (${ratePerMin} pkt/min) to port ${dst_port}`,
    };

    return {
      classification: 'SUSPICIOUS',
      reason: `Traffic spike (${ratePerMin} pkt/min from ${src_ip})`,
      updatedBaseline,
      alert,
    };
  }

  // Rule 4: Learning phase
  if (existingEntry.hit_count < LEARNING_THRESHOLD) {
    if (COMMON_PORTS.has(dst_port)) {
      return {
        classification: 'KNOWN',
        reason: 'Common service port (learning)',
        updatedBaseline,
      };
    } else {
      return {
        classification: 'UNKNOWN',
        reason: `Learning phase (${existingEntry.hit_count}/${LEARNING_THRESHOLD})`,
        updatedBaseline,
      };
    }
  }

  // Rule 5: Statistical outlier (Byte-size anomaly)
  if (existingEntry.byte_history.length >= MIN_STDDEV_SAMPLES && existingEntry.stddev_bytes > 0) {
    const z = (length - existingEntry.mean_bytes) / existingEntry.stddev_bytes;
    if (z > ANOMALY_SIGMA) {
      const alert: AlertRecord = {
        id: `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        timestamp: nowStr,
        severity: z > 5.0 ? 'HIGH' : 'MEDIUM',
        src_ip,
        dst_ip,
        dst_port,
        protocol,
        message: `Packet size statistical outlier on port ${dst_port}: length ${length}B (z-score: ${z.toFixed(2)}, mean: ${existingEntry.mean_bytes}B)`,
      };

      return {
        classification: 'UNKNOWN',
        reason: `Byte-size anomaly (z=${z.toFixed(2)} > ${ANOMALY_SIGMA})`,
        updatedBaseline,
        alert,
      };
    }
  }

  // Normal established baseline
  return {
    classification: 'KNOWN',
    reason: 'Baseline established',
    updatedBaseline,
  };
}

function updateEntry(
  existing: BaselineEntry | undefined,
  dst_port: number,
  protocol: string,
  length: number,
  nowSec: number,
  nowStr: string
): BaselineEntry {
  if (!existing) {
    return {
      dst_port,
      protocol,
      hit_count: 1,
      total_bytes: length,
      byte_history: [length],
      rate_window: [nowSec],
      first_seen: nowStr,
      last_seen: nowStr,
      mean_bytes: length,
      stddev_bytes: 0,
    };
  }
  const history = [...existing.byte_history, length].slice(-MAX_BYTE_HISTORY);
  const mean = calculateMean(history);
  const stddev = calculateStdDev(history, mean);
  const window = [...existing.rate_window, nowSec].slice(-MAX_RATE_SAMPLES);
  return {
    ...existing,
    hit_count: existing.hit_count + 1,
    total_bytes: existing.total_bytes + length,
    byte_history: history,
    rate_window: window,
    last_seen: nowStr,
    mean_bytes: Math.round(mean * 10) / 10,
    stddev_bytes: Math.round(stddev * 10) / 10,
  };
}
