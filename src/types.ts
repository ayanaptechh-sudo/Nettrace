export interface PacketRecord {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  length: number;
  classification: 'KNOWN' | 'UNKNOWN' | 'SUSPICIOUS';
  reason: string;
}

export interface AlertRecord {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  message: string;
}

export interface BaselineEntry {
  dst_port: number;
  protocol: string;
  hit_count: number;
  total_bytes: number;
  byte_history: number[];
  rate_window: number[]; // Epoch seconds
  first_seen: string;
  last_seen: string;
  mean_bytes: number;
  stddev_bytes: number;
}

export interface TrafficStats {
  total: number;
  known: number;
  unknown: number;
  suspicious: number;
  alertsTotal: number;
  alertsHigh: number;
  alertsMedium: number;
  alertsLow: number;
  totalBytes: number;
  protocolCounts: Record<string, number>;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface ReputationResult {
  ip: string;
  isPrivate: boolean;
  isBogon: boolean;
  score: number; // 0-100 malicious score
  status: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'INTERNAL';
  category: string;
  country?: string;
  asn?: string;
  details: string;
}
