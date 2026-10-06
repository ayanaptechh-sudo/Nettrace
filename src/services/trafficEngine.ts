import { PacketRecord } from '../types';
import { classifyPacket, formatTimestamp } from './baseline';
import { storage } from './storage';

export type PacketCallback = (packet: PacketRecord) => void;

class TrafficEngine {
  private isRunning = false;
  private intervalId: any = null;
  private subscribers: Set<PacketCallback> = new Set();
  private captureSpeed = 1000; // ms between packets

  // Realistic IP pools
  private localIps = ['192.168.1.105', '192.168.1.112', '192.168.1.140', '192.168.1.189', '10.0.0.45'];
  private gatewayIp = '192.168.1.1';
  private remoteIps = [
    '142.250.190.46',  // Google
    '151.101.65.140',  // Fastly CDN
    '104.244.42.1',    // Twitter
    '52.94.233.129',   // AWS Cloud
    '13.107.42.14',    // Microsoft
    '8.8.8.8',         // Google DNS
    '1.1.1.1',         // Cloudflare DNS
    '185.220.101.5',   // Known scanner / Tor exit
    '45.33.32.156',    // Nmap scanme host
    '91.240.118.234',  // Suspect C2 host
  ];

  public subscribe(cb: PacketCallback): () => void {
    this.subscribers.add(cb);
    return () => this.subscribers.delete(cb);
  }

  public getIsRunning(): boolean {
    return this.isRunning;
  }

  public setSpeed(ms: number) {
    this.captureSpeed = ms;
    if (this.isRunning) {
      this.stop();
      this.start();
    }
  }

  public start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.scheduleNextPacket();
  }

  public stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearTimeout(this.intervalId);
      this.intervalId = null;
    }
  }

  private scheduleNextPacket() {
    if (!this.isRunning) return;
    // Jitter delay slightly for realism
    const delay = Math.max(100, this.captureSpeed + (Math.random() * 200 - 100));
    this.intervalId = setTimeout(() => {
      if (this.isRunning) {
        this.generateAndProcessPacket();
        this.scheduleNextPacket();
      }
    }, delay);
  }

  public injectPacket(
    src_ip: string,
    dst_ip: string,
    dst_port: number,
    protocol: 'TCP' | 'UDP' | 'ICMP',
    length: number,
    src_port?: number
  ): PacketRecord {
    const existing = storage.getBaseline(dst_port, protocol);
    const result = classifyPacket(dst_port, protocol, length, src_ip, dst_ip, existing);

    // Save baseline
    storage.upsertBaseline(result.updatedBaseline);

    // Save alert if generated
    if (result.alert) {
      storage.insertAlert(result.alert);
    }

    const packet: PacketRecord = {
      id: `pkt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: formatTimestamp(),
      src_ip,
      dst_ip,
      src_port: src_port || Math.floor(49152 + Math.random() * 16000),
      dst_port,
      protocol,
      length,
      classification: result.classification,
      reason: result.reason,
    };

    storage.insertPacket(packet);
    this.subscribers.forEach((cb) => cb(packet));
    return packet;
  }

  // Pre-configured attack/behavior simulations
  public simulatePortScan() {
    const attacker = '185.220.101.5';
    const target = this.localIps[0];
    const portsToProbe = [21, 22, 23, 80, 135, 139, 445, 1433, 3389, 4444, 8080];
    
    portsToProbe.forEach((port, idx) => {
      setTimeout(() => {
        this.injectPacket(attacker, target, port, 'TCP', 64, 54000 + idx);
      }, idx * 120);
    });
  }

  public simulateTrafficSpike() {
    const attacker = '45.33.32.156';
    const target = '192.168.1.105';
    const port = 80; // Common port with established baseline
    // Fire 28 rapid packets
    for (let i = 0; i < 28; i++) {
      setTimeout(() => {
        this.injectPacket(attacker, target, port, 'TCP', 512 + Math.floor(Math.random() * 200));
      }, i * 50);
    }
  }

  public simulateByteSizeAnomaly() {
    const client = this.localIps[1];
    const server = '142.250.190.46';
    // Huge 12,450 byte payload on port 443 where normal packet size is ~750 bytes
    this.injectPacket(client, server, 443, 'TCP', 12450, 52194);
  }

  public simulateUnknownService() {
    const src = '192.168.1.140';
    const dst = '198.51.100.44';
    // Custom/rare unassigned port 9999
    this.injectPacket(src, dst, 9999, 'TCP', 320, 50123);
  }

  private generateAndProcessPacket() {
    const rand = Math.random();
    let src_ip: string;
    let dst_ip: string;
    let dst_port: number;
    let protocol: 'TCP' | 'UDP' | 'ICMP';
    let length: number;

    const local = this.localIps[Math.floor(Math.random() * this.localIps.length)];
    const remote = this.remoteIps[Math.floor(Math.random() * this.remoteIps.length)];

    if (rand < 0.50) {
      // 50%: Normal HTTPS web traffic (port 443)
      src_ip = Math.random() > 0.4 ? local : remote;
      dst_ip = src_ip === local ? remote : local;
      dst_port = 443;
      protocol = 'TCP';
      // Gaussian-like packet length between 300 and 1400
      length = Math.floor(400 + Math.random() * 800 + Math.random() * 200);
    } else if (rand < 0.70) {
      // 20%: DNS queries (port 53)
      src_ip = local;
      dst_ip = Math.random() > 0.5 ? '8.8.8.8' : '1.1.1.1';
      dst_port = 53;
      protocol = 'UDP';
      length = Math.floor(68 + Math.random() * 64);
    } else if (rand < 0.82) {
      // 12%: HTTP Web Traffic (port 80) or API (port 8080)
      src_ip = local;
      dst_ip = remote;
      dst_port = Math.random() > 0.3 ? 80 : 8080;
      protocol = 'TCP';
      length = Math.floor(250 + Math.random() * 600);
    } else if (rand < 0.88) {
      // 6%: ICMP Echo (ping)
      src_ip = local;
      dst_ip = '8.8.8.8';
      dst_port = 0;
      protocol = 'ICMP';
      length = 64;
    } else if (rand < 0.94) {
      // 6%: SSH or NTP
      if (Math.random() > 0.5) {
        src_ip = local;
        dst_ip = remote;
        dst_port = 22;
        protocol = 'TCP';
        length = Math.floor(128 + Math.random() * 256);
      } else {
        src_ip = local;
        dst_ip = '129.6.15.28';
        dst_port = 123;
        protocol = 'UDP';
        length = 76;
      }
    } else if (rand < 0.98) {
      // 4%: Occasional first-seen or rare port (triggers UNKNOWN learning)
      const rarePorts = [9999, 8443, 6379, 5432, 27017, 31337];
      dst_port = rarePorts[Math.floor(Math.random() * rarePorts.length)];
      src_ip = local;
      dst_ip = remote;
      protocol = 'TCP';
      length = Math.floor(100 + Math.random() * 400);
    } else {
      // 2%: Suspicious probe to risky port (port 23, 445, 3389)
      const risky = [23, 445, 3389, 135];
      dst_port = risky[Math.floor(Math.random() * risky.length)];
      src_ip = '185.220.101.5';
      dst_ip = local;
      protocol = 'TCP';
      length = 64;
    }

    this.injectPacket(src_ip, dst_ip, dst_port, protocol, length);
  }
}

export const trafficEngine = new TrafficEngine();
