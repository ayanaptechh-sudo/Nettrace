import { analyzer, IncomingPacketMeta } from './analyzer';
import { Protocol } from '../types';

export type TrafficScenario = 'normal' | 'port_scan' | 'spike' | 'malicious_ip' | 'outlier' | 'new_port';

class TrafficGeneratorService {
  private timer: number | null = null;
  private isRunning = false;
  private speed = 1000; // ms per packet (default 1 pkt/sec)
  private listeners: Set<(running: boolean) => void> = new Set();

  private normalDestinations = [
    { ip: '142.250.190.46', port: 443, proto: 'TCP' as Protocol, baseLen: 1200 }, // Google
    { ip: '104.16.132.229', port: 443, proto: 'TCP' as Protocol, baseLen: 1100 }, // Cloudflare
    { ip: '52.95.120.67', port: 443, proto: 'TCP' as Protocol, baseLen: 1350 },   // AWS
    { ip: '8.8.8.8', port: 53, proto: 'UDP' as Protocol, baseLen: 140 },          // Google DNS
    { ip: '1.1.1.1', port: 53, proto: 'UDP' as Protocol, baseLen: 128 },          // Cloudflare DNS
    { ip: '216.239.35.0', port: 123, proto: 'UDP' as Protocol, baseLen: 88 },     // NTP
    { ip: '192.168.1.1', port: 80, proto: 'TCP' as Protocol, baseLen: 650 },      // Local Gateway
    { ip: '10.0.0.1', port: 0, proto: 'ICMP' as Protocol, baseLen: 84 },          // Gateway Ping
    { ip: '192.168.1.50', port: 22, proto: 'TCP' as Protocol, baseLen: 480 },     // Local Server SSH
  ];

  public subscribe(cb: (running: boolean) => void): () => void {
    this.listeners.add(cb);
    cb(this.isRunning);
    return () => this.listeners.delete(cb);
  }

  private notify(): void {
    this.listeners.forEach((cb) => cb(this.isRunning));
  }

  public getIsRunning(): boolean {
    return this.isRunning;
  }

  public setSpeed(ms: number): void {
    this.speed = ms;
    if (this.isRunning) {
      this.stop();
      this.start();
    }
  }

  public start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    this.notify();

    const loop = () => {
      this.emitRandomPacket();
      if (this.isRunning) {
        this.timer = window.setTimeout(loop, this.speed + (Math.random() * 200 - 100));
      }
    };

    this.timer = window.setTimeout(loop, 200);
  }

  public stop(): void {
    this.isRunning = false;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.notify();
  }

  public emitRandomPacket(): void {
    const roll = Math.random();

    if (roll < 0.70) {
      // 70% normal traffic
      const dest = this.normalDestinations[Math.floor(Math.random() * this.normalDestinations.length)];
      const jitter = Math.floor((Math.random() - 0.5) * 80);
      const packet: IncomingPacketMeta = {
        src_ip: '192.168.1.105',
        dst_ip: dest.ip,
        src_port: Math.floor(49152 + Math.random() * 15000),
        dst_port: dest.port,
        protocol: dest.proto,
        length: Math.max(48, dest.baseLen + jitter),
      };
      analyzer.analyze(packet);
    } else if (roll < 0.85) {
      // 15% learning / unknown ports
      const learnPort = 50000 + (Math.floor(Date.now() / 30000) % 5);
      const packet: IncomingPacketMeta = {
        src_ip: `10.0.0.${Math.floor(Math.random() * 50) + 10}`,
        dst_ip: '192.168.1.105',
        src_port: Math.floor(49152 + Math.random() * 10000),
        dst_port: learnPort,
        protocol: 'TCP',
        length: Math.floor(250 + Math.random() * 150),
      };
      analyzer.analyze(packet);
    } else if (roll < 0.95) {
      // 10% risky port hit
      const risky = [23, 445, 3389, 1433, 21][Math.floor(Math.random() * 5)];
      const threatIp = ['185.220.101.5', '194.26.29.112', '45.148.10.23', '91.240.118.172'][
        Math.floor(Math.random() * 4)
      ];
      const packet: IncomingPacketMeta = {
        src_ip: threatIp,
        dst_ip: '192.168.1.105',
        src_port: Math.floor(40000 + Math.random() * 20000),
        dst_port: risky,
        protocol: 'TCP',
        length: Math.floor(60 + Math.random() * 120),
      };
      analyzer.analyze(packet);
    } else {
      // 5% statistical byte outlier
      const packet: IncomingPacketMeta = {
        src_ip: '10.0.0.77',
        dst_ip: '192.168.1.105',
        src_port: Math.floor(49152 + Math.random() * 10000),
        dst_port: 443,
        protocol: 'TCP',
        length: 28500, // Massive anomaly compared to ~1250 mean!
      };
      analyzer.analyze(packet);
    }
  }

  // Preset Scenario Injections
  public simulateScenario(scenario: TrafficScenario): void {
    switch (scenario) {
      case 'port_scan': {
        const attackerIp = '185.220.101.5';
        const scanPorts = [21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080];
        scanPorts.forEach((port, index) => {
          setTimeout(() => {
            analyzer.analyze({
              src_ip: attackerIp,
              dst_ip: '192.168.1.105',
              src_port: 50000 + index,
              dst_port: port,
              protocol: 'TCP',
              length: 64,
            });
          }, index * 120);
        });
        break;
      }

      case 'spike': {
        const targetIp = '192.168.1.105';
        for (let i = 0; i < 25; i++) {
          setTimeout(() => {
            analyzer.analyze({
              src_ip: '10.0.0.88',
              dst_ip: targetIp,
              src_port: 45000 + i,
              dst_port: 80,
              protocol: 'TCP',
              length: 1200,
            });
          }, i * 50);
        }
        break;
      }

      case 'malicious_ip': {
        analyzer.analyze({
          src_ip: '194.26.29.112',
          dst_ip: '192.168.1.105',
          src_port: 51234,
          dst_port: 4444,
          protocol: 'TCP',
          length: 256,
        });
        break;
      }

      case 'outlier': {
        analyzer.analyze({
          src_ip: '10.0.0.15',
          dst_ip: '192.168.1.105',
          src_port: 52110,
          dst_port: 443,
          protocol: 'TCP',
          length: 48000,
        });
        break;
      }

      case 'new_port': {
        const newPort = Math.floor(30000 + Math.random() * 10000);
        analyzer.analyze({
          src_ip: '10.0.0.22',
          dst_ip: '192.168.1.105',
          src_port: 54321,
          dst_port: newPort,
          protocol: 'UDP',
          length: 320,
        });
        break;
      }

      case 'normal':
      default: {
        for (let i = 0; i < 5; i++) {
          setTimeout(() => this.emitRandomPacket(), i * 150);
        }
        break;
      }
    }
  }

  public injectCustomPacket(packet: IncomingPacketMeta): void {
    analyzer.analyze(packet);
  }
}

export const trafficGenerator = new TrafficGeneratorService();
