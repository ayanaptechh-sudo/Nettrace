export const APP_NAME = "NetTrace";
export const APP_TITLE = "NetTrace — Network Security Monitoring System";
export const APP_SUBTITLE = "Unknown Network Traffic Detector & Anomaly Baseline";
export const APP_VERSION = "1.0.0";
export const APP_AUTHOR = "NetTrace Security Engineering";
export const APP_LICENSE = "Educational use only";

// Baseline / Anomaly tunables matching config.py
export const LEARNING_THRESHOLD = 5;
export const ANOMALY_SIGMA = 3.0;
export const MIN_STDDEV_SAMPLES = 3;
export const RATE_WINDOW_SECONDS = 60;
export const RATE_SPIKE_MULTIPLIER = 3.0;
export const RATE_SPIKE_MIN_PACKETS = 20;
export const MAX_BYTE_HISTORY = 500;
export const MAX_RATE_SAMPLES = 200;

// Port classification
export const RISKY_PORTS = new Set<number>([
  21,   // FTP
  23,   // Telnet (unencrypted)
  135,  // MS RPC
  137,  // NetBIOS
  138,  // NetBIOS
  139,  // NetBIOS
  445,  // SMB (ransomware/lateral movement target)
  1433, // MS SQL
  3306, // MySQL
  3389, // RDP (remote desktop)
  4444, // Metasploit default listener
  5900, // VNC
  6667, // IRC (botnet C2)
]);

export const COMMON_PORTS = new Set<number>([
  20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 143, 161, 162,
  179, 389, 443, 465, 514, 587, 636, 993, 995, 1080, 1194, 1433,
  1521, 1723, 2049, 3306, 3389, 5060, 5222, 5353, 5432, 5900,
  6379, 8080, 8443, 8888, 9200, 27017,
]);

export const PORT_NAMES: Record<number, string> = {
  0: "ICMP Echo / Control",
  21: "FTP (File Transfer)",
  22: "SSH (Secure Shell)",
  23: "Telnet (Unencrypted Remote Shell)",
  25: "SMTP (Mail Transfer)",
  53: "DNS (Domain Name System)",
  67: "DHCP Server",
  68: "DHCP Client",
  80: "HTTP (Web Traffic)",
  123: "NTP (Network Time Protocol)",
  135: "Microsoft RPC Endpoint Mapper",
  137: "NetBIOS Name Service",
  138: "NetBIOS Datagram Service",
  139: "NetBIOS Session Service",
  443: "HTTPS (TLS/SSL Encrypted)",
  445: "SMB (Direct Host / SMB over IP)",
  587: "SMTP Submission (STARTTLS)",
  993: "IMAPS (Secure IMAP)",
  1433: "Microsoft SQL Server",
  3306: "MySQL Database",
  3389: "RDP (Remote Desktop Protocol)",
  4444: "Metasploit Default Listener",
  5353: "mDNS (Multicast DNS)",
  5432: "PostgreSQL Database",
  5900: "VNC Remote Desktop",
  6379: "Redis Cache Server",
  6667: "IRC (Internet Relay Chat / C2)",
  8080: "HTTP Alternate / Web Proxy",
  8443: "HTTPS Alternate",
  9200: "Elasticsearch REST API",
  27017: "MongoDB Database Service"
};

export const ICMP_PORT_SENTINEL = 0;

// Risk scoring weights
export const RISK_WEIGHT_SUSPICIOUS = 10;
export const RISK_WEIGHT_UNKNOWN = 3;
export const RISK_WEIGHT_ALERT_HIGH = 8;
export const RISK_WEIGHT_ALERT_MEDIUM = 3;
export const RISK_LOW_MAX = 20;
export const RISK_MEDIUM_MAX = 60;
