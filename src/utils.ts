export function nowTimestamp(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

export function filenameTimestamp(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  return `${year}${month}${day}_${hours}${minutes}${seconds}`;
}

export function calculateMean(values: number[]): number {
  if (!values || values.length === 0) return 0;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

export function calculateStdDev(values: number[]): number {
  if (!values || values.length < 2) return 0;
  const mean = calculateMean(values);
  const variance = values.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / values.length;
  return Math.sqrt(variance);
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function getServiceName(port: number, protocol: string): string {
  if (protocol === 'ICMP' || port === 0) return 'ICMP Ping / Echo';
  const wellKnown: Record<number, string> = {
    20: 'FTP-Data',
    21: 'FTP-Control',
    22: 'SSH Remote Login',
    23: 'Telnet (Unencrypted)',
    25: 'SMTP Mail',
    53: 'DNS Domain Resolution',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    80: 'HTTP Web Traffic',
    110: 'POP3 Mail',
    123: 'NTP Time Sync',
    135: 'MS RPC Endpoint',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram',
    139: 'NetBIOS Session',
    143: 'IMAP Mail',
    161: 'SNMP Trap',
    179: 'BGP Routing',
    389: 'LDAP Directory',
    443: 'HTTPS TLS Encrypted',
    445: 'SMB File Sharing (High Risk)',
    465: 'SMTPS',
    514: 'Syslog',
    587: 'SMTP Submission',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS Proxy',
    1194: 'OpenVPN',
    1433: 'MS SQL Database',
    1521: 'Oracle DB',
    1723: 'PPTP VPN',
    2049: 'NFS Network FS',
    3306: 'MySQL Database',
    3389: 'RDP Remote Desktop',
    4444: 'Metasploit Listener',
    5060: 'SIP VoIP',
    5222: 'XMPP Messaging',
    5353: 'mDNS Multicast',
    5432: 'PostgreSQL Database',
    5900: 'VNC Remote Display',
    6379: 'Redis In-Memory DB',
    6667: 'IRC Chat (Botnet C2)',
    8080: 'HTTP Alternate Web',
    8443: 'HTTPS Alternate Web',
    8888: 'Jupyter / Alternate Web',
    9200: 'Elasticsearch',
    27017: 'MongoDB Database',
  };
  return wellKnown[port] || (port > 49152 ? 'Dynamic / Ephemeral' : 'Custom Service');
}
