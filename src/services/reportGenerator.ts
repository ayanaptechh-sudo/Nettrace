import { storage } from './storage';
import { formatTimestamp } from './baseline';
import {
  APP_NAME,
  APP_TITLE,
  APP_VERSION,
  RISK_LOW_MAX,
  RISK_MEDIUM_MAX,
} from './config';
import { PacketRecord, AlertRecord, BaselineEntry } from '../types';

export function generateHtmlReport(): string {
  const stats = storage.getStats();
  const packets = storage.getPackets({ limit: 100 });
  const alerts = storage.getAlerts({ limit: 50 });
  const baselines = storage.getAllBaselines();
  const timestamp = formatTimestamp();

  // Calculate top unknown & suspicious sources
  const sourceCounts: Record<string, { count: number; bytes: number; classifications: Set<string> }> = {};
  packets.forEach((p) => {
    if (p.classification === 'UNKNOWN' || p.classification === 'SUSPICIOUS') {
      if (!sourceCounts[p.src_ip]) {
        sourceCounts[p.src_ip] = { count: 0, bytes: 0, classifications: new Set() };
      }
      sourceCounts[p.src_ip].count += 1;
      sourceCounts[p.src_ip].bytes += p.length;
      sourceCounts[p.src_ip].classifications.add(p.classification);
    }
  });

  const topSources = Object.entries(sourceCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10);

  const riskClass =
    stats.riskScore <= RISK_LOW_MAX
      ? 'risk-low'
      : stats.riskScore <= RISK_MEDIUM_MAX
      ? 'risk-medium'
      : 'risk-high';

  const riskLabel =
    stats.riskScore <= RISK_LOW_MAX
      ? 'LOW'
      : stats.riskScore <= RISK_MEDIUM_MAX
      ? 'MEDIUM'
      : stats.riskScore > RISK_MEDIUM_MAX * 2
      ? 'CRITICAL'
      : 'HIGH';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetTrace Security Report — ${timestamp}</title>
<style>
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
  margin: 0; padding: 0; background: #f8fafc; color: #1e293b; line-height: 1.5;
}
.header { background: #0f172a; color: #f8fafc; padding: 28px 36px; border-bottom: 3px solid #38bdf8; }
.header h1 { margin: 0; font-size: 26px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
.header .meta { opacity: .8; font-size: 13px; margin-top: 8px; font-family: monospace; }
.container { max-width: 1100px; margin: 0 auto; padding: 32px 36px; }
.risk-banner {
  padding: 18px 24px; border-radius: 8px; margin-bottom: 24px;
  font-weight: 700; font-size: 16px; color: #fff; display: flex; justify-content: space-between; align-items: center;
}
.risk-low { background: #16a34a; }
.risk-medium { background: #d97706; }
.risk-high { background: #dc2626; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
.card { background: #fff; border-radius: 8px; padding: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.08); border: 1px solid #e2e8f0; }
.card .label { font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
.card .value { font-size: 28px; font-weight: 800; margin-top: 6px; color: #0f172a; }
h2 { color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 36px; font-size: 19px; }
table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.05); border-radius: 8px; overflow: hidden; font-size: 13px; margin-bottom: 24px; border: 1px solid #e2e8f0; }
th { background: #1e293b; color: #f8fafc; text-align: left; padding: 10px 14px; font-weight: 600; font-size: 12px; }
td { padding: 9px 14px; border-top: 1px solid #f1f5f9; }
tr:nth-child(even) td { background: #f8fafc; }
.tag { display: inline-block; padding: 3px 8px; border-radius: 9999px; font-size: 11px; font-weight: 700; font-family: monospace; }
.tag-known { background: #dcfce7; color: #15803d; }
.tag-unknown { background: #fef3c7; color: #b45309; }
.tag-suspicious { background: #fee2e2; color: #b91c1c; }
.tag-high { background: #fee2e2; color: #b91c1c; }
.tag-med { background: #fef3c7; color: #b45309; }
.tag-low { background: #e0f2fe; color: #0369a1; }
ul.recs { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px 24px 20px 40px; margin-top: 12px; }
ul.recs li { margin-bottom: 10px; font-size: 14px; color: #334155; }
.footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid #cbd5e1; text-align: center; font-size: 12px; color: #94a3b8; }
@media print {
  body { background: #fff; }
  .header { padding: 16px; border: none; }
  .container { padding: 16px; max-width: 100%; }
  .card, table { box-shadow: none; }
}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ NetTrace — Network Security Assessment Report</h1>
  <div class="meta">Generated: ${timestamp} | Engine: NetTrace v${APP_VERSION} | Scope: Real-time Traffic Metadata Monitor</div>
</div>
<div class="container">
  <div class="risk-banner ${riskClass}">
    <span>THREAT LEVEL: ${riskLabel}</span>
    <span>Calculated Risk Score: ${stats.riskScore}</span>
  </div>

  <div class="cards">
    <div class="card">
      <div class="label">Total Packets</div>
      <div class="value">${stats.total}</div>
    </div>
    <div class="card">
      <div class="label">Known Traffic</div>
      <div class="value" style="color: #16a34a;">${stats.known}</div>
    </div>
    <div class="card">
      <div class="label">Unknown Traffic</div>
      <div class="value" style="color: #d97706;">${stats.unknown}</div>
    </div>
    <div class="card">
      <div class="label">Suspicious Traffic</div>
      <div class="value" style="color: #dc2626;">${stats.suspicious}</div>
    </div>
    <div class="card">
      <div class="label">Security Alerts</div>
      <div class="value" style="color: ${stats.alertsTotal > 0 ? '#dc2626' : '#64748b'};">${stats.alertsTotal}</div>
    </div>
  </div>

  <h2>Protocol Distribution</h2>
  <table>
    <thead>
      <tr><th>Protocol</th><th>Packet Count</th><th>Percentage</th><th>Total Volume (approx)</th></tr>
    </thead>
    <tbody>
      ${Object.entries(stats.protocolCounts)
        .map(([proto, count]) => {
          const pct = stats.total > 0 ? ((count / stats.total) * 100).toFixed(1) : '0.0';
          return `<tr><td><strong>${proto}</strong></td><td>${count}</td><td>${pct}%</td><td>${Math.round(count * 512 / 1024)} KB</td></tr>`;
        })
        .join('')}
    </tbody>
  </table>

  <h2>Top Unknown / Suspicious Sources</h2>
  ${
    topSources.length === 0
      ? '<p style="color: #64748b; font-style: italic;">No unknown or suspicious traffic sources recorded.</p>'
      : `<table>
      <thead>
        <tr><th>Source IP Address</th><th>Packet Hits</th><th>Total Bytes</th><th>Categories Observed</th></tr>
      </thead>
      <tbody>
        ${topSources
          .map(
            ([ip, info]) =>
              `<tr><td><code>${ip}</code></td><td>${info.count}</td><td>${info.bytes} B</td><td>${Array.from(info.classifications)
                .map((c) => `<span class="tag tag-${c.toLowerCase()}">${c}</span>`)
                .join(' ')}</td></tr>`
          )
          .join('')}
      </tbody>
    </table>`
  }

  <h2>Security Alerts (${alerts.length})</h2>
  ${
    alerts.length === 0
      ? '<p style="color: #16a34a; font-weight: 500;">No security alerts triggered during this capture window.</p>'
      : `<table>
      <thead>
        <tr><th>Timestamp</th><th>Severity</th><th>Source IP</th><th>Target Port</th><th>Protocol</th><th>Alert Details</th></tr>
      </thead>
      <tbody>
        ${alerts
          .map(
            (a) =>
              `<tr><td style="font-family: monospace; font-size: 11px;">${a.timestamp}</td><td><span class="tag tag-${
                a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'high' : a.severity === 'MEDIUM' ? 'med' : 'low'
              }">${a.severity}</span></td><td><code>${a.src_ip}</code></td><td><strong>${a.dst_port}</strong></td><td>${a.protocol}</td><td>${a.message}</td></tr>`
          )
          .join('')}
      </tbody>
    </table>`
  }

  <h2>Learned Statistical Baselines (${baselines.length} entries)</h2>
  ${
    baselines.length === 0
      ? '<p style="color: #64748b; font-style: italic;">No baseline profiles learned yet.</p>'
      : `<table>
      <thead>
        <tr><th>Port</th><th>Protocol</th><th>Hits</th><th>Mean Payload</th><th>StdDev</th><th>Total Volume</th><th>First Seen</th><th>Last Seen</th></tr>
      </thead>
      <tbody>
        ${baselines
          .slice(0, 25)
          .map(
            (b) =>
              `<tr><td><strong>${b.dst_port}</strong></td><td>${b.protocol}</td><td>${b.hit_count}</td><td>${b.mean_bytes} B</td><td>${b.stddev_bytes}</td><td>${(b.total_bytes / 1024).toFixed(1)} KB</td><td style="font-size: 11px; font-family: monospace;">${b.first_seen}</td><td style="font-size: 11px; font-family: monospace;">${b.last_seen}</td></tr>`
          )
          .join('')}
      </tbody>
    </table>`
  }

  <h2>Recommendations & Remediation</h2>
  <ul class="recs">
    ${
      stats.suspicious > 0
        ? `<li><strong>Immediate Triage:</strong> Investigate <strong>${stats.suspicious}</strong> suspicious packets. Pay close attention to scans targeting risky ports (Telnet 23, SMB 445, RDP 3389) and isolate originating hosts.</li>`
        : `<li><strong>No Malicious Activity:</strong> No suspicious probe patterns detected during capture.</li>`
    }
    ${
      stats.unknown > 0
        ? `<li><strong>Service Verification:</strong> Review <strong>${stats.unknown}</strong> unknown packets. New unmapped services will automatically graduate to KNOWN status once the baseline threshold (${5} packets) is established without anomalous payload deviation.</li>`
        : ''
    }
    <li><strong>Port Hardening:</strong> Ensure default firewall drop policies for non-standard inbound ports (21, 23, 135-139, 445, 1433, 3389, 4444).</li>
    <li><strong>Baseline Calibration:</strong> Continue active capture through peak utilization periods to expand sample variance and decrease false positive rates on dynamic microservices.</li>
    <li><strong>Threat Intelligence:</strong> Cross-reference untrusted external IP addresses with threat feeds (AbuseIPDB, VirusTotal, CISA KEV).</li>
  </ul>

  <div class="footer">
    ${APP_TITLE} · Version ${APP_VERSION} · Educational & Authorized Monitoring Only
  </div>
</div>
</body>
</html>`;
}

export function downloadHtmlReport(): void {
  const htmlContent = generateHtmlReport();
  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `nettrace_report_${new Date().toISOString().replace(/[:.]/g, '-')}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function openPrintReport(): void {
  const htmlContent = generateHtmlReport();
  const printWindow = window.open('', '_blank');
  if (printWindow) {
    printWindow.document.write(htmlContent);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 400);
  } else {
    // If popup blocked, fallback to downloading HTML
    downloadHtmlReport();
  }
}
