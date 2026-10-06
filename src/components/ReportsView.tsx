import React, { useState } from 'react';
import {
  FileText,
  FileCode,
  Download,
  Printer,
  ShieldCheck,
  ShieldAlert,
  ExternalLink,
  Database,
} from 'lucide-react';
import { TrafficStats } from '../types';
import { generateHtmlReport, downloadHtmlReport, openPrintReport } from '../services/reportGenerator';
import { storage } from '../services/storage';

interface ReportsViewProps {
  stats: TrafficStats;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ stats }) => {
  const [activeTab, setActiveTab] = useState<'preview' | 'json'>('preview');

  const downloadJson = () => {
    const jsonStr = storage.exportJson();
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nettrace_backup_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const htmlContent = generateHtmlReport();

  return (
    <div className="space-y-5">
      {/* Action Header Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-tight">
              Security Assessment & Audit Reports
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Compliant with NetTrace <code className="text-cyan-400">report_html.py</code> &{' '}
            <code className="text-rose-400">report_pdf.py</code> specifications
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center flex-wrap gap-2.5">
          <button
            onClick={openPrintReport}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs shadow-lg shadow-rose-950/30 transition"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Generate & Print PDF</span>
          </button>

          <button
            onClick={downloadHtmlReport}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-lg shadow-cyan-950/30 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download HTML Report</span>
          </button>

          <button
            onClick={downloadJson}
            className="flex items-center gap-2 px-3 py-2 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs transition"
          >
            <Database className="w-3.5 h-3.5 text-purple-400" />
            <span>Export DB JSON</span>
          </button>
        </div>
      </div>

      {/* Tabs for Live HTML Preview vs Raw JSON */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('preview')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium font-mono transition ${
            activeTab === 'preview'
              ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Interactive HTML Report Preview</span>
        </button>
        <button
          onClick={() => setActiveTab('json')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium font-mono transition ${
            activeTab === 'json'
              ? 'bg-purple-950 text-purple-400 border border-purple-800'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Raw Database JSON Dump</span>
        </button>
      </div>

      {/* Content Frame */}
      {activeTab === 'preview' ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div className="bg-slate-950 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span className="font-mono text-[11px]">report_viewer: sandbox preview</span>
            <button
              onClick={downloadHtmlReport}
              className="text-cyan-400 hover:underline flex items-center gap-1 text-[11px]"
            >
              Open in external tab <ExternalLink className="w-3 h-3" />
            </button>
          </div>
          <iframe
            srcDoc={htmlContent}
            title="NetTrace Report Preview"
            className="w-full h-[650px] bg-white border-0"
          />
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <pre className="text-xs text-cyan-300 font-mono bg-slate-950 p-4 rounded-xl overflow-x-auto max-h-[600px]">
            {storage.exportJson()}
          </pre>
        </div>
      )}
    </div>
  );
};
