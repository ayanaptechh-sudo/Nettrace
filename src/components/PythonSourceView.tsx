import React, { useState } from 'react';
import { Terminal, Copy, Check, Download, FileCode, Play, AlertCircle } from 'lucide-react';
import { PYTHON_FILES } from '../services/pythonSourceData';

export const PythonSourceView: React.FC = () => {
  const fileNames = Object.keys(PYTHON_FILES);
  const [selectedFile, setSelectedFile] = useState<string>('main.py');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(PYTHON_FILES[selectedFile] || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const content = PYTHON_FILES[selectedFile] || '';
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedFile;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Overview & Desktop Instructions */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-2">
          <Terminal className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white tracking-tight">
            Original NetTrace Desktop Architecture & Python Source
          </h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed mb-4">
          NetTrace was originally architected as a cross-platform desktop application powered by <strong>Python 3.10+</strong>, <strong>Scapy</strong> (packet sniffing), <strong>Flet</strong> (Flutter UI), and <strong>ReportLab</strong> (PDF generation). Below is the complete source extracted from <code className="text-cyan-400">NETTRACE.docx</code>.
        </p>

        {/* Setup Guide Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div className="text-cyan-400 font-bold mb-1">🪟 Windows Setup</div>
            <p className="text-[11px] text-slate-400 font-sans mb-2">
              Install <strong>Npcap</strong> with "WinPcap API-compatible Mode".
            </p>
            <div className="text-[10px] text-slate-300 bg-slate-900 p-2 rounded border border-slate-800 space-y-1">
              <div>python -m venv .venv</div>
              <div>.venv\Scripts\activate</div>
              <div>pip install -r requirements.txt</div>
              <div className="text-emerald-400"># Run as Admin</div>
              <div>python main.py</div>
            </div>
          </div>

          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div className="text-cyan-400 font-bold mb-1">🐧 Linux Setup</div>
            <p className="text-[11px] text-slate-400 font-sans mb-2">
              Install libpcap-dev and configure raw socket capabilities.
            </p>
            <div className="text-[10px] text-slate-300 bg-slate-900 p-2 rounded border border-slate-800 space-y-1">
              <div>sudo apt install libpcap-dev</div>
              <div>pip install -r requirements.txt</div>
              <div className="text-emerald-400"># Run with root/sudo</div>
              <div>sudo python main.py</div>
            </div>
          </div>

          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div className="text-cyan-400 font-bold mb-1">🍏 macOS Setup</div>
            <p className="text-[11px] text-slate-400 font-sans mb-2">
              Install libpcap via Homebrew and run with administrator privileges.
            </p>
            <div className="text-[10px] text-slate-300 bg-slate-900 p-2 rounded border border-slate-800 space-y-1">
              <div>brew install libpcap</div>
              <div>pip install -r requirements.txt</div>
              <div className="text-emerald-400"># Run with sudo</div>
              <div>sudo python main.py</div>
            </div>
          </div>
        </div>
      </div>

      {/* Code Browser */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
        {/* File Tabs */}
        <div className="bg-slate-950 px-3 py-2 border-b border-slate-800 flex items-center justify-between gap-3 overflow-x-auto">
          <div className="flex items-center gap-1.5 shrink-0">
            {fileNames.map((file) => (
              <button
                key={file}
                onClick={() => setSelectedFile(file)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition flex items-center gap-1.5 whitespace-nowrap ${
                  selectedFile === file
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>{file}</span>
              </button>
            ))}
          </div>

          {/* Copy and Download Buttons */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy</span>
                </>
              )}
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>
          </div>
        </div>

        {/* Code Content */}
        <div className="p-4 bg-slate-950 overflow-x-auto max-h-[600px]">
          <pre className="text-xs font-mono text-slate-300 leading-relaxed">
            {PYTHON_FILES[selectedFile] || '# No content available'}
          </pre>
        </div>
      </div>
    </div>
  );
};
