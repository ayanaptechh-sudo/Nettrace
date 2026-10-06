import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { TrafficView } from './components/TrafficView';
import { AlertsView } from './components/AlertsView';
import { BaselineView } from './components/BaselineView';
import { ReportsView } from './components/ReportsView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { PythonSourceView } from './components/PythonSourceView';
import { PacketDetailModal } from './components/PacketDetailModal';
import { storage } from './services/storage';
import { trafficEngine } from './services/trafficEngine';
import { PacketRecord, AlertRecord, BaselineEntry, TrafficStats } from './types';

export const App: React.FC = () => {
  const [isRunning, setIsRunning] = useState<boolean>(true);
  const [currentView, setCurrentView] = useState<string>('dashboard');
  const [stats, setStats] = useState<TrafficStats>(() => storage.getStats());
  const [packets, setPackets] = useState<PacketRecord[]>(() => storage.getPackets());
  const [alerts, setAlerts] = useState<AlertRecord[]>(() => storage.getAlerts());
  const [baselines, setBaselines] = useState<BaselineEntry[]>(() => storage.getAllBaselines());
  const [selectedPacket, setSelectedPacket] = useState<PacketRecord | null>(null);

  // Rate chart sliding history (30 intervals)
  const [rateHistory, setRateHistory] = useState<number[]>([
    2, 3, 2, 4, 3, 5, 2, 4, 6, 3, 4, 7, 5, 4, 3, 2, 6, 8, 4, 3, 5, 7, 4, 3, 2, 5, 4, 3, 6, 4
  ]);

  // Synchronize with database
  const refreshData = useCallback(() => {
    setStats(storage.getStats());
    setPackets(storage.getPackets());
    setAlerts(storage.getAlerts());
    setBaselines(storage.getAllBaselines());
  }, []);

  // Initialize and seed if empty
  useEffect(() => {
    if (storage.getPackets().length === 0) {
      // Seed some initial packets for immediate visualization
      const sampleSeeds = [
        { src: '192.168.1.105', dst: '142.250.190.46', port: 443, proto: 'TCP' as const, len: 780 },
        { src: '192.168.1.105', dst: '142.250.190.46', port: 443, proto: 'TCP' as const, len: 820 },
        { src: '192.168.1.105', dst: '142.250.190.46', port: 443, proto: 'TCP' as const, len: 760 },
        { src: '192.168.1.105', dst: '142.250.190.46', port: 443, proto: 'TCP' as const, len: 840 },
        { src: '192.168.1.105', dst: '142.250.190.46', port: 443, proto: 'TCP' as const, len: 800 },
        { src: '192.168.1.112', dst: '8.8.8.8', port: 53, proto: 'UDP' as const, len: 72 },
        { src: '192.168.1.112', dst: '8.8.8.8', port: 53, proto: 'UDP' as const, len: 94 },
        { src: '192.168.1.140', dst: '1.1.1.1', port: 53, proto: 'UDP' as const, len: 68 },
        { src: '192.168.1.189', dst: '198.51.100.44', port: 9999, proto: 'TCP' as const, len: 320 },
        { src: '192.168.1.189', dst: '198.51.100.44', port: 9999, proto: 'TCP' as const, len: 340 },
        { src: '185.220.101.5', dst: '192.168.1.105', port: 23, proto: 'TCP' as const, len: 64 },
        { src: '192.168.1.105', dst: '8.8.8.8', port: 0, proto: 'ICMP' as const, len: 64 },
      ];

      sampleSeeds.forEach((s) => {
        trafficEngine.injectPacket(s.src, s.dst, s.port, s.proto, s.len);
      });
    }

    // Start engine by default
    trafficEngine.start();
    setIsRunning(true);
    refreshData();

    // Subscribe to incoming traffic packets
    let recentSecondPackets = 0;
    const unsub = trafficEngine.subscribe(() => {
      recentSecondPackets++;
      refreshData();
    });

    // Rate chart interval (updates every 2 seconds)
    const rateInterval = setInterval(() => {
      setRateHistory((prev) => {
        const next = [...prev.slice(1), recentSecondPackets];
        recentSecondPackets = 0;
        return next;
      });
    }, 2000);

    return () => {
      unsub();
      clearInterval(rateInterval);
      trafficEngine.stop();
    };
  }, [refreshData]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
      {/* Top Application Bar */}
      <Header
        isRunning={isRunning}
        setIsRunning={setIsRunning}
        onRefresh={refreshData}
        packetRate={rateHistory[rateHistory.length - 1] || 0}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentView={currentView}
          setCurrentView={setCurrentView}
          alertCount={stats.alertsTotal}
          suspiciousCount={stats.suspicious}
        />

        {/* Primary Viewport Area */}
        <main className="flex-1 overflow-y-auto p-6 max-w-7xl mx-auto w-full">
          {currentView === 'dashboard' && (
            <DashboardView
              stats={stats}
              recentPackets={packets}
              recentAlerts={alerts}
              onSelectPacket={setSelectedPacket}
              onNavigate={setCurrentView}
              rateHistory={rateHistory}
            />
          )}

          {currentView === 'traffic' && (
            <TrafficView packets={packets} onSelectPacket={setSelectedPacket} />
          )}

          {currentView === 'alerts' && <AlertsView alerts={alerts} />}

          {currentView === 'baseline' && <BaselineView baselines={baselines} />}

          {currentView === 'reports' && <ReportsView stats={stats} />}

          {currentView === 'threat_intel' && (
            <ThreatIntelView onPacketInjected={refreshData} />
          )}

          {currentView === 'python_source' && <PythonSourceView />}
        </main>
      </div>

      {/* Packet Inspector Drawer/Modal */}
      <PacketDetailModal
        packet={selectedPacket}
        onClose={() => setSelectedPacket(null)}
      />
    </div>
  );
};
