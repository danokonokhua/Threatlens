'use client';

import { useEffect, useState } from 'react';
import { useAlertStream } from '@/hooks/useAlertStream';
import { SeverityDistribution, AlertTrends, IndicatorTypes } from '@/components/DashboardCharts';
import { FeedsManager } from '@/components/FeedsManager';
import { IncidentResponseView } from '@/components/IncidentResponseView';
import { ThreatHuntingView } from '@/components/ThreatHuntingView';
import { GlobalAttackHeatmap } from '@/components/GlobalAttackHeatmap';
import { ExecutiveOverviewView } from '@/components/ExecutiveOverviewView';
import { ExportReportsCenter } from '@/components/ExportReportsCenter';
import { Shield, AlertTriangle, Activity, CheckCircle, Terminal, RefreshCw, FolderKanban, Crosshair, ShieldCheck, ArrowDownToLine } from 'lucide-react';

export default function SOC_Dashboard() {
  const { alerts, isConnected } = useAlertStream();
  const [token, setToken] = useState('');
  const [indicators, setIndicators] = useState<any[]>([]);
  const [allAlerts, setAllAlerts] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'soc' | 'incident_response' | 'threat_hunting' | 'executive' | 'export_reports'>('soc');

  // Fetch data when token is provided
  const fetchData = async () => {
    if (!token) return;
    setIsLoading(true);
    try {
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [indicatorsRes, alertsRes] = await Promise.all([
        fetch('http://localhost:8000/api/v1/indicators', { headers }),
        fetch('http://localhost:8000/api/v1/alerts?status_filter=new&limit=100', { headers })
      ]);

      if (indicatorsRes.ok) {
        const indicatorsData = await indicatorsRes.json();
        setIndicators(indicatorsData);
      }

      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAllAlerts(alertsData);
      }
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (token) fetchData();
  }, [token]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      default: return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6 font-sans">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Shield className="text-blue-500" size={32} />
            ThreatLens <span className="text-gray-500 text-xl font-normal">| SOC Dashboard</span>
          </h1>
          <p className="text-gray-400 mt-1">Real-time Cyber Threat Intelligence & Analytics</p>
        </div>
        
        {/* Auth Token Input */}
        <div className="flex items-center gap-2 bg-gray-900 p-2 rounded-lg border border-gray-800">
          <Terminal size={16} className="text-gray-500" />
          <input 
            type="password" 
            placeholder="Paste Bearer Token..." 
            className="bg-transparent border-none outline-none text-sm w-64 text-gray-300 placeholder-gray-600"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <button 
            onClick={fetchData}
            disabled={isLoading || !token}
            className="p-2 bg-blue-600 hover:bg-blue-700 rounded text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw size={16} className={isLoading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* View Switcher Navigation */}
      <div className="flex items-center gap-2 mb-6 border-b border-gray-800 pb-3">
        <button
          onClick={() => setActiveTab('soc')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'soc'
              ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900'
          }`}
        >
          <Shield size={16} />
          SOC Analyst Dashboard
        </button>
        <button
          onClick={() => setActiveTab('incident_response')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'incident_response'
              ? 'bg-purple-600 text-white shadow-lg shadow-purple-900/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900'
          }`}
        >
          <FolderKanban size={16} />
          Incident Response Workspace (FR-19)
        </button>
        <button
          onClick={() => setActiveTab('threat_hunting')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'threat_hunting'
              ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-900/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900'
          }`}
        >
          <Crosshair size={16} />
          Threat Hunting Engine (FR-25)
        </button>
        <button
          onClick={() => setActiveTab('executive')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'executive'
              ? 'bg-amber-600 text-white shadow-lg shadow-amber-900/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900'
          }`}
        >
          <ShieldCheck size={16} />
          Executive Overview (CISO)
        </button>
        <button
          onClick={() => setActiveTab('export_reports')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'export_reports'
              ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-900/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900'
          }`}
        >
          <ArrowDownToLine size={16} />
          Exports & Reports (FR-23/24)
        </button>
      </div>

      {activeTab === 'executive' ? (
        <ExecutiveOverviewView token={token} />
      ) : activeTab === 'incident_response' ? (
        <IncidentResponseView token={token} />
      ) : activeTab === 'threat_hunting' ? (
        <ThreatHuntingView token={token} />
      ) : activeTab === 'export_reports' ? (
        <ExportReportsCenter token={token} />
      ) : (
        <>
          {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-gray-900 border border-gray-800 p-6 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm font-medium">Total Indicators</p>
              <h3 className="text-3xl font-bold mt-2">{indicators.length}</h3>
            </div>
            <div className="p-3 bg-blue-500/10 rounded-lg">
              <Activity className="text-blue-500" size={24} />
            </div>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-6 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm font-medium">Active Alerts (New)</p>
              <h3 className="text-3xl font-bold mt-2">{allAlerts.length}</h3>
            </div>
            <div className="p-3 bg-orange-500/10 rounded-lg">
              <AlertTriangle className="text-orange-500" size={24} />
            </div>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-6 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm font-medium">High/Critical Severity</p>
              <h3 className="text-3xl font-bold mt-2">
                {allAlerts.filter(a => a.severity === 'high' || a.severity === 'critical').length}
              </h3>
            </div>
            <div className="p-3 bg-red-500/10 rounded-lg">
              <Shield className="text-red-500" size={24} />
            </div>
          </div>
        </div>
      </div>

      {/* Feeds Ingestion & Pipeline Management (FR-01, FR-05) */}
      <FeedsManager token={token} onFeedsUpdated={fetchData} />

      {/* Global Attack Heatmap & Geo-Density (FR-20) */}
      <GlobalAttackHeatmap token={token} />

      {/* Charts Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <SeverityDistribution alerts={allAlerts} />
        <AlertTrends alerts={allAlerts} />
        <div className="md:col-span-2">
          <IndicatorTypes indicators={indicators} />
        </div>
      </div>

      {/* Live Alert Stream */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-gray-900/50">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
            Live Alert Stream
          </h2>
          <span className="text-xs text-gray-500">{alerts.length} recent events</span>
        </div>

        <div className="divide-y divide-gray-800 max-h-[400px] overflow-y-auto">
          {alerts.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              <CheckCircle className="mx-auto mb-3 opacity-50" size={48} />
              <p>No live alerts yet. Trigger an ingestion in Swagger UI to see real-time updates!</p>
            </div>
          ) : (
            alerts.map((alert) => (
              <div key={alert.id} className={`p-4 hover:bg-gray-800/50 transition-colors border-l-4 ${getSeverityColor(alert.severity).split(' ')[2]}`}>
                <div className="flex justify-between items-start mb-2">
                  <span className={`text-xs font-bold uppercase px-2 py-1 rounded ${getSeverityColor(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <span className="text-xs text-gray-500 font-mono">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <h4 className="text-gray-200 font-medium mb-1">{alert.title}</h4>
              </div>
            ))
          )}
        </div>
      </div>
        </>
      )}
    </div>
  );
}