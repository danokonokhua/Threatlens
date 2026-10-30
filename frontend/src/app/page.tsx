'use client';

import { useEffect, useState, useCallback } from 'react';
import { useAlertStream } from '@/hooks/useAlertStream';
import { SeverityDistribution, AlertTrends, IndicatorTypes } from '@/components/DashboardCharts';
import { FeedsManager } from '@/components/FeedsManager';
import { IncidentResponseView } from '@/components/IncidentResponseView';
import { ThreatHuntingView } from '@/components/ThreatHuntingView';
import { GlobalAttackHeatmap } from '@/components/GlobalAttackHeatmap';
import { ExecutiveOverviewView } from '@/components/ExecutiveOverviewView';
import { ExportReportsCenter } from '@/components/ExportReportsCenter';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  CheckCircle, 
  Terminal, 
  RefreshCw, 
  FolderKanban, 
  Crosshair, 
  ShieldCheck, 
  ArrowDownToLine,
  KeyRound,
  LogOut,
  UserCheck
} from 'lucide-react';

// Helper to check if a JWT is still valid (not expired)
function isTokenValid(jwtStr: string): boolean {
  if (!jwtStr) return false;
  try {
    const parts = jwtStr.split('.');
    if (parts.length !== 3) return false;
    // Decode base64 payload safely
    const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(payloadJson);
    if (!payload.exp) return true;
    // Check if token expires at least 30 seconds from now
    return payload.exp * 1000 > Date.now() + 30000;
  } catch {
    return false;
  }
}

export default function SOC_Dashboard() {
  const { alerts, isConnected } = useAlertStream();
  const [token, setToken] = useState('');
  const [indicators, setIndicators] = useState<any[]>([]);
  const [allAlerts, setAllAlerts] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [activeTab, setActiveTab] = useState<'soc' | 'incident_response' | 'threat_hunting' | 'executive' | 'export_reports'>('soc');

  // Automatic demo login with seeded admin credentials
  const loginAsAdmin = useCallback(async (): Promise<string | null> => {
    setIsLoggingIn(true);
    try {
      const formData = new URLSearchParams();
      formData.append('username', 'admin@threatlens.local');
      formData.append('password', 'admin123');

      const res = await fetch('http://localhost:8000/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
      });

      if (res.ok) {
        const data = await res.json();
        if (data.access_token) {
          setToken(data.access_token);
          if (typeof window !== 'undefined') {
            localStorage.setItem('threatlens_token', data.access_token);
          }
          return data.access_token;
        }
      }
    } catch (err) {
      console.warn('Auto-login to backend failed:', err);
    } finally {
      setIsLoggingIn(false);
    }
    return null;
  }, []);

  // Fetch data when token is provided, with transparent 401 auto-renewal
  const fetchData = useCallback(async (tokenToUse?: string) => {
    const currentToken = tokenToUse || token;
    if (!currentToken) return;

    setIsLoading(true);
    try {
      const headers = { 'Authorization': `Bearer ${currentToken}` };
      
      const [indicatorsRes, alertsRes] = await Promise.all([
        fetch('http://localhost:8000/api/v1/indicators', { headers }),
        fetch('http://localhost:8000/api/v1/alerts?status_filter=new&limit=100', { headers })
      ]);

      // If token expired or is invalid, automatically renew session & re-fetch
      if (indicatorsRes.status === 401 || alertsRes.status === 401) {
        console.warn('Token expired or unauthorized (401). Auto-renewing session...');
        if (typeof window !== 'undefined') {
          localStorage.removeItem('threatlens_token');
        }
        const freshToken = await loginAsAdmin();
        if (freshToken) {
          return fetchData(freshToken);
        }
        return;
      }

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
  }, [token, loginAsAdmin]);

  // Restore saved token from localStorage on initial load, or auto-login seamlessly
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const savedToken = localStorage.getItem('threatlens_token');
      if (savedToken && isTokenValid(savedToken)) {
        setToken(savedToken);
      } else {
        loginAsAdmin();
      }
    }
  }, [loginAsAdmin]);

  // Trigger data fetch whenever token state changes
  useEffect(() => {
    if (token) {
      fetchData(token);
    }
  }, [token, fetchData]);

  const handleTokenChange = (val: string) => {
    setToken(val);
    if (typeof window !== 'undefined') {
      if (val) {
        localStorage.setItem('threatlens_token', val);
      } else {
        localStorage.removeItem('threatlens_token');
      }
    }
  };

  const logout = () => {
    setToken('');
    if (typeof window !== 'undefined') {
      localStorage.removeItem('threatlens_token');
    }
    setIndicators([]);
    setAllAlerts([]);
  };

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
        
        {/* Auth Controls & Status */}
        <div className="flex flex-wrap items-center gap-2">
          {token ? (
            <div className="flex items-center gap-2 bg-emerald-950/40 border border-emerald-800/60 px-3 py-1.5 rounded-lg text-xs text-emerald-300">
              <UserCheck size={14} className="text-emerald-400" />
              <span>Admin Connected</span>
              <button 
                onClick={logout}
                title="Disconnect / Clear Token"
                className="ml-1 text-gray-400 hover:text-red-400 transition-colors"
              >
                <LogOut size={13} />
              </button>
            </div>
          ) : (
            <button
              onClick={() => loginAsAdmin()}
              disabled={isLoggingIn}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              <KeyRound size={14} className={isLoggingIn ? 'animate-spin' : ''} />
              <span>{isLoggingIn ? 'Connecting...' : 'Quick Login (Admin)'}</span>
            </button>
          )}

          <div className="flex items-center gap-2 bg-gray-900 p-1.5 rounded-lg border border-gray-800">
            <Terminal size={14} className="text-gray-500 ml-1" />
            <input 
              type="password" 
              placeholder="Paste Bearer Token..." 
              className="bg-transparent border-none outline-none text-xs w-48 text-gray-300 placeholder-gray-600 font-mono"
              value={token}
              onChange={(e) => handleTokenChange(e.target.value)}
            />
            <button 
              onClick={() => fetchData()}
              disabled={isLoading || !token}
              title="Refresh Data"
              className="p-1.5 bg-blue-600 hover:bg-blue-700 rounded text-white transition-colors disabled:opacity-50"
            >
              <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
            </button>
          </div>
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
      <FeedsManager token={token} onFeedsUpdated={() => fetchData()} />

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

        <div className="divide-y border-gray-800 max-h-[400px] overflow-y-auto">
          {alerts.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              <CheckCircle className="mx-auto mb-3 opacity-50" size={48} />
              <p>No live alerts yet. Trigger an ingestion in Swagger UI or Feeds Manager to see real-time updates!</p>
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
