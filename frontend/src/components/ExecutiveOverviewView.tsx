'use client';

import { useState, useEffect } from 'react';
import { 
  ShieldCheck, AlertOctagon, TrendingUp, Activity, CheckCircle2, 
  Clock, ShieldAlert, ArrowUpRight, Copy, Check, RefreshCw, FileText, Printer
} from 'lucide-react';
import { 
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, Legend 
} from 'recharts';

interface TopCategory {
  category: string;
  count: number;
  percentage: number;
}

interface ThroughputDay {
  date: string;
  ingested: number;
  resolved: number;
}

interface RiskTrendDay {
  day: string;
  risk_score: number;
}

interface ExecutivePostureData {
  headline_risk_score: number;
  risk_level: string;
  risk_trend_pct: string;
  total_indicators: number;
  active_critical_high: number;
  critical_indicators: number;
  high_indicators: number;
  total_alerts: number;
  resolved_alerts: number;
  open_alerts: number;
  resolution_rate_pct: number;
  mtt_triage_seconds: number;
  trend_30_days: RiskTrendDay[];
  top_categories: TopCategory[];
  throughput_7_days: ThroughputDay[];
  executive_briefing: string;
}

export function ExecutiveOverviewView({ token }: { token: string }) {
  const [data, setData] = useState<ExecutivePostureData | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const fetchPosture = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/analytics/executive-posture', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const postureData: ExecutivePostureData = await res.json();
        setData(postureData);
      }
    } catch (err) {
      console.error('Failed to load executive posture:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPosture();
  }, [token]);

  const handleCopyBriefing = () => {
    if (!data?.executive_briefing) return;
    navigator.clipboard.writeText(data.executive_briefing);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 85) return 'text-red-400 bg-red-500/10 border-red-500/40';
    if (score >= 70) return 'text-orange-400 bg-orange-500/10 border-orange-500/40';
    if (score >= 50) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/40';
    return 'text-green-400 bg-green-500/10 border-green-500/40';
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-amber-400" size={24} />
            <h2 className="text-xl font-bold text-gray-100">
              Executive Threat Posture & Board Overview
            </h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-amber-950 text-amber-400 border border-amber-800">
              Persona: Rachel Adeyemi (CISO)
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Section 12.1: Macro risk posture, 30-day exposure trajectory, threat categorization, and SOC throughput metrics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyBriefing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs rounded-lg border border-gray-700 transition-colors"
          >
            {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy Briefing'}
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs rounded-lg border border-gray-700 transition-colors"
          >
            <Printer size={14} />
            Print Report
          </button>
          <button
            onClick={fetchPosture}
            disabled={loading || !token}
            className="p-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {loading && !data ? (
        <div className="p-16 text-center text-gray-500 text-sm flex items-center justify-center gap-2">
          <RefreshCw className="animate-spin" size={18} />
          Calculating executive risk posture...
        </div>
      ) : data ? (
        <div className="space-y-6">
          {/* Top KPI Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Headline Risk Score */}
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <div className="flex justify-between items-start mb-2">
                <span className="text-xs text-gray-400 font-medium">Headline Risk Score</span>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${getRiskScoreColor(data.headline_risk_score)}`}>
                  {data.risk_level}
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-gray-100">{data.headline_risk_score}</span>
                <span className="text-xs text-gray-500">/ 100</span>
                <span className="text-xs text-red-400 flex items-center ml-auto font-medium">
                  <TrendingUp size={13} className="mr-0.5" /> {data.risk_trend_pct}
                </span>
              </div>
              <p className="text-[11px] text-gray-500 mt-2">Aggregate 30-day exposure score</p>
            </div>

            {/* Active Critical/High Threats */}
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <div className="flex justify-between items-start mb-2">
                <span className="text-xs text-gray-400 font-medium">Critical / High Threats</span>
                <AlertOctagon size={16} className="text-red-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-gray-100">{data.active_critical_high}</span>
                <span className="text-xs text-gray-500">of {data.total_indicators} total</span>
              </div>
              <div className="flex items-center gap-3 text-[11px] mt-2 text-gray-400">
                <span className="text-red-400 font-medium">{data.critical_indicators} critical</span>
                <span>•</span>
                <span className="text-orange-400 font-medium">{data.high_indicators} high</span>
              </div>
            </div>

            {/* SOC Alert Resolution Rate */}
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <div className="flex justify-between items-start mb-2">
                <span className="text-xs text-gray-400 font-medium">Alert Resolution Rate</span>
                <CheckCircle2 size={16} className="text-green-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-gray-100">{data.resolution_rate_pct}%</span>
                <span className="text-xs text-green-400 ml-auto font-medium">&gt;85% Target</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-2">
                {data.resolved_alerts} resolved / {data.open_alerts} open
              </p>
            </div>

            {/* Mean Time to Triage */}
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <div className="flex justify-between items-start mb-2">
                <span className="text-xs text-gray-400 font-medium">Mean Time to Triage (MTTA)</span>
                <Clock size={16} className="text-cyan-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-gray-100">{data.mtt_triage_seconds}s</span>
                <span className="text-xs text-cyan-400 ml-auto font-medium">SLA &le;90s Target</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-2">Instrumented analyst triage latency</p>
            </div>
          </div>

          {/* Automated CISO Executive Briefing */}
          <div className="bg-amber-950/20 border border-amber-800/40 p-5 rounded-xl">
            <div className="flex items-center gap-2 mb-2">
              <FileText size={16} className="text-amber-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-300">
                Automated Executive Briefing & Board Summary
              </h3>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed font-sans">
              {data.executive_briefing}
            </p>
          </div>

          {/* Charts Row: 30-Day Trend (Left) & 7-Day Ingestion vs Resolution Throughput (Right) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* 30-Day Exposure Trend Chart */}
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <h3 className="text-sm font-semibold text-gray-200 mb-1 flex items-center gap-2">
                <Activity size={15} className="text-amber-400" />
                30-Day Organizational Risk Trajectory
              </h3>
              <p className="text-xs text-gray-500 mb-4">Historical score trend evaluating exposure and mitigation impact.</p>

              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={data.trend_30_days}>
                  <defs>
                    <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="day" stroke="#6b7280" fontSize={10} interval={4} />
                  <YAxis stroke="#6b7280" domain={[0, 100]} fontSize={10} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', fontSize: '12px' }}
                    itemStyle={{ color: '#f59e0b' }}
                  />
                  <Area type="monotone" dataKey="risk_score" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#riskGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* 7-Day Alert Throughput Chart */}
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <h3 className="text-sm font-semibold text-gray-200 mb-1 flex items-center gap-2">
                <TrendingUp size={15} className="text-cyan-400" />
                SOC Alert Throughput (Ingested vs. Resolved)
              </h3>
              <p className="text-xs text-gray-500 mb-4">Demonstrating operational velocity keeping pace with incoming feeds.</p>

              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={data.throughput_7_days}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="date" stroke="#6b7280" fontSize={10} />
                  <YAxis stroke="#6b7280" fontSize={10} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Bar dataKey="ingested" name="Ingested Alerts" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="resolved" name="Resolved Alerts" fill="#10b981" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Bottom Row: Top Threat Categories Breakdown */}
          <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
            <h3 className="text-sm font-semibold text-gray-200 mb-1 flex items-center gap-2">
              <ShieldAlert size={15} className="text-orange-400" />
              Top Threat Vectors & Exposure Categories
            </h3>
            <p className="text-xs text-gray-500 mb-4">Proportion of intelligence indicators categorized by threat behavior.</p>

            <div className="space-y-3">
              {data.top_categories.map((cat, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-medium text-gray-200">{cat.category}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">{cat.count} indicators</span>
                      <span className="font-mono font-bold text-amber-400">{cat.percentage}%</span>
                    </div>
                  </div>
                  <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-gradient-to-r from-amber-500 to-orange-500 rounded-full transition-all duration-500"
                      style={{ width: `${cat.percentage}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-16 text-center text-gray-500 text-sm">
          Please provide a valid authentication token to inspect executive posture.
        </div>
      )}
    </div>
  );
}

