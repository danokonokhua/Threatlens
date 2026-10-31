'use client';
import { getApiBaseUrl } from '@/lib/api';


import { useState, useEffect } from 'react';
import { 
  Download, FileSpreadsheet, FileCode, FileText, Printer, 
  Plus, RefreshCw, Check, X, Shield, ArrowDownToLine, Layers
} from 'lucide-react';

interface ReportSummary {
  id: string;
  title: string;
  report_type: string;
  summary: string;
  created_at: string;
}

interface ReportDetail {
  id: string;
  title: string;
  report_type: string;
  summary: string;
  created_at: string;
  sections: {
    generated_at: string;
    generated_by: string;
    executive_summary: string;
    threat_landscape_metrics: {
      total_indicators: number;
      critical_indicators: number;
      active_alerts: number;
      investigations_count: number;
    };
    top_threat_indicators: Array<{
      value: string;
      type: string;
      severity_score: number;
      confidence: number;
    }>;
    active_investigations: Array<{
      title: string;
      severity: string;
      status: string;
      created_at: string;
    }>;
    strategic_recommendations: string[];
  };
}

export function ExportReportsCenter({ token }: { token: string }) {
  // Export Filters
  const [minScore, setMinScore] = useState(0);
  const [exportType, setExportType] = useState('');
  const [downloadingStix, setDownloadingStix] = useState(false);
  const [downloadingCsv, setDownloadingCsv] = useState(false);

  // Reports
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportTitle, setReportTitle] = useState('');
  const [selectedReport, setSelectedReport] = useState<ReportDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const fetchReports = async () => {
    if (!token) return;
    setLoadingReports(true);
    try {
      const res = await fetch(`${getApiBaseUrl()}/api/v1/reports`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setReports(data);
      }
    } catch (err) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoadingReports(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [token]);

  const handleDownloadStix = async () => {
    setDownloadingStix(true);
    try {
      const url = `http://localhost:8000/api/v1/export/stix?min_score=${minScore}&type=${exportType}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `threatlens_stix21_bundle_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (err) {
      console.error('STIX download failed:', err);
    } finally {
      setDownloadingStix(false);
    }
  };

  const handleDownloadCsv = async () => {
    setDownloadingCsv(true);
    try {
      const url = `http://localhost:8000/api/v1/export/csv?min_score=${minScore}&type=${exportType}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `threatlens_indicators_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (err) {
      console.error('CSV download failed:', err);
    } finally {
      setDownloadingCsv(false);
    }
  };

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setGeneratingReport(true);
    try {
      const res = await fetch(`${getApiBaseUrl()}/api/v1/reports`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          title: reportTitle.trim() || undefined,
          report_type: 'executive_summary'
        })
      });
      if (res.ok) {
        const createdReport = await res.json();
        setReportTitle('');
        fetchReports();
        setSelectedReport(createdReport);
      }
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleViewReport = async (reportId: string) => {
    setLoadingDetail(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/reports/${reportId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const detail = await res.json();
        setSelectedReport(detail);
      }
    } catch (err) {
      console.error('Failed to load report detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ArrowDownToLine className="text-cyan-400" size={24} />
            <h2 className="text-xl font-bold text-gray-100">
              Intelligence Export & Reporting Hub
            </h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
              FR-23 / FR-24 (STIX 2.1 & PDF)
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Export standard OASIS STIX 2.1 bundles, CSV feeds, and generate executive threat intelligence reports.
          </p>
        </div>

        <button
          onClick={fetchReports}
          disabled={loadingReports || !token}
          className="p-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw size={16} className={loadingReports ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: STIX 2.1 & CSV Downstream Integration (FR-24) */}
        <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Layers size={18} className="text-cyan-400" />
              <h3 className="text-sm font-semibold text-gray-200">
                Operational Export (STIX 2.1 / CSV)
              </h3>
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Export canonical indicators formatted for direct integration into SIEM (Splunk, Microsoft Sentinel), 
              SOAR playbooks, and perimeter edge firewalls.
            </p>

            {/* Export Filter Controls */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6 bg-gray-900/60 p-3 rounded-lg border border-gray-800">
              <div>
                <label className="block text-[11px] font-semibold text-gray-400 mb-1">
                  Minimum Severity Score
                </label>
                <select
                  value={minScore}
                  onChange={(e) => setMinScore(Number(e.target.value))}
                  className="w-full bg-gray-950 border border-gray-800 text-xs text-gray-200 rounded-lg p-2 outline-none focus:border-cyan-500"
                >
                  <option value={0}>All Severity Levels (&ge;0)</option>
                  <option value={60}>Moderate & Above (&ge;60)</option>
                  <option value={75}>High & Critical Only (&ge;75)</option>
                  <option value={85}>Critical Threats Only (&ge;85)</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-gray-400 mb-1">
                  IOC Type Filter
                </label>
                <select
                  value={exportType}
                  onChange={(e) => setExportType(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 text-xs text-gray-200 rounded-lg p-2 outline-none focus:border-cyan-500"
                >
                  <option value="">All Indicator Types</option>
                  <option value="ip">IPv4 Addresses (C2)</option>
                  <option value="domain">Domains / Hosts</option>
                  <option value="url">Malicious URLs</option>
                  <option value="hash_sha256">SHA-256 Hashes</option>
                  <option value="cve">CVE Vulnerabilities</option>
                </select>
              </div>
            </div>
          </div>

          {/* Action Download Buttons */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-3 border-t border-gray-800">
            <button
              onClick={handleDownloadStix}
              disabled={downloadingStix || !token}
              className="flex items-center justify-center gap-2 p-3 bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs rounded-lg transition-colors disabled:opacity-50"
            >
              <FileCode size={16} />
              {downloadingStix ? 'Generating STIX...' : 'Download STIX 2.1 (.json)'}
            </button>

            <button
              onClick={handleDownloadCsv}
              disabled={downloadingCsv || !token}
              className="flex items-center justify-center gap-2 p-3 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium text-xs rounded-lg border border-gray-700 transition-colors disabled:opacity-50"
            >
              <FileSpreadsheet size={16} />
              {downloadingCsv ? 'Exporting CSV...' : 'Download CSV Feed (.csv)'}
            </button>
          </div>
        </div>

        {/* Right Column: On-Demand Report Generator (FR-23) */}
        <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <FileText size={18} className="text-amber-400" />
              <h3 className="text-sm font-semibold text-gray-200">
                On-Demand Threat Intelligence Reports (FR-23)
              </h3>
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Compile formal CTI assessments containing executive summaries, high-severity indicator catalogs, 
              incident statistics, and defensive mitigation steps.
            </p>

            <form onSubmit={handleGenerateReport} className="mb-4">
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Report Title (e.g. Q4 Executive Threat Landscape Briefing)"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  className="flex-1 bg-gray-900 border border-gray-800 text-xs rounded-lg p-2.5 text-gray-200 outline-none focus:border-amber-500"
                />
                <button
                  type="submit"
                  disabled={generatingReport || !token}
                  className="px-4 py-2.5 bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs rounded-lg transition-colors flex items-center gap-1.5 shrink-0 disabled:opacity-50"
                >
                  <Plus size={14} className={generatingReport ? 'animate-spin' : ''} />
                  Generate Report
                </button>
              </div>
            </form>
          </div>

          {/* Past Reports List */}
          <div>
            <h4 className="text-xs font-semibold text-gray-400 mb-2">Generated Reports Archive</h4>
            <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
              {loadingReports && reports.length === 0 ? (
                <p className="text-xs text-gray-500 italic">Loading reports...</p>
              ) : reports.length === 0 ? (
                <p className="text-xs text-gray-500 italic">No reports generated yet. Click "Generate Report" above.</p>
              ) : (
                reports.map((r) => (
                  <div
                    key={r.id}
                    onClick={() => handleViewReport(r.id)}
                    className="p-2.5 bg-gray-900/70 border border-gray-800 rounded-lg flex justify-between items-center cursor-pointer hover:border-amber-500/50 transition-colors text-xs"
                  >
                    <div>
                      <div className="font-semibold text-gray-200 truncate max-w-xs">{r.title}</div>
                      <div className="text-[10px] text-gray-500">{new Date(r.created_at).toLocaleString()}</div>
                    </div>
                    <span className="text-amber-400 font-medium text-xs flex items-center gap-1">
                      View Report &rarr;
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Modal: Interactive Report Viewer & Print Dialog (FR-23) */}
      {selectedReport && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Report Header */}
            <div className="flex justify-between items-start mb-6 border-b border-gray-800 pb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="text-amber-400" size={20} />
                  <span className="text-xs font-bold font-mono uppercase tracking-wider text-amber-400">
                    ThreatLens Cyber Threat Intelligence Report
                  </span>
                </div>
                <h2 className="text-xl font-bold text-gray-100">{selectedReport.title}</h2>
                <p className="text-xs text-gray-400 mt-1">
                  Generated by {selectedReport.sections.generated_by} on {new Date(selectedReport.created_at).toLocaleString()}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => window.print()}
                  className="p-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs flex items-center gap-1.5"
                >
                  <Printer size={14} />
                  Print / PDF
                </button>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="p-2 text-gray-400 hover:text-gray-200"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Executive Summary Section */}
            <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 mb-6">
              <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2">1. Executive Summary</h3>
              <p className="text-xs text-gray-300 leading-relaxed">{selectedReport.summary}</p>
            </div>

            {/* Key Metrics Snapshot */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                <span className="text-[10px] text-gray-400 uppercase font-semibold">Total Indicators</span>
                <div className="text-lg font-bold text-gray-100 mt-1">
                  {selectedReport.sections.threat_landscape_metrics.total_indicators}
                </div>
              </div>
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                <span className="text-[10px] text-gray-400 uppercase font-semibold">Critical Threats</span>
                <div className="text-lg font-bold text-red-400 mt-1">
                  {selectedReport.sections.threat_landscape_metrics.critical_indicators}
                </div>
              </div>
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                <span className="text-[10px] text-gray-400 uppercase font-semibold">Security Alerts</span>
                <div className="text-lg font-bold text-orange-400 mt-1">
                  {selectedReport.sections.threat_landscape_metrics.active_alerts}
                </div>
              </div>
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                <span className="text-[10px] text-gray-400 uppercase font-semibold">Investigations</span>
                <div className="text-lg font-bold text-purple-400 mt-1">
                  {selectedReport.sections.threat_landscape_metrics.investigations_count}
                </div>
              </div>
            </div>

            {/* Top Threat Indicators Table */}
            <div className="mb-6">
              <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2">
                2. High-Risk Threat Indicators Catalog
              </h3>
              <div className="bg-gray-950 border border-gray-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs text-gray-300">
                  <thead className="bg-gray-900 text-gray-400 uppercase text-[10px] border-b border-gray-800">
                    <tr>
                      <th className="py-2.5 px-3">Indicator Value</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Severity Score</th>
                      <th className="py-2.5 px-3">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60 font-mono text-[11px]">
                    {selectedReport.sections.top_threat_indicators.map((ind, i) => (
                      <tr key={i} className="hover:bg-gray-900/40">
                        <td className="py-2 px-3 text-cyan-300 truncate max-w-sm">{ind.value}</td>
                        <td className="py-2 px-3 uppercase text-gray-400">{ind.type}</td>
                        <td className="py-2 px-3 font-bold text-red-400">{ind.severity_score} / 100</td>
                        <td className="py-2 px-3 text-gray-400">{ind.confidence}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Strategic Defensive Recommendations */}
            <div className="bg-gray-950 p-4 rounded-xl border border-gray-800">
              <h3 className="text-xs font-bold uppercase tracking-wider text-green-400 mb-2">
                3. Strategic Mitigation & SOC Defensive Actions
              </h3>
              <ul className="space-y-1.5 text-xs text-gray-300 list-disc list-inside">
                {selectedReport.sections.strategic_recommendations.map((rec, i) => (
                  <li key={i} className="leading-relaxed">{rec}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

