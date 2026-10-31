'use client';
import { getApiBaseUrl } from '@/lib/api';


import { useState, useEffect } from 'react';
import { 
  FolderKanban, Plus, Clock, CheckCircle2, AlertTriangle, 
  FileText, Shield, Activity, ArrowRight, CheckSquare, 
  Square, RefreshCw, ChevronRight, X
} from 'lucide-react';

interface Incident {
  id: string;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  alert_count: number;
  created_at: string;
}

interface TimelineEvent {
  id: string;
  event_type: string;
  title: string;
  description: string | null;
  source: string;
  timestamp: string;
}

interface LinkedAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  indicator_value: string | null;
  indicator_type: string | null;
  created_at: string;
}

interface IncidentDetail extends Incident {
  alerts: LinkedAlert[];
  timeline: TimelineEvent[];
}

const DEFAULT_CONTAINMENT_STEPS = [
  "Isolate infected host from internal network",
  "Block malicious C2 IP and URL on perimeter firewall/proxy",
  "Sinkhole malicious domain on internal recursive DNS",
  "Revoke compromised credentials and terminate active sessions",
  "Acquire forensic memory dump & triage system artifacts"
];

export function IncidentResponseView({ token }: { token: string }) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Form states
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newSeverity, setNewSeverity] = useState('high');

  // Timeline note state
  const [noteTitle, setNoteTitle] = useState('');
  const [noteDesc, setNoteDesc] = useState('');
  const [noteType, setNoteType] = useState('note');
  const [submittingNote, setSubmittingNote] = useState(false);

  // Available alerts to link
  const [availableAlerts, setAvailableAlerts] = useState<any[]>([]);
  const [showLinkModal, setShowLinkModal] = useState(false);

  const fetchIncidents = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const url = statusFilter === 'all' 
        ? `${getApiBaseUrl()}/api/v1/incidents` 
        : `http://localhost:8000/api/v1/incidents?status_filter=${statusFilter}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setIncidents(data);
        if (data.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchIncidentDetail = async (id: string) => {
    if (!token || !id) return;
    setLoadingDetail(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setIncidentDetail(data);
      }
    } catch (err) {
      console.error('Failed to fetch incident details:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [token, statusFilter]);

  useEffect(() => {
    if (selectedIncidentId) {
      fetchIncidentDetail(selectedIncidentId);
    }
  }, [selectedIncidentId, token]);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      const res = await fetch(`${getApiBaseUrl()}/api/v1/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          title: newTitle,
          description: newDesc,
          severity: newSeverity
        })
      });
      if (res.ok) {
        const created = await res.json();
        setNewTitle('');
        setNewDesc('');
        setShowCreateModal(false);
        fetchIncidents();
        setSelectedIncidentId(created.id);
      }
    } catch (err) {
      console.error('Failed to create incident:', err);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedIncidentId) return;
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncidentId}?status=${newStatus}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        fetchIncidents();
        fetchIncidentDetail(selectedIncidentId);
      }
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  const handleAddTimelineEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncidentId || !noteTitle.trim()) return;
    setSubmittingNote(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncidentId}/timeline`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          event_type: noteType,
          title: noteTitle,
          description: noteDesc,
          source: 'analyst'
        })
      });
      if (res.ok) {
        setNoteTitle('');
        setNoteDesc('');
        fetchIncidentDetail(selectedIncidentId);
      }
    } catch (err) {
      console.error('Failed to add timeline event:', err);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleContainmentCheck = async (stepText: string) => {
    if (!selectedIncidentId) return;
    try {
      await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncidentId}/timeline`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          event_type: 'containment',
          title: `Containment Executed: ${stepText}`,
          description: `Responder verified containment control: "${stepText}"`,
          source: 'analyst'
        })
      });
      fetchIncidentDetail(selectedIncidentId);
    } catch (err) {
      console.error('Failed to log containment step:', err);
    }
  };

  const fetchUnlinkedAlerts = async () => {
    try {
      const res = await fetch(`${getApiBaseUrl()}/api/v1/alerts?limit=50`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAvailableAlerts(data);
        setShowLinkModal(true);
      }
    } catch (err) {
      console.error('Failed to load alerts:', err);
    }
  };

  const linkAlert = async (alertId: string) => {
    if (!selectedIncidentId) return;
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncidentId}/alerts/${alertId}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        fetchIncidentDetail(selectedIncidentId);
        fetchIncidents();
        setShowLinkModal(false);
      }
    } catch (err) {
      console.error('Failed to link alert:', err);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'resolved':
      case 'closed':
        return 'bg-green-500/20 text-green-400 border-green-500/40';
      case 'investigating':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/40';
      default:
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    }
  };

  const getTimelineIcon = (eventType: string) => {
    switch (eventType) {
      case 'created':
        return <Shield className="text-cyan-400" size={16} />;
      case 'alert_linked':
        return <AlertTriangle className="text-orange-400" size={16} />;
      case 'status_change':
        return <Activity className="text-purple-400" size={16} />;
      case 'containment':
        return <CheckCircle2 className="text-green-400" size={16} />;
      default:
        return <FileText className="text-blue-400" size={16} />;
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <FolderKanban className="text-purple-400" size={24} />
            <h2 className="text-xl font-bold text-gray-100">
              Incident Response Workspace
            </h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-purple-950 text-purple-400 border border-purple-800">
              Persona: Daniel Okafor (IR Lead)
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Investigation records, correlated alerts, containment checklist, and chronological audit timeline (FR-19).
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Status Filter */}
          <div className="flex bg-gray-950 rounded-lg p-1 border border-gray-800 text-xs">
            {['all', 'open', 'investigating', 'resolved'].map((f) => (
              <button
                key={f}
                onClick={() => setStatusFilter(f)}
                className={`px-3 py-1 rounded capitalize transition-colors ${
                  statusFilter === f
                    ? 'bg-purple-600 text-white font-medium'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 text-white font-medium text-sm rounded-lg transition-colors"
          >
            <Plus size={16} />
            New Incident
          </button>
        </div>
      </div>

      {/* Main Grid: Incident List on Left (1/3), Investigation Workspace on Right (2/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Incidents List */}
        <div className="space-y-3 max-h-[700px] overflow-y-auto pr-1">
          {loading && incidents.length === 0 ? (
            <div className="p-8 text-center text-gray-500 text-sm flex items-center justify-center gap-2">
              <RefreshCw className="animate-spin" size={16} />
              Loading investigations...
            </div>
          ) : incidents.length === 0 ? (
            <div className="p-8 text-center text-gray-500 text-sm border border-dashed border-gray-800 rounded-xl">
              No incidents found in this filter.
            </div>
          ) : (
            incidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => setSelectedIncidentId(inc.id)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  selectedIncidentId === inc.id
                    ? 'bg-purple-950/30 border-purple-600/70 shadow-lg shadow-purple-950/40'
                    : 'bg-gray-950/60 border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex justify-between items-start gap-2 mb-1.5">
                  <h3 className="font-semibold text-gray-100 text-sm line-clamp-1">{inc.title}</h3>
                  <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${getSeverityBadge(inc.severity)}`}>
                    {inc.severity}
                  </span>
                </div>
                {inc.description && (
                  <p className="text-xs text-gray-400 line-clamp-2 mb-3">{inc.description}</p>
                )}
                <div className="flex items-center justify-between text-xs text-gray-500 pt-2 border-t border-gray-800/60">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] uppercase border font-semibold ${getStatusBadge(inc.status)}`}>
                    {inc.status}
                  </span>
                  <div className="flex items-center gap-1 text-gray-400">
                    <AlertTriangle size={12} className="text-orange-400" />
                    <span>{inc.alert_count} alerts</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right Columns: Active Incident Workspace (2 Cols) */}
        <div className="lg:col-span-2 space-y-6">
          {loadingDetail ? (
            <div className="p-16 text-center text-gray-500 text-sm flex items-center justify-center gap-2 bg-gray-950/40 rounded-xl border border-gray-800">
              <RefreshCw className="animate-spin" size={18} />
              Loading investigation timeline...
            </div>
          ) : incidentDetail ? (
            <>
              {/* Workspace Header */}
              <div className="bg-gray-950/80 border border-gray-800 p-5 rounded-xl">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs uppercase font-bold px-2.5 py-0.5 rounded border ${getSeverityBadge(incidentDetail.severity)}`}>
                        {incidentDetail.severity}
                      </span>
                      <h2 className="text-lg font-bold text-gray-100">{incidentDetail.title}</h2>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">
                      Opened: {new Date(incidentDetail.created_at).toLocaleString()}
                    </p>
                  </div>

                  {/* Status Dropdown */}
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">Status:</span>
                    <select
                      value={incidentDetail.status}
                      onChange={(e) => handleStatusChange(e.target.value)}
                      className="bg-gray-900 border border-gray-700 text-xs text-gray-200 rounded-lg px-2.5 py-1.5 outline-none focus:border-purple-500"
                    >
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="contained">Contained</option>
                      <option value="resolved">Resolved</option>
                      <option value="closed">Closed</option>
                    </select>
                  </div>
                </div>

                {incidentDetail.description && (
                  <p className="text-xs text-gray-300 bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                    {incidentDetail.description}
                  </p>
                )}
              </div>

              {/* Linked Alerts Section */}
              <div className="bg-gray-950/60 border border-gray-800 p-5 rounded-xl">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                    <AlertTriangle size={15} className="text-orange-400" />
                    Correlated Alerts ({incidentDetail.alerts.length})
                  </h3>
                  <button
                    onClick={fetchUnlinkedAlerts}
                    className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1"
                  >
                    <Plus size={13} /> Link Alert
                  </button>
                </div>

                {incidentDetail.alerts.length === 0 ? (
                  <p className="text-xs text-gray-500 italic">No alerts linked to this incident yet.</p>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {incidentDetail.alerts.map((alt) => (
                      <div key={alt.id} className="p-2.5 rounded-lg bg-gray-900/70 border border-gray-800 text-xs">
                        <div className="flex justify-between items-start gap-2 mb-1">
                          <span className="font-medium text-gray-200 line-clamp-1">{alt.title}</span>
                          <span className={`text-[9px] uppercase font-bold px-1.5 py-0.2 rounded border ${getSeverityBadge(alt.severity)}`}>
                            {alt.severity}
                          </span>
                        </div>
                        {alt.indicator_value && (
                          <div className="font-mono text-[11px] text-cyan-400 truncate">
                            IOC: {alt.indicator_value} ({alt.indicator_type})
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Containment Checklist */}
              <div className="bg-gray-950/60 border border-gray-800 p-5 rounded-xl">
                <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
                  <CheckSquare size={15} className="text-green-400" />
                  Containment Checklist
                </h3>
                <div className="space-y-2">
                  {DEFAULT_CONTAINMENT_STEPS.map((step, idx) => {
                    const isExecuted = incidentDetail.timeline.some(
                      t => t.event_type === 'containment' && t.title.includes(step)
                    );
                    return (
                      <div
                        key={idx}
                        onClick={() => !isExecuted && handleContainmentCheck(step)}
                        className={`flex items-center gap-3 p-2.5 rounded-lg border text-xs cursor-pointer transition-colors ${
                          isExecuted
                            ? 'bg-green-950/20 border-green-800/40 text-green-300'
                            : 'bg-gray-900/60 border-gray-800 text-gray-300 hover:border-gray-700'
                        }`}
                      >
                        {isExecuted ? (
                          <CheckCircle2 size={16} className="text-green-400 shrink-0" />
                        ) : (
                          <Square size={16} className="text-gray-500 shrink-0" />
                        )}
                        <span className={isExecuted ? 'line-through text-gray-400' : ''}>
                          {step}
                        </span>
                        {isExecuted && (
                          <span className="ml-auto text-[10px] text-green-400 font-medium">Logged to timeline</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Append-Only Chronological Timeline (FR-19) */}
              <div className="bg-gray-950/80 border border-gray-800 p-5 rounded-xl">
                <div className="flex justify-between items-center mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                      <Clock size={15} className="text-cyan-400" />
                      Append-Only Incident Timeline (FR-19)
                    </h3>
                    <p className="text-[11px] text-gray-500 mt-0.5">
                      Immutable sequence of alerts, status changes, and analyst actions.
                    </p>
                  </div>
                  <span className="text-xs font-mono text-gray-400 bg-gray-900 px-2 py-1 rounded border border-gray-800">
                    {incidentDetail.timeline.length} events
                  </span>
                </div>

                {/* Vertical Timeline Tree */}
                <div className="relative pl-6 space-y-6 before:content-[''] before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-gray-800">
                  {incidentDetail.timeline.map((event) => (
                    <div key={event.id} className="relative group">
                      {/* Timeline Node Icon */}
                      <div className="absolute -left-6 top-0.5 w-5 h-5 rounded-full bg-gray-900 border border-gray-700 flex items-center justify-center">
                        {getTimelineIcon(event.event_type)}
                      </div>

                      <div className="bg-gray-900/70 border border-gray-800/80 rounded-lg p-3 text-xs">
                        <div className="flex justify-between items-start gap-2 mb-1">
                          <span className="font-semibold text-gray-200">{event.title}</span>
                          <span className="text-[10px] text-gray-500 shrink-0">
                            {new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </span>
                        </div>
                        {event.description && (
                          <p className="text-gray-400 mt-1 leading-relaxed">{event.description}</p>
                        )}
                        <div className="flex items-center gap-2 mt-2 pt-2 border-t border-gray-800/40 text-[10px] text-gray-500">
                          <span className="uppercase font-mono text-[9px] bg-gray-800 px-1.5 py-0.5 rounded text-gray-400">
                            {event.source}
                          </span>
                          <span>•</span>
                          <span>{new Date(event.timestamp).toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Add Timeline Entry Form */}
                <form onSubmit={handleAddTimelineEvent} className="mt-6 pt-4 border-t border-gray-800">
                  <h4 className="text-xs font-semibold text-gray-300 mb-2">Append Forensic Note / Action</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 mb-2">
                    <input
                      type="text"
                      placeholder="Event Title (e.g., Malware sample recovered)"
                      value={noteTitle}
                      onChange={(e) => setNoteTitle(e.target.value)}
                      className="sm:col-span-3 bg-gray-900 border border-gray-800 text-xs rounded-lg px-3 py-2 text-gray-200 outline-none focus:border-purple-500"
                    />
                    <select
                      value={noteType}
                      onChange={(e) => setNoteType(e.target.value)}
                      className="bg-gray-900 border border-gray-800 text-xs rounded-lg px-2.5 py-2 text-gray-300 outline-none focus:border-purple-500"
                    >
                      <option value="note">Analyst Note</option>
                      <option value="containment">Containment Action</option>
                      <option value="indicator_flagged">IOC Observation</option>
                    </select>
                  </div>
                  <textarea
                    placeholder="Provide contextual details, hash values, affected hosts, or escalation notes..."
                    value={noteDesc}
                    onChange={(e) => setNoteDesc(e.target.value)}
                    rows={2}
                    className="w-full bg-gray-900 border border-gray-800 text-xs rounded-lg p-3 text-gray-200 outline-none focus:border-purple-500 mb-2 resize-none"
                  />
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={submittingNote || !noteTitle.trim()}
                      className="px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs rounded-lg transition-colors disabled:opacity-50"
                    >
                      {submittingNote ? 'Recording...' : 'Add to Timeline'}
                    </button>
                  </div>
                </form>
              </div>
            </>
          ) : (
            <div className="p-16 text-center text-gray-500 text-sm bg-gray-950/40 rounded-xl border border-gray-800">
              Select an investigation from the left panel to inspect the timeline.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Create Incident */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold text-gray-100 flex items-center gap-2">
                <FolderKanban className="text-purple-400" size={20} />
                Create Investigation
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-gray-400 hover:text-gray-200">
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Incident Title</label>
                <input
                  type="text"
                  placeholder="e.g. Cobalt Strike Beaconing from HR Workstation"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  required
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg p-2.5 text-xs text-gray-200 outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Initial Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg p-2.5 text-xs text-gray-200 outline-none focus:border-purple-500"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Investigation Scope & Hypothesis</label>
                <textarea
                  placeholder="Describe initial detection indicators, impacted assets, and hypotheses..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  rows={3}
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg p-2.5 text-xs text-gray-200 outline-none focus:border-purple-500 resize-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!newTitle.trim()}
                  className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium rounded-lg disabled:opacity-50"
                >
                  Open Investigation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Link Alert to Incident */}
      {showLinkModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-lg shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-base font-bold text-gray-100 flex items-center gap-2">
                <AlertTriangle className="text-orange-400" size={18} />
                Select Alert to Correlate
              </h3>
              <button onClick={() => setShowLinkModal(false)} className="text-gray-400 hover:text-gray-200">
                <X size={18} />
              </button>
            </div>
            <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
              {availableAlerts.length === 0 ? (
                <p className="text-xs text-gray-500">No active alerts available.</p>
              ) : (
                availableAlerts.map((alt) => (
                  <div
                    key={alt.id}
                    className="p-3 bg-gray-950 border border-gray-800 rounded-lg flex justify-between items-center hover:border-purple-500/50 transition-colors"
                  >
                    <div>
                      <div className="font-semibold text-xs text-gray-200">{alt.title}</div>
                      <div className="text-[11px] text-gray-400">
                        {alt.indicator_value ? `IOC: ${alt.indicator_value}` : alt.severity} • {alt.status}
                      </div>
                    </div>
                    <button
                      onClick={() => linkAlert(alt.id)}
                      className="px-2.5 py-1 bg-purple-600 hover:bg-purple-500 text-white text-xs rounded font-medium"
                    >
                      Attach
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

