'use client';

import { useState, useEffect } from 'react';
import { 
  Crosshair, Search, SlidersHorizontal, Zap, Play, 
  Trash2, Plus, Clock, Target, Layers, Copy, Check, 
  RefreshCw, X, ShieldAlert, ArrowUpRight
} from 'lucide-react';

interface HuntRule {
  id: string;
  name: string;
  description: string;
  severity_threshold: number;
  indicator_type: string | null;
  execution_count: number;
  created_at: string;
}

interface HuntExecution {
  id: string;
  rule_id: string;
  rule_name: string;
  indicator_type: string;
  status: string;
  matches_count: number;
  created_at: string;
}

interface SearchResult {
  id: string;
  value: string;
  type: string;
  severity_score: number;
  confidence: number;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  sources: string[];
}

const MITRE_TECHNIQUES = [
  { id: 'T1071.001', name: 'Web Protocols (C2)', type: 'ip', query: '' },
  { id: 'T1566.002', name: 'Spearphishing Link', type: 'url', query: '' },
  { id: 'T1204.002', name: 'Malicious File Execution', type: 'hash_sha256', query: '' },
  { id: 'T1190', name: 'Exploit Public-Facing App', type: 'cve', query: 'CVE' },
  { id: 'T1059.001', name: 'PowerShell Payload', type: 'domain', query: '' }
];

export function ThreatHuntingView({ token }: { token: string }) {
  const [activeTab, setActiveTab] = useState<'search' | 'rules' | 'executions'>('search');

  // Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [minScore, setMinScore] = useState(0);
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [searchLatency, setSearchLatency] = useState<number | null>(null);
  const [searching, setSearching] = useState(false);

  // Hunt Rules State
  const [rules, setRules] = useState<HuntRule[]>([]);
  const [loadingRules, setLoadingRules] = useState(false);
  const [executingRuleId, setExecutingRuleId] = useState<string | null>(null);
  const [showCreateRuleModal, setShowCreateRuleModal] = useState(false);

  // New Rule Form State
  const [ruleName, setRuleName] = useState('');
  const [ruleDesc, setRuleDesc] = useState('');
  const [ruleThreshold, setRuleThreshold] = useState(80);
  const [ruleType, setRuleType] = useState('');

  // Executions State
  const [executions, setExecutions] = useState<HuntExecution[]>([]);
  const [loadingExecutions, setLoadingExecutions] = useState(false);
  const [selectedExecutionMatches, setSelectedExecutionMatches] = useState<any[] | null>(null);
  const [inspectingExecutionId, setInspectingExecutionId] = useState<string | null>(null);

  // Copy feedback
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Perform Elasticsearch Search (FR-25)
  const executeSearch = async (overrideParams?: { q?: string; type?: string; minScore?: number }) => {
    if (!token) return;
    setSearching(true);
    const q = overrideParams?.q !== undefined ? overrideParams.q : searchQuery;
    const type = overrideParams?.type !== undefined ? overrideParams.type : selectedType;
    const score = overrideParams?.minScore !== undefined ? overrideParams.minScore : minScore;

    try {
      const url = `http://localhost:8000/api/v1/search?q=${encodeURIComponent(q)}&type=${encodeURIComponent(type)}&min_score=${score}&size=50`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.results || []);
        setSearchLatency(data.latency_ms);
      }
    } catch (err) {
      console.error('Search failed:', err);
    } finally {
      setSearching(false);
    }
  };

  const fetchRules = async () => {
    if (!token) return;
    setLoadingRules(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/hunts/rules', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRules(data);
      }
    } catch (err) {
      console.error('Failed to load rules:', err);
    } finally {
      setLoadingRules(false);
    }
  };

  const fetchExecutions = async () => {
    if (!token) return;
    setLoadingExecutions(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/hunts/executions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setExecutions(data);
      }
    } catch (err) {
      console.error('Failed to load executions:', err);
    } finally {
      setLoadingExecutions(false);
    }
  };

  useEffect(() => {
    if (token) {
      executeSearch();
      fetchRules();
      fetchExecutions();
    }
  }, [token]);

  const handleRunHunt = async (ruleId: string) => {
    setExecutingRuleId(ruleId);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/hunts/rules/${ruleId}/execute`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        fetchRules();
        fetchExecutions();
        // Open execution matches inspector
        if (data.execution_id) {
          inspectExecution(data.execution_id);
        }
      }
    } catch (err) {
      console.error('Failed to run hunt:', err);
    } finally {
      setExecutingRuleId(null);
    }
  };

  const inspectExecution = async (execId: string) => {
    setInspectingExecutionId(execId);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/hunts/executions/${execId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedExecutionMatches(data.indicators_found || []);
      }
    } catch (err) {
      console.error('Failed to inspect execution:', err);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleName.trim()) return;
    try {
      const res = await fetch('http://localhost:8000/api/v1/hunts/rules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          name: ruleName,
          description: ruleDesc,
          severity_threshold: ruleThreshold,
          indicator_type: ruleType || null
        })
      });
      if (res.ok) {
        setRuleName('');
        setRuleDesc('');
        setShowCreateRuleModal(false);
        fetchRules();
      }
    } catch (err) {
      console.error('Failed to create rule:', err);
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/hunts/rules/${ruleId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        fetchRules();
      }
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(text);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-500/10 border-red-500/40';
    if (score >= 60) return 'text-orange-400 bg-orange-500/10 border-orange-500/40';
    if (score >= 40) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/40';
    return 'text-blue-400 bg-blue-500/10 border-blue-500/40';
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Crosshair className="text-emerald-400" size={24} />
            <h2 className="text-xl font-bold text-gray-100">
              Threat Hunting & Exploration Engine
            </h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800">
              Persona: Mei Lin Tan (Threat Hunter)
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Faceted intelligence search (FR-25), ATT&CK pivoting, hypothesis-driven hunt rules, and match tracking.
          </p>
        </div>

        {/* View Tabs */}
        <div className="flex bg-gray-950 rounded-lg p-1 border border-gray-800 text-xs">
          <button
            onClick={() => setActiveTab('search')}
            className={`px-3 py-1.5 rounded flex items-center gap-1.5 transition-colors ${
              activeTab === 'search'
                ? 'bg-emerald-600 text-white font-medium'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Search size={14} />
            Faceted Search
          </button>
          <button
            onClick={() => { setActiveTab('rules'); fetchRules(); }}
            className={`px-3 py-1.5 rounded flex items-center gap-1.5 transition-colors ${
              activeTab === 'rules'
                ? 'bg-emerald-600 text-white font-medium'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Target size={14} />
            Hunt Rules ({rules.length})
          </button>
          <button
            onClick={() => { setActiveTab('executions'); fetchExecutions(); }}
            className={`px-3 py-1.5 rounded flex items-center gap-1.5 transition-colors ${
              activeTab === 'executions'
                ? 'bg-emerald-600 text-white font-medium'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Clock size={14} />
            Execution History
          </button>
        </div>
      </div>

      {/* MITRE ATT&CK Quick Pivots */}
      <div className="mb-6 bg-gray-950/70 border border-gray-800/80 p-3.5 rounded-xl">
        <div className="flex items-center gap-2 mb-2 text-xs font-semibold text-gray-300">
          <Layers size={14} className="text-emerald-400" />
          <span>ATT&CK Adversary Technique Pivots:</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {MITRE_TECHNIQUES.map((tech) => (
            <button
              key={tech.id}
              onClick={() => {
                setActiveTab('search');
                setSelectedType(tech.type);
                setSearchQuery(tech.query);
                executeSearch({ type: tech.type, q: tech.query });
              }}
              className="text-xs px-2.5 py-1 rounded bg-gray-900 border border-gray-800 hover:border-emerald-500/50 hover:bg-emerald-950/30 text-gray-300 transition-colors flex items-center gap-1.5"
            >
              <span className="font-mono text-emerald-400 text-[11px]">{tech.id}</span>
              <span>{tech.name}</span>
              <ArrowUpRight size={11} className="text-gray-500" />
            </button>
          ))}
        </div>
      </div>

      {/* TAB 1: FACETED SEARCH (FR-25) */}
      {activeTab === 'search' && (
        <div className="space-y-4">
          {/* Search Controls Bar */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 bg-gray-950 p-4 rounded-xl border border-gray-800">
            {/* Input */}
            <div className="md:col-span-5 relative">
              <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
              <input
                type="text"
                placeholder="Search indicator, IP, domain, hash, or CVE..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && executeSearch()}
                className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-9 pr-3 py-2 text-xs text-gray-200 outline-none focus:border-emerald-500"
              />
            </div>

            {/* Type Filter */}
            <div className="md:col-span-3">
              <select
                value={selectedType}
                onChange={(e) => {
                  setSelectedType(e.target.value);
                  executeSearch({ type: e.target.value });
                }}
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-300 outline-none focus:border-emerald-500"
              >
                <option value="">All IOC Types</option>
                <option value="ip">IP Address (IPv4)</option>
                <option value="domain">Domain / Hostname</option>
                <option value="url">URL</option>
                <option value="hash_sha256">SHA-256 Hash</option>
                <option value="hash_md5">MD5 Hash</option>
                <option value="cve">CVE Vulnerability</option>
              </select>
            </div>

            {/* Min Severity Slider */}
            <div className="md:col-span-2 flex items-center gap-2">
              <span className="text-[11px] text-gray-400 whitespace-nowrap">Min: {minScore}</span>
              <input
                type="range"
                min="0"
                max="90"
                step="10"
                value={minScore}
                onChange={(e) => {
                  const val = Number(e.target.value);
                  setMinScore(val);
                  executeSearch({ minScore: val });
                }}
                className="w-full accent-emerald-500 cursor-pointer"
              />
            </div>

            {/* Execute Button */}
            <div className="md:col-span-2">
              <button
                onClick={() => executeSearch()}
                disabled={searching}
                className="w-full h-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs rounded-lg flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 py-2"
              >
                <RefreshCw size={14} className={searching ? 'animate-spin' : ''} />
                Search
              </button>
            </div>
          </div>

          {/* Latency & Match Count Bar (NFR-05) */}
          <div className="flex justify-between items-center text-xs text-gray-400 px-1">
            <span>
              Showing <span className="font-semibold text-gray-200">{searchResults.length}</span> indicators
            </span>
            {searchLatency !== null && (
              <span className="flex items-center gap-1 font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/60 text-[11px]">
                <Zap size={12} />
                Query Latency: {searchLatency} ms (NFR-05 &lt; 800ms)
              </span>
            )}
          </div>

          {/* Results Table */}
          <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-gray-300">
                <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                  <tr>
                    <th className="py-3 px-4">Indicator Value</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Source Provenance</th>
                    <th className="py-3 px-4">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {searching ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-gray-500">
                        <RefreshCw className="animate-spin inline-block mr-2" size={16} />
                        Searching intelligence store...
                      </td>
                    </tr>
                  ) : searchResults.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-gray-500">
                        No indicators matched the search filters. Try adjusting query or threshold.
                      </td>
                    </tr>
                  ) : (
                    searchResults.map((ind) => (
                      <tr key={ind.id} className="hover:bg-gray-900/50 transition-colors">
                        <td className="py-3 px-4 font-mono font-medium text-gray-200">
                          <div className="flex items-center gap-2 max-w-md truncate">
                            <span className="truncate">{ind.value}</span>
                            <button
                              onClick={() => handleCopy(ind.value)}
                              title="Copy IOC"
                              className="text-gray-500 hover:text-gray-300 shrink-0"
                            >
                              {copiedValue === ind.value ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                            </button>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-gray-400">
                            {ind.type}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`font-bold px-2 py-0.5 rounded border text-[11px] ${getScoreColor(ind.severity_score)}`}>
                            {ind.severity_score} / 100
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-400">
                          {ind.confidence}%
                        </td>
                        <td className="py-3 px-4 text-gray-400 truncate max-w-xs">
                          {ind.sources && ind.sources.length > 0 ? ind.sources.join(', ') : 'ThreatLens Engine'}
                        </td>
                        <td className="py-3 px-4 text-gray-500 text-[11px] whitespace-nowrap">
                          {ind.last_seen ? new Date(ind.last_seen).toLocaleDateString() : 'N/A'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: PROACTIVE HUNT RULES */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center mb-2">
            <div>
              <h3 className="text-sm font-semibold text-gray-200">Active Hunting Rules</h3>
              <p className="text-xs text-gray-400">Rules query the intelligence database to find undetected adversary activity.</p>
            </div>
            <button
              onClick={() => setShowCreateRuleModal(true)}
              className="flex items-center gap-2 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs rounded-lg transition-colors"
            >
              <Plus size={15} />
              New Hunt Rule
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {loadingRules ? (
              <div className="col-span-2 py-12 text-center text-gray-500 text-sm">
                <RefreshCw className="animate-spin inline-block mr-2" size={16} />
                Loading hunt rules...
              </div>
            ) : rules.map((r) => (
              <div key={r.id} className="bg-gray-950 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-all flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-start gap-2 mb-2">
                    <h4 className="font-semibold text-gray-100 text-sm">{r.name}</h4>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                      Score &ge; {r.severity_threshold}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 mb-4">{r.description || 'No description provided.'}</p>
                </div>

                <div className="pt-3 border-t border-gray-800 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 text-gray-500">
                    <span className="font-mono uppercase text-[10px] bg-gray-900 px-2 py-0.5 rounded border border-gray-800">
                      {r.indicator_type || 'any type'}
                    </span>
                    <span>•</span>
                    <span>{r.execution_count} runs</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDeleteRule(r.id)}
                      title="Delete rule"
                      className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors"
                    >
                      <Trash2 size={14} />
                    </button>
                    <button
                      onClick={() => handleRunHunt(r.id)}
                      disabled={executingRuleId === r.id}
                      className="flex items-center gap-1.5 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded text-xs transition-colors disabled:opacity-50"
                    >
                      <Play size={12} className={executingRuleId === r.id ? 'animate-spin' : ''} />
                      Run Hunt
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: EXECUTION HISTORY */}
      {activeTab === 'executions' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center mb-2">
            <div>
              <h3 className="text-sm font-semibold text-gray-200">Hunt Execution Records</h3>
              <p className="text-xs text-gray-400">History of automated and on-demand threat hunting executions.</p>
            </div>
            <button
              onClick={fetchExecutions}
              className="p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors"
            >
              <RefreshCw size={14} className={loadingExecutions ? 'animate-spin' : ''} />
            </button>
          </div>

          <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Hunt Rule</th>
                  <th className="py-3 px-4">Target Type</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Matches Found</th>
                  <th className="py-3 px-4">Executed At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {loadingExecutions ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-gray-500">
                      <RefreshCw className="animate-spin inline-block mr-2" size={16} />
                      Loading executions...
                    </td>
                  </tr>
                ) : executions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-gray-500">
                      No executions recorded yet. Go to Hunt Rules and click "Run Hunt"!
                    </td>
                  </tr>
                ) : (
                  executions.map((e) => (
                    <tr key={e.id} className="hover:bg-gray-900/50 transition-colors">
                      <td className="py-3 px-4 font-semibold text-gray-200">{e.rule_name}</td>
                      <td className="py-3 px-4 font-mono uppercase text-[10px] text-gray-400">{e.indicator_type}</td>
                      <td className="py-3 px-4">
                        <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                          {e.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-bold text-gray-100">{e.matches_count} indicators</span>
                      </td>
                      <td className="py-3 px-4 text-gray-500">
                        {e.created_at ? new Date(e.created_at).toLocaleString() : 'N/A'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => inspectExecution(e.id)}
                          className="text-xs text-emerald-400 hover:text-emerald-300 font-medium"
                        >
                          View Matches
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: Create Hunt Rule */}
      {showCreateRuleModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold text-gray-100 flex items-center gap-2">
                <Target className="text-emerald-400" size={20} />
                Create Proactive Hunt Rule
              </h3>
              <button onClick={() => setShowCreateRuleModal(false)} className="text-gray-400 hover:text-gray-200">
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleCreateRule} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Rule Name</label>
                <input
                  type="text"
                  placeholder="e.g. Cobalt Strike Beacon Search"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  required
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg p-2.5 text-xs text-gray-200 outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Target Indicator Type</label>
                <select
                  value={ruleType}
                  onChange={(e) => setRuleType(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg p-2.5 text-xs text-gray-200 outline-none focus:border-emerald-500"
                >
                  <option value="">Any Type (Global Hunt)</option>
                  <option value="ip">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="hash_sha256">SHA-256 Hash</option>
                  <option value="cve">CVE</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">
                  Severity Score Threshold: {ruleThreshold}
                </label>
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={ruleThreshold}
                  onChange={(e) => setRuleThreshold(Number(e.target.value))}
                  className="w-full accent-emerald-500 cursor-pointer"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Description & Hypothesis</label>
                <textarea
                  placeholder="State the hypothesis and indicators sought..."
                  value={ruleDesc}
                  onChange={(e) => setRuleDesc(e.target.value)}
                  rows={2}
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg p-2.5 text-xs text-gray-200 outline-none focus:border-emerald-500 resize-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateRuleModal(false)}
                  className="px-3.5 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!ruleName.trim()}
                  className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg disabled:opacity-50"
                >
                  Save Hunt Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Matches Inspector */}
      {selectedExecutionMatches && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-2xl shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-base font-bold text-gray-100 flex items-center gap-2">
                <ShieldAlert className="text-emerald-400" size={18} />
                Hunt Matches ({selectedExecutionMatches.length} indicators found)
              </h3>
              <button onClick={() => setSelectedExecutionMatches(null)} className="text-gray-400 hover:text-gray-200">
                <X size={18} />
              </button>
            </div>
            <div className="max-h-96 overflow-y-auto space-y-2 pr-1">
              {selectedExecutionMatches.length === 0 ? (
                <p className="text-xs text-gray-500 py-8 text-center">No indicators matched the threshold during this execution.</p>
              ) : (
                selectedExecutionMatches.map((m) => (
                  <div key={m.id} className="p-3 bg-gray-950 border border-gray-800 rounded-lg flex justify-between items-center text-xs">
                    <div>
                      <div className="font-mono text-gray-200 font-semibold">{m.value}</div>
                      <div className="text-[11px] text-gray-500 uppercase">{m.type}</div>
                    </div>
                    <span className={`font-bold px-2 py-0.5 rounded border text-[11px] ${getScoreColor(m.score)}`}>
                      Score: {m.score}
                    </span>
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

