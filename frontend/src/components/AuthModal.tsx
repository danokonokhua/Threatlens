'use client';

import { useState } from 'react';
import { 
  Shield, 
  User, 
  Lock, 
  KeyRound, 
  Check, 
  X, 
  AlertCircle, 
  ChevronRight, 
  Sparkles, 
  Terminal,
  Activity,
  FolderKanban,
  Crosshair,
  ShieldCheck,
  Cpu
} from 'lucide-react';

export interface UserProfile {
  id?: string;
  email: string;
  role: string;
  name?: string;
  title?: string;
}

export const PRD_PERSONAS = [
  {
    name: 'Marcus Vance',
    role: 'admin',
    roleLabel: 'Administrator',
    email: 'admin@threatlens.local',
    password: 'admin123',
    icon: Shield,
    color: 'border-purple-500/40 bg-purple-500/10 text-purple-400',
    badge: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
    description: 'Full platform authority: user management, feed orchestrations, system configuration and audit logs.',
    defaultTab: 'soc'
  },
  {
    name: 'Daniel Okafor',
    role: 'incident_responder',
    roleLabel: 'Incident Responder',
    email: 'responder@threatlens.local',
    password: 'responder123',
    icon: FolderKanban,
    color: 'border-rose-500/40 bg-rose-500/10 text-rose-400',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
    description: 'Lead Incident Responder: active containment, forensic timeline events (FR-19) and alert escalation.',
    defaultTab: 'incident_response'
  },
  {
    name: 'Mei Lin Tan',
    role: 'threat_hunter',
    roleLabel: 'Threat Hunter',
    email: 'hunter@threatlens.local',
    password: 'hunter123',
    icon: Crosshair,
    color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    description: 'Advanced Threat Hunter: faceted Elasticsearch IOC pivoting (FR-25), MITRE ATT&CK rules and hunts.',
    defaultTab: 'threat_hunting'
  },
  {
    name: 'Rachel Adeyemi',
    role: 'executive',
    roleLabel: 'Executive / CISO',
    email: 'executive@threatlens.local',
    password: 'executive123',
    icon: ShieldCheck,
    color: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    description: 'Chief Information Security Officer: 30-day exposure posture, executive board briefing and risk indexing.',
    defaultTab: 'executive'
  },
  {
    name: 'Kavita Patel',
    role: 'security_engineer',
    roleLabel: 'Security Engineer',
    email: 'engineer@threatlens.local',
    password: 'engineer123',
    icon: Cpu,
    color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400',
    badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
    description: 'Platform & Pipeline Engineer: multi-feed aggregation pipelines (FR-01/05), TAXII 2.1 and Redis bus.',
    defaultTab: 'soc'
  },
  {
    name: 'SOC Analyst Hub',
    role: 'soc_analyst',
    roleLabel: 'SOC Tier 1/2 Analyst',
    email: 'analyst@threatlens.local',
    password: 'analyst123',
    icon: Activity,
    color: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
    badge: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    description: 'Operations Analyst: real-time alert triage (FR-18), indicator confidence scoring (FR-13) and escalation.',
    defaultTab: 'soc'
  }
];

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: UserProfile | null;
  onLoginSuccess: (token: string, user: UserProfile, preferredTab?: string) => void;
}

export function AuthModal({ isOpen, onClose, currentUser, onLoginSuccess }: AuthModalProps) {
  const [activeTab, setActiveTab] = useState<'personas' | 'custom' | 'dev'>('personas');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [devToken, setDevToken] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const performLogin = async (loginEmail: string, loginPass: string, preferredTab?: string) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const formData = new URLSearchParams();
      formData.append('username', loginEmail);
      formData.append('password', loginPass);

      const res = await fetch('http://localhost:8000/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Invalid email or password');
      }

      const data = await res.json();
      const token = data.access_token;

      // Fetch user profile from /api/v1/users/me
      let userProfile: UserProfile = { email: loginEmail, role: 'soc_analyst' };
      try {
        const meRes = await fetch('http://localhost:8000/api/v1/users/me', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (meRes.ok) {
          const meData = await meRes.json();
          userProfile = {
            id: meData.id,
            email: meData.email,
            role: meData.role
          };
        }
      } catch {
        // Fallback to email/role from matched persona
        const matched = PRD_PERSONAS.find(p => p.email === loginEmail);
        if (matched) {
          userProfile.role = matched.role;
        }
      }

      const matchedPersona = PRD_PERSONAS.find(p => p.email === loginEmail);
      if (matchedPersona) {
        userProfile.name = matchedPersona.name;
        userProfile.title = matchedPersona.roleLabel;
      }

      onLoginSuccess(token, userProfile, preferredTab || matchedPersona?.defaultTab);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMsg('Please enter both email and password.');
      return;
    }
    performLogin(email, password);
  };

  const handleDevTokenApply = async () => {
    if (!devToken.trim()) {
      setErrorMsg('Please enter a valid Bearer token.');
      return;
    }
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const meRes = await fetch('http://localhost:8000/api/v1/users/me', {
        headers: { 'Authorization': `Bearer ${devToken.trim()}` }
      });
      if (!meRes.ok) throw new Error('Token is invalid or expired (401)');
      const meData = await meRes.json();
      const profile: UserProfile = {
        id: meData.id,
        email: meData.email,
        role: meData.role,
        name: meData.email.split('@')[0],
        title: meData.role
      };
      onLoginSuccess(devToken.trim(), profile);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Token verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-6 border-b border-gray-800 flex justify-between items-center bg-gray-950/50">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-600/20 text-blue-400 rounded-xl border border-blue-500/30">
              <Shield size={24} />
            </div>
            <div>
              <h2 className="text-xl font-bold text-gray-100 flex items-center gap-2">
                ThreatLens Identity Gateway
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                  PRD Section 11 & 13
                </span>
              </h2>
              <p className="text-xs text-gray-400 mt-0.5">
                Role-Based Access Control (RBAC) & OAuth2 JWT Session Authentication
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 p-2 rounded-lg hover:bg-gray-800 transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-gray-800 bg-gray-950/30 px-6 pt-3 gap-2">
          <button
            onClick={() => { setActiveTab('personas'); setErrorMsg(null); }}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-colors border-b-2 ${
              activeTab === 'personas'
                ? 'border-blue-500 text-blue-400 bg-gray-900/80'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Sparkles size={14} />
            PRD Roles & Personas (One-Click)
          </button>
          <button
            onClick={() => { setActiveTab('custom'); setErrorMsg(null); }}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-colors border-b-2 ${
              activeTab === 'custom'
                ? 'border-blue-500 text-blue-400 bg-gray-900/80'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <User size={14} />
            Account Sign-In
          </button>
          <button
            onClick={() => { setActiveTab('dev'); setErrorMsg(null); }}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-colors border-b-2 ${
              activeTab === 'dev'
                ? 'border-blue-500 text-blue-400 bg-gray-900/80'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Terminal size={14} />
            Token Override
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto flex-1">
          {errorMsg && (
            <div className="mb-4 p-3 bg-red-950/50 border border-red-800/60 rounded-xl flex items-center gap-2.5 text-xs text-red-300">
              <AlertCircle size={16} className="text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {activeTab === 'personas' && (
            <div className="space-y-3">
              <div className="text-xs text-gray-400 mb-2 flex justify-between items-center">
                <span>Select a persona defined in PRD Section 11 to test role-specific workflows:</span>
                <span className="text-[11px] text-gray-500">6 Authorized Roles</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {PRD_PERSONAS.map((persona) => {
                  const Icon = persona.icon;
                  const isCurrent = currentUser?.email === persona.email;
                  return (
                    <div
                      key={persona.email}
                      className={`p-3.5 rounded-xl border transition-all text-left flex flex-col justify-between ${
                        isCurrent 
                          ? 'border-blue-500/80 bg-blue-950/20 shadow-lg shadow-blue-950/50 ring-1 ring-blue-500/50' 
                          : 'border-gray-800 hover:border-gray-700 bg-gray-950/40 hover:bg-gray-800/30'
                      }`}
                    >
                      <div>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2.5">
                            <div className={`p-2 rounded-lg border ${persona.color}`}>
                              <Icon size={16} />
                            </div>
                            <div>
                              <div className="text-sm font-semibold text-gray-100 flex items-center gap-1.5">
                                {persona.name}
                                {isCurrent && (
                                  <span className="text-[10px] px-1.5 py-0.2 bg-blue-500/20 text-blue-300 border border-blue-500/30 rounded-full font-normal">
                                    Active
                                  </span>
                                )}
                              </div>
                              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border inline-block mt-0.5 ${persona.badge}`}>
                                {persona.roleLabel}
                              </span>
                            </div>
                          </div>
                        </div>
                        <p className="text-[11px] text-gray-400 line-clamp-2 leading-relaxed mb-3">
                          {persona.description}
                        </p>
                      </div>

                      <button
                        onClick={() => performLogin(persona.email, persona.password, persona.defaultTab)}
                        disabled={isLoading}
                        className={`w-full py-1.5 px-3 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors ${
                          isCurrent
                            ? 'bg-blue-600/30 text-blue-300 border border-blue-500/40 hover:bg-blue-600 hover:text-white'
                            : 'bg-gray-800 hover:bg-blue-600 text-gray-200 hover:text-white'
                        }`}
                      >
                        {isLoading ? (
                          <span className="animate-pulse">Authenticating...</span>
                        ) : isCurrent ? (
                          <>
                            <Check size={13} />
                            Re-authenticate
                          </>
                        ) : (
                          <>
                            <span>Sign in as {persona.name.split(' ')[0]}</span>
                            <ChevronRight size={13} />
                          </>
                        )}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {activeTab === 'custom' && (
            <form onSubmit={handleCustomSubmit} className="space-y-4 max-w-md mx-auto py-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <User size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@threatlens.local"
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl pl-9 pr-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl pl-9 pr-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-sm font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  <KeyRound size={16} />
                  <span>{isLoading ? 'Signing In...' : 'Sign In with OAuth2'}</span>
                </button>
              </div>

              <div className="text-center pt-2">
                <p className="text-[11px] text-gray-500">
                  Password verification is executed server-side via Bcrypt against PostgreSQL.
                </p>
              </div>
            </form>
          )}

          {activeTab === 'dev' && (
            <div className="space-y-4 max-w-lg mx-auto py-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1.5">
                  Manual Bearer Token (JWT)
                </label>
                <textarea
                  rows={4}
                  value={devToken}
                  onChange={(e) => setDevToken(e.target.value)}
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs text-gray-300 font-mono placeholder-gray-700 focus:outline-none focus:border-blue-500 transition-colors"
                />
                <p className="text-[11px] text-gray-500 mt-1">
                  Allows direct manual token injection for integration testing and external scripts.
                </p>
              </div>

              <button
                onClick={handleDevTokenApply}
                disabled={isLoading || !devToken}
                className="w-full py-2 bg-gray-800 hover:bg-blue-600 text-white rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
              >
                <span>Verify & Apply Token</span>
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800 bg-gray-950/60 flex items-center justify-between text-xs text-gray-500">
          <span>Standards: OAuth2 Password Bearer · RFC 7519 JWT · PBKDF2/Bcrypt</span>
          <span>ThreatLens Sentinel v0.1.0</span>
        </div>
      </div>
    </div>
  );
}
