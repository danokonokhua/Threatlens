'use client';

import { useState, useEffect } from 'react';
import { Globe, ShieldAlert, Activity, RefreshCw, Flame, Crosshair } from 'lucide-react';

interface GeoLocation {
  country_code: string;
  country_name: string;
  lat: number;
  lng: number;
  threat_count: number;
  critical_count: number;
  avg_severity: number;
  top_threat: string;
}

interface GeoDistributionResponse {
  total_active_indicators: number;
  high_severity_count: number;
  locations: GeoLocation[];
}

export function GlobalAttackHeatmap({ token }: { token: string }) {
  const [locations, setLocations] = useState<GeoLocation[]>([]);
  const [totalIndicators, setTotalIndicators] = useState(0);
  const [highCount, setHighCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [hoveredLocation, setHoveredLocation] = useState<GeoLocation | null>(null);
  const [selectedLocation, setSelectedLocation] = useState<GeoLocation | null>(null);
  const [filterCriticalOnly, setFilterCriticalOnly] = useState(false);

  const fetchGeoData = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/analytics/geo-distribution', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data: GeoDistributionResponse = await res.json();
        setLocations(data.locations || []);
        setTotalIndicators(data.total_active_indicators || 0);
        setHighCount(data.high_severity_count || 0);
      }
    } catch (err) {
      console.error('Failed to load geographic threat data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGeoData();
  }, [token]);

  // Convert lat/lng to Equirectangular SVG coordinates (width=900, height=450)
  const projectCoords = (lat: number, lng: number) => {
    const x = ((lng + 180) / 360) * 900;
    const y = ((90 - lat) / 180) * 450;
    return { x, y };
  };

  const displayedLocations = filterCriticalOnly 
    ? locations.filter(l => l.critical_count > 0)
    : locations;

  const maxThreats = Math.max(...locations.map(l => l.threat_count), 1);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="text-cyan-400" size={24} />
            <h2 className="text-xl font-bold text-gray-100">
              Global Attack Heatmap & Geo-Density
            </h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
              FR-20 / Section 12.5
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Real-time geospatial distribution of threat infrastructure, adversary origins, and critical attack volumes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setFilterCriticalOnly(!filterCriticalOnly)}
            className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-colors flex items-center gap-1.5 ${
              filterCriticalOnly
                ? 'bg-red-500/20 text-red-400 border-red-500/50'
                : 'bg-gray-800 text-gray-400 border-gray-700 hover:text-gray-200'
            }`}
          >
            <Flame size={14} className={filterCriticalOnly ? 'text-red-400' : ''} />
            {filterCriticalOnly ? 'Critical Threats Only' : 'All Severity Levels'}
          </button>

          <button
            onClick={fetchGeoData}
            disabled={loading || !token}
            className="p-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors disabled:opacity-50"
            title="Refresh map telemetry"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Map + Sidebar Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* SVG Interactive Map Area (3 Cols) */}
        <div className="lg:col-span-3 relative bg-gray-950 rounded-xl border border-gray-800 p-3 overflow-hidden shadow-inner">
          {/* Subtle Grid Guidelines */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293710_1px,transparent_1px),linear-gradient(to_bottom,#1f293710_1px,transparent_1px)] bg-[size:30px_30px] pointer-events-none"></div>

          <svg
            viewBox="0 0 900 450"
            className="w-full h-auto select-none"
            style={{ filter: 'drop-shadow(0px 0px 8px rgba(6,182,212,0.1))' }}
          >
            {/* World Continents Vector Outlines */}
            <g fill="#1e293b" stroke="#334155" strokeWidth="0.8" opacity="0.85">
              {/* North America */}
              <path d="M 120 70 L 220 65 L 260 110 L 230 180 L 190 220 L 150 200 L 120 150 Z" />
              {/* South America */}
              <path d="M 230 220 L 310 230 L 330 330 L 290 410 L 240 370 L 210 270 Z" />
              {/* Europe */}
              <path d="M 430 80 L 510 75 L 530 120 L 480 150 L 420 140 L 410 100 Z" />
              {/* Africa */}
              <path d="M 430 160 L 520 160 L 550 250 L 510 350 L 460 360 L 420 250 L 410 190 Z" />
              {/* Asia & Russia */}
              <path d="M 520 65 L 810 70 L 850 140 L 780 230 L 680 270 L 570 230 L 530 130 Z" />
              {/* Australia */}
              <path d="M 720 290 L 820 290 L 830 380 L 730 380 Z" />
              {/* Greenland */}
              <path d="M 280 40 L 340 35 L 360 70 L 310 85 Z" />
            </g>

            {/* Latitude / Longitude lines */}
            <line x1="0" y1="225" x2="900" y2="225" stroke="#334155" strokeWidth="0.5" strokeDasharray="4 4" opacity="0.4" />
            <line x1="450" y1="0" x2="450" y2="450" stroke="#334155" strokeWidth="0.5" strokeDasharray="4 4" opacity="0.4" />

            {/* Threat Nodes / Heat Rings */}
            {displayedLocations.map((loc) => {
              const { x, y } = projectCoords(loc.lat, loc.lng);
              const radius = Math.max(8, Math.min(26, (loc.threat_count / maxThreats) * 26));
              const isSelected = selectedLocation?.country_code === loc.country_code;
              const isHovered = hoveredLocation?.country_code === loc.country_code;

              const fillColor = loc.avg_severity >= 85 
                ? '#ef4444' 
                : loc.avg_severity >= 75 
                ? '#f97316' 
                : '#eab308';

              return (
                <g
                  key={loc.country_code}
                  className="cursor-pointer transition-transform duration-200"
                  onMouseEnter={() => setHoveredLocation(loc)}
                  onMouseLeave={() => setHoveredLocation(null)}
                  onClick={() => setSelectedLocation(loc)}
                >
                  {/* Outer Pulsing Aura */}
                  <circle
                    cx={x}
                    cy={y}
                    r={radius + 8}
                    fill={fillColor}
                    opacity={isSelected || isHovered ? 0.35 : 0.15}
                    className="animate-ping"
                    style={{ animationDuration: '3s' }}
                  />

                  {/* Mid Ring */}
                  <circle
                    cx={x}
                    cy={y}
                    r={radius + 2}
                    fill="none"
                    stroke={fillColor}
                    strokeWidth={isSelected || isHovered ? 2 : 1}
                    opacity={0.8}
                  />

                  {/* Core Node */}
                  <circle
                    cx={x}
                    cy={y}
                    r={radius}
                    fill={fillColor}
                    opacity={0.75}
                  />

                  {/* Node Label */}
                  <text
                    x={x}
                    y={y + 3}
                    textAnchor="middle"
                    fill="#ffffff"
                    fontSize={Math.max(9, Math.min(12, radius * 0.7))}
                    fontWeight="bold"
                    pointerEvents="none"
                  >
                    {loc.threat_count}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* HUD Tooltip for Hovered Node */}
          {hoveredLocation && (
            <div 
              className="absolute z-10 bg-gray-900/95 border border-cyan-500/50 backdrop-blur-md p-3.5 rounded-xl shadow-2xl text-xs w-64 pointer-events-none transition-all duration-150"
              style={{
                left: `${Math.min(75, Math.max(5, (projectCoords(hoveredLocation.lat, hoveredLocation.lng).x / 900) * 100))}%`,
                top: `${Math.min(70, Math.max(10, (projectCoords(hoveredLocation.lat, hoveredLocation.lng).y / 450) * 100))}%`
              }}
            >
              <div className="flex items-center justify-between mb-1.5 border-b border-gray-800 pb-1.5">
                <span className="font-bold text-gray-100 text-sm flex items-center gap-1.5">
                  <span className="font-mono text-cyan-400">[{hoveredLocation.country_code}]</span>
                  {hoveredLocation.country_name}
                </span>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                  hoveredLocation.avg_severity >= 85 
                    ? 'text-red-400 border-red-500/40 bg-red-500/10'
                    : 'text-orange-400 border-orange-500/40 bg-orange-500/10'
                }`}>
                  Score {hoveredLocation.avg_severity}
                </span>
              </div>

              <div className="space-y-1 text-gray-300">
                <div className="flex justify-between">
                  <span className="text-gray-400">Threat Volume:</span>
                  <span className="font-semibold text-gray-100">{hoveredLocation.threat_count} indicators</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Critical Attacks:</span>
                  <span className="font-semibold text-red-400">{hoveredLocation.critical_count}</span>
                </div>
                <div className="pt-1.5 border-t border-gray-800/80 text-[11px]">
                  <span className="text-gray-400 block">Top Observed Threat:</span>
                  <span className="text-cyan-300 font-medium truncate block">{hoveredLocation.top_threat}</span>
                </div>
              </div>
            </div>
          )}

          {/* Map Footer Stats */}
          <div className="absolute bottom-3 left-3 bg-gray-900/80 backdrop-blur border border-gray-800 px-3 py-1.5 rounded-lg flex items-center gap-4 text-xs text-gray-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block animate-pulse"></span>
              Critical Severity (&ge;85)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500 inline-block"></span>
              High (75-84)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 inline-block"></span>
              Medium (&lt;75)
            </span>
          </div>
        </div>

        {/* Right Sidebar: Threat Origins Leaderboard */}
        <div className="space-y-4">
          <div className="bg-gray-950 p-4 rounded-xl border border-gray-800">
            <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
              <Crosshair size={15} className="text-red-400" />
              Top Threat Origins
            </h3>

            <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
              {displayedLocations
                .sort((a, b) => b.threat_count - a.threat_count)
                .map((loc) => {
                  const percentage = Math.round((loc.threat_count / maxThreats) * 100);
                  const isSelected = selectedLocation?.country_code === loc.country_code;

                  return (
                    <div
                      key={loc.country_code}
                      onClick={() => setSelectedLocation(loc)}
                      className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-cyan-950/30 border-cyan-500/50 shadow-md'
                          : 'bg-gray-900/60 border-gray-800/80 hover:border-gray-700'
                      }`}
                    >
                      <div className="flex justify-between items-center mb-1">
                        <span className="font-semibold text-gray-200 flex items-center gap-1.5">
                          <span className="font-mono text-cyan-400 text-[11px]">[{loc.country_code}]</span>
                          {loc.country_name}
                        </span>
                        <span className="font-mono font-bold text-gray-100">
                          {loc.threat_count}
                        </span>
                      </div>

                      {/* Mini Bar */}
                      <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden mb-1.5">
                        <div
                          className={`h-full rounded-full ${
                            loc.avg_severity >= 85 
                              ? 'bg-red-500' 
                              : loc.avg_severity >= 75 
                              ? 'bg-orange-500' 
                              : 'bg-yellow-500'
                          }`}
                          style={{ width: `${percentage}%` }}
                        ></div>
                      </div>

                      <div className="flex justify-between items-center text-[10px] text-gray-400">
                        <span className="truncate max-w-[140px] text-gray-400">{loc.top_threat}</span>
                        <span className="text-red-400 font-medium">{loc.critical_count} critical</span>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

