'use client';

import { useState, useEffect } from 'react';
import { Rss, RefreshCw, CheckCircle2, XCircle, Database, Play, Power } from 'lucide-react';

interface Feed {
  id: string;
  name: string;
  url: string;
  feed_type: string;
  description: string;
  is_active: boolean;
  indicator_count: number;
}

interface FeedsManagerProps {
  token: string;
  onFeedsUpdated?: () => void;
}

export function FeedsManager({ token, onFeedsUpdated }: FeedsManagerProps) {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncingAll, setSyncingAll] = useState(false);
  const [syncingFeed, setSyncingFeed] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchFeeds = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/feeds', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setFeeds(data);
      }
    } catch (err) {
      console.error('Failed to load feeds:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFeeds();
  }, [token]);

  const toggleFeed = async (feedId: string) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/feeds/${feedId}/toggle`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        fetchFeeds();
      }
    } catch (err) {
      console.error('Failed to toggle feed:', err);
    }
  };

  const syncFeed = async (feedType: string) => {
    setSyncingFeed(feedType);
    setStatusMessage(`Triggered ingestion for ${feedType}...`);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/feeds/ingest/${feedType}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        setStatusMessage(`Ingestion started for ${feedType}`);
        setTimeout(() => {
          fetchFeeds();
          if (onFeedsUpdated) onFeedsUpdated();
        }, 2000);
      }
    } catch (err) {
      console.error(`Failed to sync ${feedType}:`, err);
    } finally {
      setSyncingFeed(null);
    }
  };

  const syncAllFeeds = async () => {
    setSyncingAll(true);
    setStatusMessage('Triggering ingestion across all active feeds...');
    try {
      const res = await fetch('http://localhost:8000/api/v1/feeds/ingest/all', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage(data.message || 'All active feeds triggered');
        setTimeout(() => {
          fetchFeeds();
          if (onFeedsUpdated) onFeedsUpdated();
        }, 3000);
      }
    } catch (err) {
      console.error('Failed to sync all feeds:', err);
    } finally {
      setSyncingAll(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Rss className="text-cyan-400" size={22} />
            <h2 className="text-xl font-bold text-gray-100">
              Threat Intelligence Feeds
            </h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
              FR-01 (≥6 Sources)
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Configure, monitor, and synchronize live threat intelligence pipelines.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchFeeds}
            disabled={loading || !token}
            className="p-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors disabled:opacity-50"
            title="Refresh feed list"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={syncAllFeeds}
            disabled={syncingAll || !token}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm rounded-lg transition-colors disabled:opacity-50"
          >
            <Play size={16} className={syncingAll ? 'animate-spin' : ''} />
            Sync All Feeds
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="mb-4 text-xs text-cyan-300 bg-cyan-950/50 border border-cyan-800/60 px-3 py-2 rounded-lg">
          {statusMessage}
        </div>
      )}

      {/* Feeds Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {feeds.map((feed) => (
          <div
            key={feed.id}
            className={`border rounded-xl p-4 transition-all ${
              feed.is_active
                ? 'bg-gray-950/70 border-gray-800 hover:border-gray-700'
                : 'bg-gray-950/30 border-gray-900 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start mb-2">
              <div>
                <h3 className="font-semibold text-gray-100 text-base">{feed.name}</h3>
                <span className="text-xs font-mono text-gray-500 uppercase">{feed.feed_type}</span>
              </div>
              <button
                onClick={() => toggleFeed(feed.id)}
                title={feed.is_active ? 'Disable feed' : 'Enable feed'}
                className={`p-1.5 rounded-lg border transition-colors ${
                  feed.is_active
                    ? 'text-green-400 bg-green-500/10 border-green-500/30 hover:bg-green-500/20'
                    : 'text-gray-500 bg-gray-800/40 border-gray-700 hover:text-gray-300'
                }`}
              >
                <Power size={14} />
              </button>
            </div>

            <p className="text-xs text-gray-400 mb-4 min-h-[32px] line-clamp-2">
              {feed.description || feed.url}
            </p>

            <div className="flex items-center justify-between pt-3 border-t border-gray-800/80">
              <div className="flex items-center gap-1.5 text-xs text-gray-400">
                <Database size={13} className="text-gray-500" />
                <span>{feed.indicator_count} indicators</span>
              </div>

              <button
                onClick={() => syncFeed(feed.feed_type)}
                disabled={syncingFeed === feed.feed_type || !feed.is_active || !token}
                className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition-colors disabled:opacity-40"
              >
                <RefreshCw
                  size={12}
                  className={syncingFeed === feed.feed_type ? 'animate-spin text-cyan-400' : ''}
                />
                Poll Feed
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

