'use client';
import { getWsBaseUrl } from '@/lib/api';


import { useEffect, useState } from 'react';

interface Alert {
  id: string;
  title: string;
  severity: string;
  status: string;
  timestamp: string;
}

export default function AlertStream() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    // Connect to WebSocket
    const ws = new WebSocket(`${getWsBaseUrl()}/ws/alerts`);

    ws.onopen = () => {
      console.log('Connected to alert stream');
      setConnected(true);
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.channel === 'alerts.new' || message.channel === 'alerts_updated') {
        const newAlert: Alert = {
          id: message.data.alert_id,
          title: message.data.title,
          severity: message.data.severity,
          status: message.data.status,
          timestamp: message.data.timestamp
        };
        
        setAlerts(prev => [newAlert, ...prev].slice(0, 10)); // Keep last 10
        
        // Show browser notification
        if (Notification.permission === 'granted') {
          new Notification(`🚨 ${message.data.severity.toUpperCase()} Alert`, {
            body: message.data.title,
            icon: '/alert-icon.png'
          });
        }
      }
    };

    ws.onclose = () => {
      console.log('Disconnected from alert stream');
      setConnected(false);
    };

    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }

    return () => {
      ws.close();
    };
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  return (
    <div className="bg-gray-900 p-4 rounded-lg">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-white">Live Alerts</h2>
        <div className={`px-2 py-1 rounded text-xs ${connected ? 'bg-green-600' : 'bg-red-600'}`}>
          {connected ? '● Connected' : '○ Disconnected'}
        </div>
      </div>
      
      <div className="space-y-2">
        {alerts.length === 0 ? (
          <p className="text-gray-400 text-sm">No alerts yet...</p>
        ) : (
          alerts.map((alert) => (
            <div key={alert.id} className={`${getSeverityColor(alert.severity)} bg-opacity-20 border-l-4 border-${alert.severity === 'critical' ? 'red' : 'orange'}-500 p-3 rounded`}>
              <div className="flex items-center justify-between">
                <span className={`text-xs font-bold uppercase ${alert.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`}>
                  {alert.severity}
                </span>
                <span className="text-gray-400 text-xs">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <p className="text-white text-sm mt-1">{alert.title}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}