import { getWsBaseUrl } from '@/lib/api';
import { useEffect, useState } from 'react';

export interface LiveAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  timestamp: string;
}

export function useAlertStream() {
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const ws = new WebSocket(`${getWsBaseUrl()}/ws/alerts`);

    ws.onopen = () => {
      console.log('✅ WebSocket Connected to Alert Stream');
      setIsConnected(true);
      
      // Request browser notification permission
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
      }
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      // Listen for new alerts or updates
      if (message.channel === 'alerts.new' || message.channel === 'alerts_updated') {
        const newAlert: LiveAlert = {
          id: message.data.alert_id,
          title: message.data.title,
          severity: message.data.severity,
          status: message.data.status,
          timestamp: message.data.timestamp,
        };

        // Add to top of list, keep max 20
        setAlerts((prev) => [newAlert, ...prev].slice(0, 20));

        // Trigger native browser notification
        if (Notification.permission === 'granted') {
          new Notification(`🚨 ${message.data.severity.toUpperCase()} Alert`, {
            body: message.data.title,
            icon: '/favicon.ico',
          });
        }
      }
    };

    ws.onclose = () => {
      console.log('❌ WebSocket Disconnected');
      setIsConnected(false);
    };

    return () => ws.close();
  }, []);

  return { alerts, isConnected };
}