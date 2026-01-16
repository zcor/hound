'use client';

import { useEffect, useState, useRef } from 'react';
import { getWebSocketUrl } from '@/lib/api';

interface ActivityLog {
  type: string;
  message?: string;
  data?: any;
  timestamp: string;
}

interface ActivityPanelProps {
  sessionId: string;
}

export default function ActivityPanel({ sessionId }: ActivityPanelProps) {
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const connectWebSocket = () => {
      try {
        const wsUrl = getWebSocketUrl(sessionId);
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('WebSocket connected');
          setConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setLogs((prev) => [...prev, data]);
          } catch (err) {
            console.error('Failed to parse WebSocket message:', err);
          }
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          setConnected(false);
        };

        ws.onclose = () => {
          console.log('WebSocket disconnected');
          setConnected(false);
          // Attempt to reconnect after 3 seconds
          setTimeout(() => {
            if (wsRef.current?.readyState === WebSocket.CLOSED) {
              connectWebSocket();
            }
          }, 3000);
        };

        wsRef.current = ws;
      } catch (err) {
        console.error('Failed to create WebSocket:', err);
        setConnected(false);
      }
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [sessionId]);

  useEffect(() => {
    // Auto-scroll to bottom when new logs arrive
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-lg bg-white dark:bg-zinc-800">
      <div className="flex items-center justify-between border-b border-zinc-200 p-4 dark:border-zinc-700">
        <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">
          Activity
        </h2>
        <div className="flex items-center gap-2">
          <div
            className={`h-2 w-2 rounded-full ${
              connected ? 'bg-green-500' : 'bg-red-500'
            }`}
          />
          <span className="text-sm text-zinc-600 dark:text-zinc-400">
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4">
        {logs.length === 0 ? (
          <div className="flex h-full items-center justify-center text-zinc-500 dark:text-zinc-400">
            {connected ? 'Waiting for activity...' : 'Connecting...'}
          </div>
        ) : (
          <div className="space-y-2">
            {logs.map((log, index) => (
              <div
                key={index}
                className="rounded border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-700 dark:bg-zinc-900"
              >
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-xs font-medium text-blue-600 dark:text-blue-400">
                    {log.type}
                  </span>
                  <span className="text-xs text-zinc-500 dark:text-zinc-400">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                {log.message && (
                  <div className="text-sm text-zinc-700 dark:text-zinc-300">
                    {log.message}
                  </div>
                )}
                {log.data && (
                  <pre className="mt-2 overflow-x-auto text-xs text-zinc-600 dark:text-zinc-400">
                    {JSON.stringify(log.data, null, 2)}
                  </pre>
                )}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        )}
      </div>
    </div>
  );
}
