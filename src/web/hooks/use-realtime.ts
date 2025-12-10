import { useEffect, useRef, useState } from 'react';
import { LogEntry } from '../types/api';

export function useRealtimeAttacks() {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [isConnected, setIsConnected] = useState(false);
    const wsRef = useRef<WebSocket | null>(null);

    useEffect(() => {
        // Connect to WebSocket
        const connect = () => {
            const ws = new WebSocket('ws://localhost:8000/ws/attacks');

            ws.onopen = () => {
                console.log('Connected to Nexus Attack Stream');
                setIsConnected(true);
            };

            ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    if (message.type === 'log_entry') {
                        setLogs(prev => [message.data, ...prev].slice(0, 1000)); // Keep last 1000 logs
                    }
                } catch (e) {
                    console.error('Error parsing WebSocket message', e);
                }
            };

            ws.onclose = () => {
                setIsConnected(false);
                // Reconnect after 3 seconds
                setTimeout(connect, 3000);
            };

            ws.onerror = (error) => {
                console.error('WebSocket error', error);
                ws.close();
            };

            wsRef.current = ws;
        };

        connect();

        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, []);

    return { logs, isConnected };
}
