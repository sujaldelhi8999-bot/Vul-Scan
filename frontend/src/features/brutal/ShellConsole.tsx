import { useEffect, useRef, useState } from 'react';
import { Terminal, X } from 'lucide-react';
import toast from 'react-hot-toast';

import { createAuthenticatedWebSocket, expireSession, refreshSessionToken } from '../../services/api';
import { Button } from '../../components/ui/Primitives';

interface ShellConsoleProps {
  shellId: string;
  onClose: () => void;
}

export default function ShellConsole({ shellId, onClose }: ShellConsoleProps) {
  const [lines, setLines] = useState<string[]>(['[vulscan] connecting to shell session...']);
  const [input, setInput] = useState('');
  const [connected, setConnected] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);
  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let active = true;
    let refreshCycles = 0;

    const connect = async () => {
      if (!active) return;
      const refreshed = await refreshSessionToken();
      if (!active) return;
      if (!refreshed) {
        expireSession();
        return;
      }
      try {
        socket = await createAuthenticatedWebSocket(`/ws/brutal/shell/${shellId}`, 'brutal');
      } catch {
        setLines((prev) => [...prev, '[vulscan] failed to create authenticated shell connection']);
        return;
      }
      socketRef.current = socket;

      timer = setTimeout(() => {
        if (socket && socket.readyState === WebSocket.CONNECTING) {
          setLines((prev) => [...prev, '[vulscan] connection timed out']);
          socket.close();
        }
      }, 8000);

      socket.onopen = () => {
        setConnected(true);
        setLines((prev) => [...prev, '[vulscan] shell established — type commands below']);
      };

      socket.onmessage = (event) => {
        const text = String(event.data);
        if (text === '__ready__') {
          setLines((prev) => [...prev, '[vulscan] shell ready']);
          return;
        }
        if (text === '__closed__') {
          setConnected(false);
          setLines((prev) => [...prev, '[vulscan] shell session closed']);
          return;
        }
        setLines((prev) => [...prev, text]);
      };

      socket.onerror = () => {
        setConnected(false);
        setLines((prev) => [...prev, '[vulscan] connection error']);
      };

      socket.onclose = (event: CloseEvent) => {
        setConnected(false);
        if (!active) return;
        if (event.code === 4000 || event.code === 4001) {
          refreshCycles += 1;
          if (refreshCycles > 2) {
            setLines((prev) => [...prev, '[vulscan] session expired — please log in again']);
            expireSession();
            return;
          }
          setLines((prev) => [...prev, '[vulscan] token refreshed — reconnecting...']);
          void connect();
          return;
        }
        if (event.code === 1008) {
          setLines((prev) => [...prev, '[vulscan] authentication failed — please log in again']);
          expireSession();
          return;
        }
        setLines((prev) => [...prev, '[vulscan] disconnected']);
      };
    };

    try {
      void connect();
    } catch (err) {
      setLines((prev) => [...prev, `[vulscan] failed to connect: ${String(err)}`]);
    }

    return () => {
      active = false;
      if (timer) clearTimeout(timer);
      try {
        socket?.close();
      } catch {
        /* noop */
      }
    };
  }, [shellId]);

  useEffect(() => {
    outputRef.current?.scrollTo({ top: outputRef.current.scrollHeight });
  }, [lines]);

  useEffect(() => {
    if (connected) inputRef.current?.focus();
  }, [connected]);

  const send = () => {
    const socket = socketRef.current;
    const command = input.trim();
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      toast.error('Shell is not connected');
      return;
    }
    if (!command) return;
    setLines((prev) => [...prev, `$ ${command}`]);
    socket.send(command);
    setInput('');
  };

  return (
    <div className="overflow-hidden rounded-xl border border-[var(--border-default)] bg-[#0b0f14]">
      <div className="flex items-center justify-between border-b border-white/10 px-3 py-2">
        <div className="flex items-center gap-2">
          <Terminal className="h-3.5 w-3.5 text-green-400" />
          <span className="font-mono text-[11px] font-semibold text-gray-300">
            target-shell:{shellId.slice(0, 8)}
          </span>
          <span
            className={`h-1.5 w-1.5 rounded-full ${connected ? 'animate-pulse bg-green-400' : 'bg-red-500'}`}
          />
        </div>
        <Button variant="ghost" className="!px-2 !py-1 text-gray-400 hover:text-white" onClick={onClose}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      <div ref={outputRef} className="h-72 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed text-gray-300 scrollbar-compact">
        {lines.map((line, index) => (
          <div key={index} className={line.startsWith('[vulscan]') ? 'text-cyan-400/80' : 'whitespace-pre-wrap'}>
            {line || '\u00A0'}
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2 border-t border-white/10 px-3 py-2">
        <span className="font-mono text-[11px] text-green-400">$</span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') send();
          }}
          placeholder={connected ? 'e.g. whoami, netstat -ano, cat /etc/passwd, env, exit' : 'connecting...'}
          disabled={!connected}
          className="flex-1 bg-transparent font-mono text-[11px] text-gray-200 placeholder-gray-600 outline-none"
        />
      </div>
    </div>
  );
}
