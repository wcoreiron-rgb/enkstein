'use client';
import { useCallback, useEffect, useState } from 'react';
import { Activity } from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { getEvents, getAnomalies } from '@/lib/api';
import ClientDate from '@/components/ClientDate';

export default function EventsPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [tab, setTab] = useState<'all' | 'anomalies'>('all');

  const loadEvents = useCallback(() => {
    Promise.all([getEvents(), getAnomalies()])
      .then(([events, anomalies]) => {
        setEvents(events);
        setAnomalies(anomalies);
        setLoadError(null);
      })
      .catch(error => setLoadError(error?.message || 'Could not reach the Enkstein API.'));
  }, []);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  const shown = tab === 'all' ? events : anomalies;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Activity className="text-green-400" /> Events
        </h1>
        <p className="text-gray-400 mt-1">CoreOS Telemetry Bus — unified event stream across all Capability Nodes</p>
      </div>

      <div className="flex gap-2 border-b border-gray-800 pb-2">
        {(['all', 'anomalies'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${tab === t ? 'bg-regent-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            {t === 'all' ? `All Events (${events.length})` : `Anomalies (${anomalies.length})`}
          </button>
        ))}
      </div>

      {loadError ? (
        <div className="rounded-xl border border-red-700/40 p-8 text-center" style={{ background: 'var(--rc-bg-surface)' }}>
          <p className="text-red-400 font-semibold mb-2">Could not load events</p>
          <p className="text-sm mb-4" style={{ color: 'var(--rc-text-2)' }}>{loadError}</p>
          <button
            onClick={loadEvents}
            className="px-4 py-2 rounded text-sm font-medium"
            style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-1)', border: '1px solid var(--rc-border)' }}>
            Retry
          </button>
        </div>
      ) : (
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Timestamp</th>
                <th className="px-6 py-3 text-left">Module</th>
                <th className="px-6 py-3 text-left">Actor</th>
                <th className="px-6 py-3 text-left">Action</th>
                <th className="px-6 py-3 text-left">Outcome</th>
                <th className="px-6 py-3 text-left">Severity</th>
                <th className="px-6 py-3 text-right">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {shown.length === 0 && (
                <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500">No events yet.</td></tr>
              )}
              {shown.map((e: any) => (
                <tr key={e.id} className={`hover:bg-gray-800/50 ${e.is_anomaly ? 'border-l-2 border-orange-500' : ''}`}>
                  <td className="px-6 py-3 text-gray-500 whitespace-nowrap text-xs"><ClientDate value={e.timestamp} /></td>
                  <td className="px-6 py-3 text-regent-400 font-medium">{e.source_module}</td>
                  <td className="px-6 py-3 text-gray-300">{e.actor_name ?? '—'}</td>
                  <td className="px-6 py-3 text-white">{e.action}</td>
                  <td className="px-6 py-3"><RiskBadge value={e.outcome} /></td>
                  <td className="px-6 py-3"><RiskBadge value={e.severity} /></td>
                  <td className="px-6 py-3 text-right font-mono text-gray-300">{e.risk_score?.toFixed(0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      )}
    </div>
  );
}
