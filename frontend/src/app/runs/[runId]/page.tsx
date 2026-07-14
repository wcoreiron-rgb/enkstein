'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  Play, CheckCircle, XCircle, Clock, ChevronLeft,
  Bot, Shield, Zap, AlertTriangle, RefreshCw,
  Activity, Database, Bell, GitMerge, SkipForward,
  ChevronDown, ChevronRight,
} from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { getRunReplayById } from '@/lib/api';
import ClientDate from '@/components/ClientDate';
import { capabilityName } from '@/lib/capability-names';

// ─── Step type icons ──────────────────────────────────────────────────────────
const STEP_TYPE_META: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  agent_run:    { icon: Bot,         color: 'text-blue-400',   label: 'Agent Run' },
  policy_check: { icon: Shield,      color: 'text-purple-400', label: 'Policy Check' },
  condition:    { icon: GitMerge,    color: 'text-orange-400', label: 'Condition' },
  wait:         { icon: Clock,       color: 'text-gray-400',   label: 'Wait' },
  notify:       { icon: Bell,        color: 'text-yellow-400', label: 'Notify' },
  unknown:      { icon: Activity,    color: 'text-gray-500',   label: 'Step' },
};

const STATUS_META: Record<string, { icon: React.ElementType; color: string; bg: string }> = {
  completed: { icon: CheckCircle, color: 'text-green-400',  bg: 'bg-green-900/30 border-green-800' },
  failed:    { icon: XCircle,     color: 'text-red-400',    bg: 'bg-red-900/30 border-red-800' },
  skipped:   { icon: SkipForward, color: 'text-gray-500',   bg: 'bg-gray-800/60 border-gray-700' },
  running:   { icon: RefreshCw,   color: 'text-blue-400',   bg: 'bg-blue-900/20 border-blue-800' },
  unknown:   { icon: Clock,       color: 'text-gray-400',   bg: 'bg-gray-900 border-gray-800' },
};

export default function RunReplayPage() {
  const { runId } = useParams<{ runId: string }>();
  const router = useRouter();
  const [replay, setReplay] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [expandedStep, setExpandedStep] = useState<number | null>(null);

  useEffect(() => {
    if (!runId) return;
    setLoading(true);
    getRunReplayById(runId)
      .then(setReplay)
      .catch(e => setError(e.message || 'Failed to load run'))
      .finally(() => setLoading(false));
  }, [runId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (error || !replay) {
    return (
      <div className="px-6 py-12 text-center">
        <XCircle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-white">{error || 'Run not found'}</p>
        <button onClick={() => router.back()} className="mt-4 text-sm text-cyan-400">← Go back</button>
      </div>
    );
  }

  const { workflow, run, timeline, completed_count, failed_count, skipped_count, success_rate } = replay;

  const runStatusMeta = STATUS_META[run.status] ?? STATUS_META.unknown;
  const RunIcon = runStatusMeta.icon;

  return (
    <div className="space-y-6">

      {/* Header */}
      <div>
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white mb-4 transition-colors"
        >
          <ChevronLeft className="w-4 h-4" /> Back to runs
        </button>

        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Play className="text-cyan-400" /> Flight Recorder
            </h1>
            <p className="text-gray-400 mt-1">{workflow.name}</p>
          </div>
          <div className={`flex items-center gap-2 px-4 py-2 rounded-xl border ${runStatusMeta.bg}`}>
            <RunIcon className={`w-5 h-5 ${runStatusMeta.color}`} />
            <span className={`font-semibold text-sm ${runStatusMeta.color}`}>{run.status.toUpperCase()}</span>
          </div>
        </div>
      </div>

      {/* Run summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Duration',    value: run.duration_sec != null ? `${run.duration_sec.toFixed(2)}s` : '—', color: 'text-white' },
          { label: 'Completed',   value: completed_count, color: 'text-green-400' },
          { label: 'Failed',      value: failed_count,    color: failed_count > 0 ? 'text-red-400' : 'text-gray-500' },
          { label: 'Skipped',     value: skipped_count,   color: 'text-gray-400' },
          { label: 'Success Rate', value: `${success_rate}%`, color: success_rate === 100 ? 'text-green-400' : success_rate >= 75 ? 'text-yellow-400' : 'text-red-400' },
        ].map(s => (
          <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
            <p className="text-xs text-gray-500 mb-1">{s.label}</p>
            <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Metadata strip */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-4 flex flex-wrap gap-6 text-sm">
        <div>
          <p className="text-xs text-gray-500">Run ID</p>
          <p className="text-white font-mono text-xs mt-0.5">{run.id}</p>
        </div>
        <div>
          <p className="text-xs text-gray-500">Triggered by</p>
          <p className="text-white text-xs mt-0.5">{run.triggered_by}</p>
        </div>
        <div>
          <p className="text-xs text-gray-500">Started</p>
          <p className="text-white text-xs mt-0.5"><ClientDate value={run.started_at} fallback="—" /></p>
        </div>
        <div>
          <p className="text-xs text-gray-500">Completed</p>
          <p className="text-white text-xs mt-0.5"><ClientDate value={run.completed_at} fallback="—" /></p>
        </div>
        {workflow.category && (
          <div>
            <p className="text-xs text-gray-500">Category</p>
            <p className="text-white text-xs mt-0.5">{workflow.category}</p>
          </div>
        )}
      </div>

      {/* Summary */}
      {run.summary && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-4">
          <p className="text-xs text-gray-500 mb-1.5">Execution Summary</p>
          <p className="text-gray-300 text-sm leading-relaxed">{run.summary}</p>
        </div>
      )}

      {/* Timeline */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" /> Step-by-Step Timeline
          </h2>
        </div>

        {timeline.length === 0 ? (
          <p className="px-6 py-8 text-gray-500 text-sm">No step data available for this run.</p>
        ) : (
          <div className="relative">
            {/* Vertical timeline line */}
            <div className="absolute left-[3.25rem] top-0 bottom-0 w-px bg-gray-800" />

            <div className="space-y-0">
              {timeline.map((step: any, idx: number) => {
                const typeMeta   = STEP_TYPE_META[step.type] ?? STEP_TYPE_META.unknown;
                const statusMeta = STATUS_META[step.status] ?? STATUS_META.unknown;
                const TypeIcon   = typeMeta.icon;
                const StatusIcon = statusMeta.icon;
                const isExpanded = expandedStep === idx;
                const isLast     = idx === timeline.length - 1;

                return (
                  <div key={idx} className={`relative ${!isLast ? 'border-b border-gray-800/40' : ''}`}>
                    {/* Timeline dot */}
                    <div className={`absolute left-10 top-5 w-3 h-3 rounded-full border-2 z-10 ${statusMeta.color.replace('text-', 'border-')} bg-gray-900`} />

                    {/* Step row */}
                    <button
                      onClick={() => setExpandedStep(isExpanded ? null : idx)}
                      className="w-full px-6 py-4 pl-16 flex items-start gap-4 hover:bg-gray-800/20 transition-colors text-left"
                    >
                      {/* Index */}
                      <span className="flex-shrink-0 text-xs text-gray-600 font-mono w-4">{step.index}</span>

                      {/* Type icon */}
                      <TypeIcon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${typeMeta.color}`} />

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-white text-sm font-medium">{step.name}</p>
                          <span className={`text-xs px-1.5 py-0.5 rounded ${typeMeta.color} bg-gray-800`}>
                            {typeMeta.label}
                          </span>
                          {step.data_source === 'real_api' && (
                            <span className="text-xs text-green-400 bg-green-900/30 border border-green-800 rounded px-1.5 py-0.5">
                              live data
                            </span>
                          )}
                          {step.alerts_routed > 0 && (
                            <span className="text-xs text-yellow-400 flex items-center gap-1">
                              <Bell className="w-3 h-3" /> {step.alerts_routed} alerts
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-400 mt-1 line-clamp-2">{step.output}</p>
                      </div>

                      {/* Right side: status + duration */}
                      <div className="flex items-center gap-3 flex-shrink-0">
                        {step.duration_ms != null && (
                          <span className="text-xs text-gray-500">
                            {step.duration_ms < 1000
                              ? `${step.duration_ms}ms`
                              : `${(step.duration_ms / 1000).toFixed(1)}s`}
                          </span>
                        )}
                        <StatusIcon className={`w-4 h-4 ${statusMeta.color}`} />
                        {isExpanded
                          ? <ChevronDown className="w-3.5 h-3.5 text-gray-600" />
                          : <ChevronRight className="w-3.5 h-3.5 text-gray-600" />
                        }
                      </div>
                    </button>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <div className="px-16 pb-5 pl-24 space-y-4">

                        {/* Full output */}
                        {step.output && (
                          <div>
                            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1.5">Output</p>
                            <div className="bg-gray-800 rounded-lg px-4 py-3">
                              <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">{step.output}</p>
                            </div>
                          </div>
                        )}

                        {/* Agent info */}
                        {step.agent_info && (
                          <div>
                            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1.5">Agent</p>
                            <div className="flex items-center gap-3 bg-gray-800 rounded-lg px-4 py-3">
                              <Bot className="w-4 h-4 text-blue-400" />
                              <div>
                                <p className="text-white text-xs font-medium">{step.agent_info.name}</p>
                                <p className="text-gray-400 text-xs">{capabilityName(step.agent_info.claw)} · {step.agent_info.execution_mode} · risk: {step.agent_info.risk_level}</p>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Timing */}
                        <div className="flex gap-6 text-xs text-gray-400">
                          {step.started_at && (
                            <span><span className="text-gray-600">Started: </span><ClientDate value={step.started_at} format="time" /></span>
                          )}
                          {step.completed_at && (
                            <span><span className="text-gray-600">Completed: </span><ClientDate value={step.completed_at} format="time" /></span>
                          )}
                          <span><span className="text-gray-600">On failure: </span>{step.on_failure}</span>
                          {step.event_id && (
                            <span><span className="text-gray-600">Event ID: </span>{step.event_id}</span>
                          )}
                        </div>

                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
