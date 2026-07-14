'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Check,
  CircleAlert,
  Clock3,
  DatabaseBackup,
  KeyRound,
  MessageSquare,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Send,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import {
  acknowledgeMarcellusPlexusMessage,
  approveMarcellusPlexusMessage,
  approveMarcellusReflexExecution,
  approveMarcellusRegeneration,
  createMarcellusCheckpoint,
  createMarcellusReflex,
  evaluateMarcellusReflexes,
  getMarcellusCheckpoints,
  getMarcellusNodeRuntimes,
  getMarcellusPlexusMessages,
  getMarcellusReflexExecutions,
  getMarcellusReflexes,
  getMarcellusRegenerationRuns,
  MarcellusCapabilityNode,
  MarcellusCheckpoint,
  MarcellusNodeRuntime,
  MarcellusPlexusMessage,
  MarcellusReflexDefinition,
  MarcellusReflexExecution,
  MarcellusRegenerationRun,
  sendMarcellusPlexusMessage,
  startMarcellusRegeneration,
  verifyMarcellusCheckpoint,
} from '@/lib/api';

type RuntimeTab = 'plexus' | 'reflexes' | 'regeneration';

const CONTROL = 'w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-red-500/40';
const BUTTON = 'inline-flex h-9 items-center justify-center gap-2 rounded-md px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50';

function fieldStyle(): React.CSSProperties {
  return {
    background: 'var(--rc-bg-elevated)',
    borderColor: 'var(--rc-border)',
    color: 'var(--rc-text-1)',
  };
}

function parseObject(value: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

function parseArray(value: string, label: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error(`${label} must be a JSON array`);
  return parsed;
}

function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  return 'The runtime request could not be completed.';
}

function statusColor(status: string): string {
  if (['delivered', 'processed', 'completed', 'active', 'verified', 'executed'].includes(status)) return '#16a34a';
  if (['requires_approval', 'pending', 'quarantined'].includes(status)) return '#d97706';
  if (['denied', 'rejected', 'failed', 'expired'].includes(status)) return '#dc2626';
  return '#64748b';
}

function Status({ value }: { value: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: statusColor(value) }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: statusColor(value) }} />
      {value.replaceAll('_', ' ')}
    </span>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>{children}</label>;
}

function Empty({ text }: { text: string }) {
  return <p className="py-8 text-center text-sm" style={{ color: 'var(--rc-text-3)' }}>{text}</p>;
}

export default function MarcellusRuntimeConsole({ nodes }: { nodes: MarcellusCapabilityNode[] }) {
  const nodeIds = useMemo(() => nodes.map((node) => node.id), [nodes]);
  const [tab, setTab] = useState<RuntimeTab>('plexus');
  const [tenantId, setTenantId] = useState('demo-tenant');
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null);

  const [messages, setMessages] = useState<MarcellusPlexusMessage[]>([]);
  const [reflexes, setReflexes] = useState<MarcellusReflexDefinition[]>([]);
  const [executions, setExecutions] = useState<MarcellusReflexExecution[]>([]);
  const [checkpoints, setCheckpoints] = useState<MarcellusCheckpoint[]>([]);
  const [runs, setRuns] = useState<MarcellusRegenerationRun[]>([]);
  const [runtimes, setRuntimes] = useState<MarcellusNodeRuntime[]>([]);

  const [sender, setSender] = useState(nodeIds[0] || 'threat-analysis');
  const [recipient, setRecipient] = useState(nodeIds[1] || 'threat-intelligence');
  const [messageType, setMessageType] = useState('capability.request');
  const [messagePayload, setMessagePayload] = useState('{\n  "request": "Correlate this signal",\n  "severity": "high"\n}');

  const [reflexName, setReflexName] = useState('Critical signal relay');
  const [reflexNode, setReflexNode] = useState(nodeIds[0] || 'threat-analysis');
  const [reflexEventType, setReflexEventType] = useState('finding.created');
  const [reflexConditions, setReflexConditions] = useState('[{"field":"severity","operator":"in","value":["critical","high"]}]');
  const [reflexAction, setReflexAction] = useState<'record_signal' | 'plexus_notify'>('record_signal');
  const [reflexRecipient, setReflexRecipient] = useState(nodeIds[1] || 'threat-intelligence');
  const [reflexAuthority, setReflexAuthority] = useState<'observe' | 'recommend' | 'approval_gated_action'>('observe');
  const [eventPayload, setEventPayload] = useState('{\n  "severity": "critical",\n  "finding_id": "finding-001"\n}');

  const [checkpointNode, setCheckpointNode] = useState(nodeIds[0] || 'threat-analysis');
  const [checkpointState, setCheckpointState] = useState('{\n  "cursor": "event-1042",\n  "mode": "monitoring"\n}');

  const refresh = useCallback(async () => {
    if (!tenantId.trim()) return;
    setLoading(true);
    setNotice(null);
    try {
      const [nextMessages, nextReflexes, nextExecutions, nextCheckpoints, nextRuns, nextRuntimes] = await Promise.all([
        getMarcellusPlexusMessages(tenantId),
        getMarcellusReflexes(tenantId),
        getMarcellusReflexExecutions(tenantId),
        getMarcellusCheckpoints(tenantId),
        getMarcellusRegenerationRuns(tenantId),
        getMarcellusNodeRuntimes(tenantId),
      ]);
      setMessages(nextMessages);
      setReflexes(nextReflexes);
      setExecutions(nextExecutions);
      setCheckpoints(nextCheckpoints);
      setRuns(nextRuns);
      setRuntimes(nextRuntimes);
    } catch (error) {
      setNotice({ kind: 'error', text: errorText(error) });
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => { refresh(); }, [refresh]);

  const perform = async (key: string, action: () => Promise<unknown>, success: string) => {
    setBusy(key);
    setNotice(null);
    try {
      await action();
      await refresh();
      setNotice({ kind: 'ok', text: success });
    } catch (error) {
      setNotice({ kind: 'error', text: errorText(error) });
    } finally {
      setBusy(null);
    }
  };

  const sendMessage = (event: FormEvent) => {
    event.preventDefault();
    void perform('send-message', () => sendMarcellusPlexusMessage({
      tenant_id: tenantId,
      sender_node_id: sender,
      recipient_node_id: recipient,
      message_type: messageType,
      payload: parseObject(messagePayload, 'Payload'),
      classification: 'internal',
      idempotency_key: `ui-${crypto.randomUUID()}`,
    }), 'Peer message accepted by the Plexus.');
  };

  const registerReflex = (event: FormEvent) => {
    event.preventDefault();
    void perform('create-reflex', () => createMarcellusReflex({
      tenant_id: tenantId,
      name: reflexName,
      node_id: reflexNode,
      event_type: reflexEventType,
      conditions: parseArray(reflexConditions, 'Conditions'),
      action_kind: reflexAction,
      action_config: reflexAction === 'plexus_notify' ? { recipient_node_id: reflexRecipient } : {},
      authority: reflexAuthority,
      classification: 'internal',
      max_runs_per_hour: 10,
      cooldown_seconds: 30,
    }), 'Reflex registered with its policy envelope.');
  };

  const evaluateEvent = () => void perform('evaluate-reflex', () => evaluateMarcellusReflexes({
    tenant_id: tenantId,
    event_id: `ui-event-${crypto.randomUUID()}`,
    event_type: reflexEventType,
    payload: parseObject(eventPayload, 'Event payload'),
    classification: 'internal',
  }), 'Event evaluated against active Reflexes.');

  const saveCheckpoint = (event: FormEvent) => {
    event.preventDefault();
    void perform('create-checkpoint', () => createMarcellusCheckpoint({
      tenant_id: tenantId,
      node_id: checkpointNode,
      state: parseObject(checkpointState, 'Checkpoint state'),
      manifest: {
        skills: [],
        connectors: [],
        policy_pack_ids: [],
        memory_refs: [],
        configuration: { source: 'operator-console' },
      },
    }), 'Signed checkpoint created.');
  };

  const pendingReflexes = executions.filter((item) => item.status === 'requires_approval').length;
  const pendingRegenerations = runs.filter((item) => item.status === 'requires_approval').length;

  return (
    <section className="border-y py-6" style={{ borderColor: 'var(--rc-border)' }}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-red-500" />
            <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>Distributed Runtime</h2>
          </div>
          <div className="mt-2 flex flex-wrap gap-4 text-xs" style={{ color: 'var(--rc-text-3)' }}>
            <span>{messages.length} messages</span>
            <span>{reflexes.length} reflexes</span>
            <span>{pendingReflexes + pendingRegenerations} awaiting approval</span>
            <span>{runtimes.length} regenerated runtimes</span>
          </div>
        </div>
        <div className="flex items-end gap-2">
          <div>
            <Label>Tenant</Label>
            <input className={`${CONTROL} h-9 w-44`} style={fieldStyle()} value={tenantId} onChange={(event) => setTenantId(event.target.value)} />
          </div>
          <button type="button" title="Refresh runtime" aria-label="Refresh runtime" onClick={refresh} disabled={loading} className={`${BUTTON} w-9 border px-0`} style={fieldStyle()}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="mt-5 flex border-b" style={{ borderColor: 'var(--rc-border)' }}>
        {([
          ['plexus', 'Plexus', MessageSquare],
          ['reflexes', 'Reflexes', Zap],
          ['regeneration', 'Regeneration', RotateCcw],
        ] as const).map(([id, label, Icon]) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className="flex min-h-10 items-center gap-2 border-b-2 px-4 text-sm font-medium"
            style={{
              borderColor: tab === id ? '#ef4444' : 'transparent',
              color: tab === id ? 'var(--rc-text-1)' : 'var(--rc-text-3)',
            }}
          >
            <Icon className="h-4 w-4" /> {label}
          </button>
        ))}
      </div>

      {notice && (
        <div className="mt-4 flex items-center gap-2 rounded-md border px-3 py-2 text-sm" style={{
          borderColor: notice.kind === 'ok' ? '#16a34a55' : '#dc262655',
          color: notice.kind === 'ok' ? '#16a34a' : '#ef4444',
        }}>
          {notice.kind === 'ok' ? <Check className="h-4 w-4" /> : <CircleAlert className="h-4 w-4" />}
          {notice.text}
        </div>
      )}

      {tab === 'plexus' && (
        <div className="mt-5 grid gap-6 xl:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.5fr)]">
          <form onSubmit={sendMessage} className="space-y-4">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Send Peer Message</h3>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
              <div><Label>Sender Node</Label><select className={CONTROL} style={fieldStyle()} value={sender} onChange={(event) => setSender(event.target.value)}>{nodeIds.map((id) => <option key={id}>{id}</option>)}</select></div>
              <div><Label>Recipient Node</Label><select className={CONTROL} style={fieldStyle()} value={recipient} onChange={(event) => setRecipient(event.target.value)}>{nodeIds.map((id) => <option key={id}>{id}</option>)}</select></div>
            </div>
            <div><Label>Message Type</Label><input className={CONTROL} style={fieldStyle()} value={messageType} onChange={(event) => setMessageType(event.target.value)} /></div>
            <div><Label>Payload</Label><textarea rows={6} className={`${CONTROL} resize-y font-mono text-xs`} style={fieldStyle()} value={messagePayload} onChange={(event) => setMessagePayload(event.target.value)} /></div>
            <button type="submit" disabled={busy !== null || sender === recipient} className={`${BUTTON} bg-red-600 text-white hover:bg-red-700`}><Send className="h-4 w-4" /> Send</button>
          </form>

          <div className="min-w-0">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Message Ledger</h3>
            <div className="mt-3 divide-y overflow-hidden rounded-md border" style={{ borderColor: 'var(--rc-border)' }}>
              {messages.length === 0 ? <Empty text="No Plexus messages for this tenant." /> : messages.map((message) => (
                <div key={message.id} className="p-3" style={{ borderColor: 'var(--rc-border)' }}>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{message.sender_node_id} <span style={{ color: 'var(--rc-text-3)' }}>to</span> {message.recipient_node_id}</p>
                      <p className="mt-1 truncate text-xs" style={{ color: 'var(--rc-text-3)' }}>{message.message_type} | {message.correlation_id}</p>
                    </div>
                    <Status value={message.status} />
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                    <span className="inline-flex items-center gap-1"><KeyRound className="h-3 w-3" /> {message.signature_algorithm}</span>
                    <span>risk {Math.round(message.risk_score)}</span>
                    <span className="font-mono">{message.payload_digest.slice(0, 12)}</span>
                    {message.status === 'delivered' && <button type="button" className="font-medium text-green-500" onClick={() => perform(`ack-${message.id}`, () => acknowledgeMarcellusPlexusMessage(message.id, { tenant_id: tenantId, recipient_node_id: message.recipient_node_id }), 'Message signature verified and acknowledged.')}>Acknowledge</button>}
                    {message.status === 'requires_approval' && <button type="button" className="font-medium text-amber-500" onClick={() => perform(`approve-message-${message.id}`, () => approveMarcellusPlexusMessage(message.id, tenantId), 'Peer message approved.')}>Approve</button>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === 'reflexes' && (
        <div className="mt-5 space-y-6">
          <div className="grid gap-6 xl:grid-cols-2">
            <form onSubmit={registerReflex} className="space-y-4">
              <div className="flex items-center gap-2"><Plus className="h-4 w-4 text-amber-500" /><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Register Reflex</h3></div>
              <div className="grid gap-3 sm:grid-cols-2"><div><Label>Name</Label><input className={CONTROL} style={fieldStyle()} value={reflexName} onChange={(event) => setReflexName(event.target.value)} /></div><div><Label>Owner Node</Label><select className={CONTROL} style={fieldStyle()} value={reflexNode} onChange={(event) => setReflexNode(event.target.value)}>{nodeIds.map((id) => <option key={id}>{id}</option>)}</select></div></div>
              <div className="grid gap-3 sm:grid-cols-2"><div><Label>Event Type</Label><input className={CONTROL} style={fieldStyle()} value={reflexEventType} onChange={(event) => setReflexEventType(event.target.value)} /></div><div><Label>Authority</Label><select disabled={reflexAction === 'record_signal'} className={CONTROL} style={fieldStyle()} value={reflexAuthority} onChange={(event) => setReflexAuthority(event.target.value as typeof reflexAuthority)}><option value="observe">Observe</option><option value="recommend">Recommend</option><option value="approval_gated_action">Approval gated</option></select></div></div>
              <div><Label>Conditions</Label><textarea rows={3} className={`${CONTROL} font-mono text-xs`} style={fieldStyle()} value={reflexConditions} onChange={(event) => setReflexConditions(event.target.value)} /></div>
              <div className="grid gap-3 sm:grid-cols-2"><div><Label>Action</Label><select className={CONTROL} style={fieldStyle()} value={reflexAction} onChange={(event) => { const action = event.target.value as typeof reflexAction; setReflexAction(action); if (action === 'record_signal') setReflexAuthority('observe'); }}><option value="record_signal">Record signal</option><option value="plexus_notify">Plexus notify</option></select></div>{reflexAction === 'plexus_notify' && <div><Label>Recipient Node</Label><select className={CONTROL} style={fieldStyle()} value={reflexRecipient} onChange={(event) => setReflexRecipient(event.target.value)}>{nodeIds.map((id) => <option key={id}>{id}</option>)}</select></div>}</div>
              <button type="submit" disabled={busy !== null} className={`${BUTTON} bg-amber-600 text-white hover:bg-amber-700`}><ShieldCheck className="h-4 w-4" /> Register</button>
            </form>
            <div className="space-y-4">
              <div className="flex items-center gap-2"><Play className="h-4 w-4 text-amber-500" /><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Evaluate Event</h3></div>
              <div><Label>Event Payload</Label><textarea rows={7} className={`${CONTROL} font-mono text-xs`} style={fieldStyle()} value={eventPayload} onChange={(event) => setEventPayload(event.target.value)} /></div>
              <button type="button" disabled={busy !== null} onClick={evaluateEvent} className={`${BUTTON} border`} style={fieldStyle()}><Zap className="h-4 w-4" /> Evaluate</button>
            </div>
          </div>
          <div className="grid gap-5 xl:grid-cols-2">
            <div><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Definitions</h3><div className="mt-3 divide-y rounded-md border" style={{ borderColor: 'var(--rc-border)' }}>{reflexes.length === 0 ? <Empty text="No Reflex definitions for this tenant." /> : reflexes.map((reflex) => <div key={reflex.id} className="flex items-start justify-between gap-3 p-3"><div><p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{reflex.name}</p><p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>{reflex.node_id} | {reflex.event_type} | {reflex.run_count} runs</p></div><Status value={reflex.is_active ? 'active' : 'inactive'} /></div>)}</div></div>
            <div><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Execution Decisions</h3><div className="mt-3 divide-y rounded-md border" style={{ borderColor: 'var(--rc-border)' }}>{executions.length === 0 ? <Empty text="No Reflex executions for this tenant." /> : executions.map((execution) => <div key={execution.id} className="p-3"><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{execution.event_type}</p><p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>{execution.policy_outcome} | risk {Math.round(execution.risk_score)}</p></div><Status value={execution.status} /></div>{execution.status === 'requires_approval' && <button type="button" className="mt-2 text-xs font-medium text-amber-500" onClick={() => perform(`approve-reflex-${execution.id}`, () => approveMarcellusReflexExecution(execution.id, tenantId), 'Reflex execution approved and re-evaluated.')}>Approve execution</button>}</div>)}</div></div>
          </div>
        </div>
      )}

      {tab === 'regeneration' && (
        <div className="mt-5 space-y-6">
          <div className="grid gap-6 xl:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.5fr)]">
            <form onSubmit={saveCheckpoint} className="space-y-4">
              <div className="flex items-center gap-2"><DatabaseBackup className="h-4 w-4 text-green-500" /><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Create Checkpoint</h3></div>
              <div><Label>Capability Node</Label><select className={CONTROL} style={fieldStyle()} value={checkpointNode} onChange={(event) => setCheckpointNode(event.target.value)}>{nodeIds.map((id) => <option key={id}>{id}</option>)}</select></div>
              <div><Label>Recoverable State</Label><textarea rows={6} className={`${CONTROL} font-mono text-xs`} style={fieldStyle()} value={checkpointState} onChange={(event) => setCheckpointState(event.target.value)} /></div>
              <button type="submit" disabled={busy !== null} className={`${BUTTON} bg-green-700 text-white hover:bg-green-800`}><DatabaseBackup className="h-4 w-4" /> Checkpoint</button>
            </form>
            <div><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Signed Checkpoints</h3><div className="mt-3 divide-y rounded-md border" style={{ borderColor: 'var(--rc-border)' }}>{checkpoints.length === 0 ? <Empty text="No signed checkpoints for this tenant." /> : checkpoints.map((checkpoint) => <div key={checkpoint.id} className="p-3"><div className="flex flex-wrap items-start justify-between gap-2"><div><p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{checkpoint.node_id} <span style={{ color: 'var(--rc-text-3)' }}>v{checkpoint.version}</span></p><p className="mt-1 font-mono text-xs" style={{ color: 'var(--rc-text-3)' }}>{checkpoint.state_digest.slice(0, 16)} | {checkpoint.signature_algorithm}</p></div><Status value={checkpoint.status} /></div><div className="mt-2 flex gap-3"><button type="button" className="text-xs font-medium text-cyan-500" onClick={() => perform(`verify-${checkpoint.id}`, () => verifyMarcellusCheckpoint(checkpoint.id, tenantId), 'Checkpoint signature and manifest verified.')}>Verify</button><button type="button" className="text-xs font-medium text-green-500" onClick={() => perform(`regenerate-${checkpoint.id}`, () => startMarcellusRegeneration(tenantId, checkpoint.id), 'Regeneration request passed into its approval gate.')}>Regenerate</button></div></div>)}</div></div>
          </div>
          <div className="grid gap-5 xl:grid-cols-2">
            <div><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Regeneration Runs</h3><div className="mt-3 divide-y rounded-md border" style={{ borderColor: 'var(--rc-border)' }}>{runs.length === 0 ? <Empty text="No Regeneration runs for this tenant." /> : runs.map((run) => <div key={run.id} className="p-3"><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{run.node_id}</p><p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>{run.policy_outcome} | risk {Math.round(run.risk_score)}</p></div><Status value={run.status} /></div>{run.status === 'requires_approval' && <button type="button" className="mt-2 text-xs font-medium text-amber-500" onClick={() => perform(`approve-regeneration-${run.id}`, () => approveMarcellusRegeneration(run.id, tenantId), 'Regeneration approved and executed.')}>Approve and execute</button>}</div>)}</div></div>
            <div><h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Node Runtimes</h3><div className="mt-3 divide-y rounded-md border" style={{ borderColor: 'var(--rc-border)' }}>{runtimes.length === 0 ? <Empty text="No regenerated runtimes for this tenant." /> : runtimes.map((runtime) => <div key={runtime.id} className="p-3"><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{runtime.node_id} <span style={{ color: 'var(--rc-text-3)' }}>generation {runtime.generation}</span></p><p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>{runtime.instance_id}</p></div><Status value={runtime.status} /></div><p className="mt-2 inline-flex items-center gap-1 text-xs" style={{ color: 'var(--rc-text-3)' }}><Clock3 className="h-3 w-3" /> {new Date(runtime.regenerated_at).toLocaleString()}</p></div>)}</div></div>
          </div>
        </div>
      )}
    </section>
  );
}
