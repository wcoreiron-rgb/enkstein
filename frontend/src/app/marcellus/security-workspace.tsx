'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  BrainCircuit,
  CheckCircle2,
  CircleDot,
  Database,
  ExternalLink,
  Gauge,
  HeartPulse,
  Network,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  Workflow,
} from 'lucide-react';
import {
  getMarcellusArchitecture,
  MarcellusArchitecture,
  MarcellusCapabilityNode,
  MarcellusImplementationState,
  MarcellusSecurityArm,
} from '@/lib/api';
import MarcellusRuntimeConsole from './runtime-console';
import MissionControl from './mission-control';

const ARM_COLORS: Record<string, string> = {
  threat_exposure: '#dc2626',
  identity_human_risk: '#2563eb',
  cloud_infrastructure: '#0891b2',
  network_endpoint: '#16a34a',
  application_delivery: '#7c3aed',
  data_privacy_saas: '#c026d3',
  governance_resilience: '#d97706',
  ai_autonomous_operations: '#4f46e5',
};

const STATE_LABELS: Record<MarcellusImplementationState, string> = {
  existing: 'Existing',
  partial: 'Partial',
  contract_only: 'Contract only',
};

function StateBadge({ state }: { state: MarcellusImplementationState }) {
  const color = state === 'existing' ? '#16a34a' : state === 'partial' ? '#d97706' : '#64748b';
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium" style={{ color }}>
      <CircleDot className="h-3 w-3" />
      {STATE_LABELS[state]}
    </span>
  );
}

function Metric({ label, value, icon: Icon }: { label: string; value: number; icon: React.ElementType }) {
  return (
    <div className="border-l-2 pl-4" style={{ borderColor: 'var(--rc-border-2)' }}>
      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--rc-text-3)' }}>
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <p className="mt-1 text-2xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>{value}</p>
    </div>
  );
}

function ArmPanel({
  arm,
  nodes,
  selectedId,
  onSelect,
}: {
  arm: MarcellusSecurityArm;
  nodes: MarcellusCapabilityNode[];
  selectedId: string | null;
  onSelect: (node: MarcellusCapabilityNode) => void;
}) {
  const color = ARM_COLORS[arm.id] || '#64748b';
  return (
    <article
      className="rounded-lg border p-4"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
            <h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{arm.name}</h2>
          </div>
          <p className="mt-1 text-xs leading-5" style={{ color: 'var(--rc-text-3)' }}>{arm.purpose}</p>
        </div>
        <span className="text-xs tabular-nums" style={{ color: 'var(--rc-text-3)' }}>{nodes.length}</span>
      </div>

      <div className="relative mt-5 min-h-[54px] px-1">
        <div
          className="absolute left-3 right-3 top-5 h-px"
          style={{ background: color, opacity: 0.45 }}
        />
        <div className="relative flex flex-wrap gap-3">
          {nodes.map((node) => {
            const selected = selectedId === node.id;
            return (
              <button
                key={node.id}
                type="button"
                title={node.name}
                aria-label={`Inspect ${node.name}`}
                aria-pressed={selected}
                onClick={() => onSelect(node)}
                className="flex h-10 w-10 items-center justify-center rounded-full border-2 transition-transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-offset-2"
                style={{
                  background: selected ? color : 'var(--rc-bg-elevated)',
                  borderColor: color,
                  color: selected ? '#ffffff' : color,
                  boxShadow: selected ? `0 0 0 3px ${color}22` : 'none',
                  '--tw-ring-color': color,
                  '--tw-ring-offset-color': 'var(--rc-bg-surface)',
                } as React.CSSProperties}
              >
                <CircleDot className="h-4 w-4" />
              </button>
            );
          })}
        </div>
      </div>
    </article>
  );
}

export default function SecurityWorkspace() {
  const [architecture, setArchitecture] = useState<MarcellusArchitecture | null>(null);
  const [selectedNode, setSelectedNode] = useState<MarcellusCapabilityNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getMarcellusArchitecture();
      setArchitecture(result);
      setSelectedNode((current) => current || result.capability_nodes[0] || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load architecture');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const nodesByArm = useMemo(() => {
    const grouped = new Map<string, MarcellusCapabilityNode[]>();
    architecture?.capability_nodes.forEach((node) => {
      grouped.set(node.arm_id, [...(grouped.get(node.arm_id) || []), node]);
    });
    return grouped;
  }, [architecture]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center" style={{ color: 'var(--rc-text-2)' }}>
        <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
        Loading Marcellus architecture
      </div>
    );
  }

  if (error || !architecture) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/20 p-4 text-sm text-red-300">
        <p>{error || 'Architecture data is unavailable.'}</p>
        <button type="button" onClick={load} className="mt-3 inline-flex items-center gap-2 text-sm font-medium">
          <RefreshCw className="h-4 w-4" /> Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <MissionControl />

      <div className="border-t pt-8" style={{ borderColor: 'var(--rc-border)' }}>
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <BrainCircuit className="h-7 w-7 text-cyan-400" />
            <h1 className="text-3xl font-bold" style={{ color: 'var(--rc-text-1)' }}>Marcellus Architecture</h1>
          </div>
          <p className="mt-2 max-w-3xl text-sm" style={{ color: 'var(--rc-text-2)' }}>{architecture.thesis}</p>
          <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Contract {architecture.version} | Compatibility-first working name
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          title="Refresh architecture"
          aria-label="Refresh architecture"
          className="flex h-9 w-9 items-center justify-center rounded-lg border transition-colors hover:bg-[var(--rc-bg-elevated)]"
          style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </header>

      <section className="grid grid-cols-2 gap-5 border-y py-5 md:grid-cols-4" style={{ borderColor: 'var(--rc-border)' }}>
        <Metric label="Cortex systems" value={architecture.cortex.length} icon={BrainCircuit} />
        <Metric label="Hearts" value={architecture.hearts.length} icon={HeartPulse} />
        <Metric label="Security Arms" value={architecture.arms.length} icon={Network} />
        <Metric label="Capability Nodes" value={architecture.capability_nodes.length} icon={CircleDot} />
      </section>

      <MarcellusRuntimeConsole nodes={architecture.capability_nodes} />

      <section>
        <div className="mb-4 flex items-center gap-2">
          <BrainCircuit className="h-5 w-5 text-cyan-400" />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>Cortex</h2>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {architecture.cortex.map((component) => (
            <article key={component.id} className="border-l-2 pl-4" style={{ borderColor: '#0891b2' }}>
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{component.name}</h3>
                <StateBadge state={component.implementation_state} />
              </div>
              <p className="mt-1 text-xs leading-5" style={{ color: 'var(--rc-text-3)' }}>{component.purpose}</p>
            </article>
          ))}
        </div>
      </section>

      <section>
        <div className="mb-4 flex items-center gap-2">
          <HeartPulse className="h-5 w-5 text-red-400" />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>Three Hearts</h2>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          {architecture.hearts.map((heart, index) => {
            const Icon = index === 0 ? ShieldCheck : index === 1 ? Database : Gauge;
            const color = index === 0 ? '#dc2626' : index === 1 ? '#7c3aed' : '#16a34a';
            return (
              <article
                key={heart.id}
                className="rounded-lg border p-4"
                style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Icon className="h-5 w-5" style={{ color }} />
                    <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{heart.name}</h3>
                  </div>
                  <StateBadge state={heart.implementation_state} />
                </div>
                <p className="mt-2 text-xs leading-5" style={{ color: 'var(--rc-text-2)' }}>{heart.purpose}</p>
                <p className="mt-3 text-xs" style={{ color: 'var(--rc-text-3)' }}>{heart.components.join(' | ')}</p>
              </article>
            );
          })}
        </div>
      </section>

      <section>
        <div className="mb-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Network className="h-5 w-5 text-green-400" />
            <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>Security Arms</h2>
          </div>
          <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Circular controls are Capability Nodes</span>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {architecture.arms.map((arm) => (
            <ArmPanel
              key={arm.id}
              arm={arm}
              nodes={nodesByArm.get(arm.id) || []}
              selectedId={selectedNode?.id || null}
              onSelect={setSelectedNode}
            />
          ))}
        </div>
      </section>

      {selectedNode && (
        <section className="rounded-lg border p-5" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <CircleDot className="h-5 w-5" style={{ color: ARM_COLORS[selectedNode.arm_id] }} />
                <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>{selectedNode.name}</h2>
              </div>
              <p className="mt-2 max-w-3xl text-sm" style={{ color: 'var(--rc-text-2)' }}>{selectedNode.purpose}</p>
            </div>
            <Link
              href={selectedNode.legacy_route.replace('/api/v1', '')}
              className="inline-flex items-center gap-2 text-sm font-medium text-cyan-400"
            >
              Open capability <ExternalLink className="h-4 w-4" />
            </Link>
          </div>
          <div className="mt-5 grid gap-4 md:grid-cols-3">
            <div>
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Compatibility module</p>
              <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-1)' }}>{selectedNode.legacy_module}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Authority ceiling</p>
              <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-1)' }}>{selectedNode.authority_ceiling.replaceAll('_', ' ')}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Focused execution</p>
              <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-1)' }}>{selectedNode.task_route}</p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2">
            {selectedNode.capabilities.map((capability) => (
              <span key={capability} className="inline-flex items-center gap-1.5 text-xs" style={{ color: 'var(--rc-text-2)' }}>
                <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                {capability.replaceAll('-', ' ')}
              </span>
            ))}
          </div>
        </section>
      )}

      <section>
        <div className="mb-4 flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-indigo-400" />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>Runtime Contracts</h2>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          {[
            { name: 'Reflexes', icon: Activity, contract: architecture.reflexes },
            { name: 'Plexus', icon: Workflow, contract: architecture.plexus },
            { name: 'Regeneration', icon: RotateCcw, contract: architecture.regeneration },
          ].map(({ name, icon: Icon, contract }) => (
            <article key={name} className="border-t pt-4" style={{ borderColor: 'var(--rc-border-2)' }}>
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Icon className="h-4 w-4 text-indigo-400" />
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{name}</h3>
                </div>
                <StateBadge state={contract.implementation_state} />
              </div>
              <p className="mt-2 text-xs leading-5" style={{ color: 'var(--rc-text-2)' }}>{contract.purpose}</p>
            </article>
          ))}
        </div>
      </section>
      </div>
    </div>
  );
}
