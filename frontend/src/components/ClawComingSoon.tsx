'use client';
import { Construction, Shield, Zap } from 'lucide-react';

export interface ClawMeta {
  name: string;
  tag: string;
  category: string;
  icon: string;
  description: string;
  capabilities: string[];
  connectors: string[];
  policies: number;
  color: string; // tailwind color name like 'violet', 'blue', etc.
}

export default function ClawComingSoon({ meta }: { meta: ClawMeta }) {
  const colorMap: Record<string, { bg: string; border: string; text: string; badge: string }> = {
    violet:  { bg: 'rgba(139,92,246,0.08)',  border: '#7c3aed', text: '#a78bfa', badge: 'rgba(139,92,246,0.15)' },
    blue:    { bg: 'rgba(59,130,246,0.08)',   border: '#2563eb', text: '#60a5fa', badge: 'rgba(59,130,246,0.15)' },
    cyan:    { bg: 'rgba(6,182,212,0.08)',    border: '#0891b2', text: '#22d3ee', badge: 'rgba(6,182,212,0.15)' },
    green:   { bg: 'rgba(34,197,94,0.08)',    border: '#16a34a', text: '#4ade80', badge: 'rgba(34,197,94,0.15)' },
    yellow:  { bg: 'rgba(234,179,8,0.08)',    border: '#ca8a04', text: '#facc15', badge: 'rgba(234,179,8,0.15)' },
    orange:  { bg: 'rgba(249,115,22,0.08)',   border: '#ea580c', text: '#fb923c', badge: 'rgba(249,115,22,0.15)' },
    red:     { bg: 'rgba(239,68,68,0.08)',    border: '#dc2626', text: '#f87171', badge: 'rgba(239,68,68,0.15)' },
    pink:    { bg: 'rgba(236,72,153,0.08)',   border: '#db2777', text: '#f472b6', badge: 'rgba(236,72,153,0.15)' },
    indigo:  { bg: 'rgba(99,102,241,0.08)',   border: '#4f46e5', text: '#818cf8', badge: 'rgba(99,102,241,0.15)' },
    teal:    { bg: 'rgba(20,184,166,0.08)',   border: '#0d9488', text: '#2dd4bf', badge: 'rgba(20,184,166,0.15)' },
    emerald: { bg: 'rgba(16,185,129,0.08)',   border: '#059669', text: '#34d399', badge: 'rgba(16,185,129,0.15)' },
    sky:     { bg: 'rgba(14,165,233,0.08)',   border: '#0284c7', text: '#38bdf8', badge: 'rgba(14,165,233,0.15)' },
  };

  const c = colorMap[meta.color] ?? colorMap.violet;

  return (
    <div className="space-y-8">

      {/* Header */}
      <div className="flex items-start gap-5">
        <div
          className="w-16 h-16 rounded-2xl flex items-center justify-center text-3xl flex-shrink-0 border"
          style={{ background: c.bg, borderColor: c.border }}
        >
          {meta.icon}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-3xl font-bold" style={{ color: 'var(--rc-text-1)' }}>{meta.name}</h1>
            <span className="px-2.5 py-1 rounded-lg text-xs font-semibold border"
              style={{ background: c.badge, borderColor: c.border, color: c.text }}>
              {meta.tag}
            </span>
            <span className="px-2.5 py-1 rounded-lg text-xs font-medium border"
              style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}>
              {meta.category}
            </span>
          </div>
          <p className="mt-2 text-sm leading-relaxed max-w-2xl" style={{ color: 'var(--rc-text-2)' }}>
            {meta.description}
          </p>
        </div>
      </div>

      {/* Status banner */}
      <div
        className="rounded-xl border p-5 flex items-start gap-4"
        style={{ background: 'rgba(234,179,8,0.06)', borderColor: '#a16207' }}
      >
        <Construction className="w-6 h-6 flex-shrink-0 mt-0.5" style={{ color: '#facc15' }} />
        <div>
          <p className="font-semibold text-sm" style={{ color: '#facc15' }}>Coming Soon — In Development</p>
          <p className="text-sm mt-1" style={{ color: 'var(--rc-text-2)' }}>
            This Capability Node is scoped and policies are loaded. The full detection engine, data fetchers,
            and dashboards are being built. Policies are already enforced through the Trust Fabric
            even before the dedicated UI is ready.
          </p>
        </div>
      </div>

      {/* Capabilities + Connectors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

        <div className="rounded-xl border p-5" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-4 h-4" style={{ color: c.text }} />
            <h3 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>Planned Capabilities</h3>
          </div>
          <ul className="space-y-2">
            {meta.capabilities.map(cap => (
              <li key={cap} className="flex items-start gap-2 text-sm" style={{ color: 'var(--rc-text-2)' }}>
                <span style={{ color: c.text }} className="mt-0.5 flex-shrink-0">›</span>
                {cap}
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-xl border p-5" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4" style={{ color: c.text }} />
            <h3 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>Data Sources & Connectors</h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {meta.connectors.map(conn => (
              <span key={conn} className="px-2.5 py-1 rounded-lg text-xs border font-medium"
                style={{ background: c.badge, borderColor: c.border, color: c.text }}>
                {conn}
              </span>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--rc-border)' }}>
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
              <span className="font-semibold" style={{ color: c.text }}>{meta.policies} active policies</span>
              {' '}enforced via Trust Fabric · Priority-ordered with platform-wide rules
            </p>
          </div>
        </div>
      </div>

      {/* Roadmap hint */}
      <div className="rounded-xl border p-5" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <h3 className="font-semibold text-sm mb-3" style={{ color: 'var(--rc-text-1)' }}>Build Roadmap</h3>
        <div className="grid grid-cols-3 gap-4">
          {[
            { step: '1', label: 'Policies', desc: 'Active via Trust Fabric', done: true },
            { step: '2', label: 'Data Fetchers', desc: 'Connector integrations', done: false },
            { step: '3', label: 'Dashboard', desc: 'Detections & analytics', done: false },
          ].map(({ step, label, desc, done }) => (
            <div key={step} className="flex items-start gap-3">
              <div
                className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
                style={{
                  background: done ? c.badge : 'var(--rc-bg-elevated)',
                  color: done ? c.text : 'var(--rc-text-3)',
                  border: `1px solid ${done ? c.border : 'var(--rc-border)'}`,
                }}
              >
                {done ? '✓' : step}
              </div>
              <div>
                <p className="text-xs font-semibold" style={{ color: done ? c.text : 'var(--rc-text-2)' }}>{label}</p>
                <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
