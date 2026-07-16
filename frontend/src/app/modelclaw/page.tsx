'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { BrainCircuit, CheckCircle2, Clock3, Cpu, Database, RefreshCw, ShieldCheck, Sparkles, Vote, XCircle } from 'lucide-react';
import {
  createOrUpdateModelClawProfile,
  getModelClawCalls,
  getModelClawProfiles,
  getModelClawProviders,
  getBrainStatuses,
  routeBrainConsensus,
  routeModelClawCall,
} from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

type Provider = {
  provider: string;
  enabled: boolean;
  default_model: string;
  supports_tool_calling: boolean;
};

type Profile = {
  name: string;
  provider: string;
  model: string;
  allowed_claws: string[];
  allowed_data_classes: string[];
  temperature: number;
  max_tokens: number;
  tool_calling: boolean;
  requires_redaction: boolean;
  fallback_profile?: string | null;
  created_at: string;
};

type ModelCall = {
  id: string;
  timestamp: string;
  claw: string;
  provider: string;
  model: string;
  model_profile?: string | null;
  data_classification: string;
  outcome: string;
  policy_name: string;
  reason: string;
  latency_ms: number;
  token_count: number;
};

type BrainStatus = {
  brain: string;
  kind: string;
  available: boolean;
  authenticated: boolean;
  runtime?: string | null;
  account_type?: string | null;
  detail?: string | null;
};

export default function ModelClawPage() {
  const [loading, setLoading] = useState(true);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [calls, setCalls] = useState<ModelCall[]>([]);
  const [brains, setBrains] = useState<BrainStatus[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [routeForm, setRouteForm] = useState({
    claw: 'threatclaw',
    prompt: 'Summarize high-risk findings and top remediation actions.',
    data_classification: 'internal',
    model_profile: 'nim_fast_reasoning',
    swarm_job_id: '',
  });
  const [routeResult, setRouteResult] = useState<any>(null);
  const [routing, setRouting] = useState(false);
  const [consensusPrompt, setConsensusPrompt] = useState('Assess the highest-priority security risk and recommend the next governed action.');
  const [consensusSources, setConsensusSources] = useState<string[]>([
    'codex_subscription',
    'claude_subscription',
    'profile:nim_fast_reasoning',
    'profile:ollama_local_fallback',
  ]);
  const [consensusResult, setConsensusResult] = useState<any>(null);
  const [consensusRunning, setConsensusRunning] = useState(false);

  const [profileForm, setProfileForm] = useState({
    name: '',
    provider: 'ollama',
    model: '',
    allowed_claws: 'arcclaw,threatclaw',
    allowed_data_classes: 'public,internal',
  });
  const [savingProfile, setSavingProfile] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [pvd, pfl, cls, brn] = await Promise.all([
        getModelClawProviders(),
        getModelClawProfiles(),
        getModelClawCalls(30),
        getBrainStatuses(),
      ]);
      setProviders(pvd || []);
      setProfiles(pfl || []);
      setCalls(cls || []);
      setBrains(brn || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load Model Cortex data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const profileOptions = useMemo(() => profiles.map(p => p.name), [profiles]);

  const onRoute = async () => {
    setRouting(true);
    setRouteResult(null);
    try {
      const res = await routeModelClawCall({
        claw: routeForm.claw,
        prompt: routeForm.prompt,
        data_classification: routeForm.data_classification,
        model_profile: routeForm.model_profile || null,
        swarm_job_id: routeForm.swarm_job_id || null,
      });
      setRouteResult(res);
      await load();
    } catch (e: any) {
      setRouteResult({ error: e?.message || 'Routing failed' });
    } finally {
      setRouting(false);
    }
  };

  const onSaveProfile = async () => {
    if (!profileForm.name.trim() || !profileForm.model.trim()) return;
    setSavingProfile(true);
    try {
      await createOrUpdateModelClawProfile({
        name: profileForm.name.trim(),
        provider: profileForm.provider,
        model: profileForm.model.trim(),
        allowed_claws: profileForm.allowed_claws.split(',').map(s => s.trim()).filter(Boolean),
        allowed_data_classes: profileForm.allowed_data_classes.split(',').map(s => s.trim()).filter(Boolean),
        temperature: 0.2,
        max_tokens: 4000,
        tool_calling: true,
        requires_redaction: true,
        fallback_profile: null,
      });
      setProfileForm({ ...profileForm, name: '', model: '' });
      await load();
    } finally {
      setSavingProfile(false);
    }
  };

  const onConsensus = async () => {
    if (!consensusPrompt.trim() || consensusSources.length === 0) return;
    setConsensusRunning(true);
    setConsensusResult(null);
    try {
      setConsensusResult(await routeBrainConsensus({
        prompt: consensusPrompt.trim(),
        sources: consensusSources,
        claw: 'executive',
        data_classification: 'internal',
        minimum_votes: Math.min(2, consensusSources.length),
      }));
      await load();
    } catch (e: any) {
      setConsensusResult({ error: e?.message || 'Consensus routing failed' });
    } finally {
      setConsensusRunning(false);
    }
  };

  const toggleConsensusSource = (source: string) => {
    setConsensusSources(current => current.includes(source)
      ? current.filter(item => item !== source)
      : [...current, source]);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Sparkles className="text-cyan-400" /> Model Cortex
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Governed model routing profiles for Capability Nodes and swarm judge synthesis.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-900/20 px-4 py-3 text-sm text-red-300">{error}</div>
      )}

      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <BrainCircuit className="h-5 w-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">Native Subscription Brains</h2>
          <span className="text-xs text-gray-500">Vendor sessions remain on this device</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {brains.map(brain => {
            const ready = brain.available && brain.authenticated;
            return (
              <div key={brain.brain} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">
                      {brain.brain === 'codex_subscription' ? 'Codex Subscription' : 'Claude Agent SDK'}
                    </p>
                    <p className="mt-1 text-xs text-gray-500">{brain.runtime || 'Host runtime not detected'}</p>
                  </div>
                  <span className={`inline-flex items-center gap-1 rounded px-2 py-1 text-xs ${ready ? 'bg-emerald-950 text-emerald-300' : 'bg-gray-800 text-gray-400'}`}>
                    {ready ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                    {ready ? 'Ready' : 'Unavailable'}
                  </span>
                </div>
                <p className="mt-3 text-xs text-gray-400">{brain.detail}</p>
                {brain.account_type && <p className="mt-1 text-xs text-cyan-400">{brain.account_type}</p>}
              </div>
            );
          })}
        </div>
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        <div className="flex items-center gap-2">
          <Vote className="h-5 w-5 text-indigo-400" />
          <div>
            <h2 className="text-base font-semibold text-white">Brain Consensus</h2>
            <p className="text-xs text-gray-500">Compare independent subscription, API, and local answers under one Trust Fabric decision path.</p>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
          <div>
            <textarea
              className="min-h-28 w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-white"
              value={consensusPrompt}
              onChange={(event) => setConsensusPrompt(event.target.value)}
            />
            <button
              onClick={onConsensus}
              disabled={consensusRunning || consensusSources.length === 0}
              className="mt-3 inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm text-white hover:bg-indigo-500 disabled:opacity-50"
            >
              <Vote className="h-4 w-4" />
              {consensusRunning ? 'Consulting Brains...' : 'Run Consensus'}
            </button>
          </div>
          <div className="space-y-2">
            {[
              ['codex_subscription', 'Codex Subscription'],
              ['claude_subscription', 'Claude Agent SDK'],
              ['profile:nim_fast_reasoning', 'NVIDIA NIM API'],
              ['profile:ollama_local_fallback', 'Local Ollama'],
            ].map(([source, label]) => (
              <label key={source} className="flex cursor-pointer items-center gap-2 rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={consensusSources.includes(source)}
                  onChange={() => toggleConsensusSource(source)}
                  className="accent-cyan-500"
                />
                {label}
              </label>
            ))}
          </div>
        </div>
        {consensusResult && (
          <div className="mt-4 space-y-3">
            {consensusResult.error ? (
              <p className="rounded-lg border border-red-900 bg-red-950/30 p-3 text-sm text-red-300">{consensusResult.error}</p>
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="rounded bg-gray-800 px-2 py-1 text-gray-300">{consensusResult.counted_votes}/{consensusResult.requested_votes} votes</span>
                  <span className="rounded bg-cyan-950 px-2 py-1 text-cyan-300">{consensusResult.agreement} agreement</span>
                  <span className="rounded bg-indigo-950 px-2 py-1 text-indigo-300">{Math.round((consensusResult.confidence || 0) * 100)}% confidence</span>
                </div>
                <div className="rounded-lg border border-gray-800 bg-gray-950 p-4 text-sm whitespace-pre-wrap text-gray-200">{consensusResult.consensus || 'Not enough available Brains to form consensus.'}</div>
                <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                  {(consensusResult.votes || []).map((vote: any) => (
                    <div key={vote.source} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-xs font-semibold text-white">{vote.source}</p>
                        <span className={`text-[11px] ${vote.counted ? 'text-emerald-400' : 'text-gray-500'}`}>{vote.counted ? 'counted' : 'not counted'}</span>
                      </div>
                      <p className="mt-1 text-xs text-gray-500">{vote.provider || vote.kind}{vote.model ? ` · ${vote.model}` : ''}</p>
                      {vote.reason && <p className="mt-2 text-xs text-amber-300">{vote.reason}</p>}
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-xs uppercase tracking-wide text-gray-500 mb-3">Providers</p>
          <div className="space-y-2">
            {providers.map(p => (
              <div key={p.provider} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-white font-medium">{p.provider}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${p.enabled ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-400'}`}>
                    {p.enabled ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{p.default_model}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 lg:col-span-2">
          <p className="text-xs uppercase tracking-wide text-gray-500 mb-3">Route Test</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" value={routeForm.claw} onChange={(e) => setRouteForm({ ...routeForm, claw: e.target.value })} placeholder="Capability ID" />
            <select className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" value={routeForm.model_profile} onChange={(e) => setRouteForm({ ...routeForm, model_profile: e.target.value })}>
              {profileOptions.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
            <select className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" value={routeForm.data_classification} onChange={(e) => setRouteForm({ ...routeForm, data_classification: e.target.value })}>
              <option value="public">public</option>
              <option value="internal">internal</option>
              <option value="confidential">confidential</option>
              <option value="restricted">restricted</option>
              <option value="top_secret">top_secret</option>
            </select>
            <input className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" value={routeForm.swarm_job_id} onChange={(e) => setRouteForm({ ...routeForm, swarm_job_id: e.target.value })} placeholder="swarm job id (optional)" />
            <textarea className="md:col-span-2 px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white min-h-24" value={routeForm.prompt} onChange={(e) => setRouteForm({ ...routeForm, prompt: e.target.value })} />
          </div>
          <div className="mt-3 flex items-center gap-2">
            <button onClick={onRoute} disabled={routing} className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm hover:bg-cyan-500 disabled:opacity-60">
              {routing ? 'Routing...' : 'Route Call'}
            </button>
            <ShieldCheck className="w-4 h-4 text-green-400" />
            <span className="text-xs text-gray-400">Trust Fabric enforced before model response.</span>
          </div>
          {routeResult && (
            <pre className="mt-3 p-3 text-xs bg-gray-950 border border-gray-800 rounded-lg text-gray-300 overflow-x-auto">{JSON.stringify(routeResult, null, 2)}</pre>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-xs uppercase tracking-wide text-gray-500 mb-3">Create Profile</p>
          <div className="space-y-2">
            <input className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" placeholder="profile name" value={profileForm.name} onChange={(e) => setProfileForm({ ...profileForm, name: e.target.value })} />
            <input className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" placeholder="model id" value={profileForm.model} onChange={(e) => setProfileForm({ ...profileForm, model: e.target.value })} />
            <select className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" value={profileForm.provider} onChange={(e) => setProfileForm({ ...profileForm, provider: e.target.value })}>
              {providers.map(p => <option key={p.provider} value={p.provider}>{p.provider}</option>)}
            </select>
            <input className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" placeholder="allowed capabilities csv" value={profileForm.allowed_claws} onChange={(e) => setProfileForm({ ...profileForm, allowed_claws: e.target.value })} />
            <input className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" placeholder="allowed data classes csv" value={profileForm.allowed_data_classes} onChange={(e) => setProfileForm({ ...profileForm, allowed_data_classes: e.target.value })} />
            <button onClick={onSaveProfile} disabled={savingProfile} className="w-full px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm hover:bg-indigo-500 disabled:opacity-60">
              {savingProfile ? 'Saving...' : 'Save Profile'}
            </button>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-xs uppercase tracking-wide text-gray-500 mb-3">Recent Model Calls</p>
          <div className="space-y-2 max-h-80 overflow-auto pr-1">
            {calls.length === 0 && <p className="text-sm text-gray-500">No model calls yet.</p>}
            {calls.map(call => (
              <div key={call.id} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm text-white font-medium">{capabilityName(call.claw)}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${call.outcome === 'allowed' ? 'bg-green-900/30 text-green-400' : 'bg-yellow-900/30 text-yellow-400'}`}>{call.outcome}</span>
                </div>
                <p className="text-xs text-gray-400 mt-1">{call.provider} · {call.model}</p>
                <div className="mt-2 flex items-center gap-3 text-[11px] text-gray-500">
                  <span className="inline-flex items-center gap-1"><Clock3 className="w-3 h-3" />{call.latency_ms}ms</span>
                  <span className="inline-flex items-center gap-1"><Database className="w-3 h-3" />{call.token_count} tokens</span>
                  <span className="inline-flex items-center gap-1"><Cpu className="w-3 h-3" />{call.model_profile || 'default'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
