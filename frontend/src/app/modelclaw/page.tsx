'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Cpu, RefreshCw, ShieldCheck, Sparkles, Clock3, Database } from 'lucide-react';
import {
  createOrUpdateModelClawProfile,
  getModelClawCalls,
  getModelClawProfiles,
  getModelClawProviders,
  routeModelClawCall,
} from '@/lib/api';

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

export default function ModelClawPage() {
  const [loading, setLoading] = useState(true);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [calls, setCalls] = useState<ModelCall[]>([]);
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
      const [pvd, pfl, cls] = await Promise.all([
        getModelClawProviders(),
        getModelClawProfiles(),
        getModelClawCalls(30),
      ]);
      setProviders(pvd || []);
      setProfiles(pfl || []);
      setCalls(cls || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load ModelClaw data');
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
            <Sparkles className="text-cyan-400" /> ModelClaw
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Governed model routing profiles for claws and swarm judge synthesis.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-900/20 px-4 py-3 text-sm text-red-300">{error}</div>
      )}

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
            <input className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" value={routeForm.claw} onChange={(e) => setRouteForm({ ...routeForm, claw: e.target.value })} placeholder="claw" />
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
            <input className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-sm text-white" placeholder="allowed claws csv" value={profileForm.allowed_claws} onChange={(e) => setProfileForm({ ...profileForm, allowed_claws: e.target.value })} />
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
                  <span className="text-sm text-white font-medium">{call.claw}</span>
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

