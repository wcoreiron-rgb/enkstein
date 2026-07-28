'use client';
import { useEffect, useState } from 'react';
import { Plus, Plug, Trash2, Play, ChevronDown, ChevronRight, Edit2, Save, X, Globe, Zap } from 'lucide-react';
import { apiFetch } from '@/lib/api';

// ── Types ──────────────────────────────────────────────────────────────────────

interface EndpointDef {
  name: string;
  path: string;
  method: string;
  params?: Record<string, string>;
  body_template?: Record<string, any> | null;
  extract_field?: string;
  result_label?: string;
}

interface ClawDefinition {
  id?: string;
  name: string;
  description?: string;
  base_url: string;
  auth_type: string;
  auth_value?: string;
  auth_header?: string;
  icon?: string;
  tags?: string[];
  endpoints: EndpointDef[];
  created_at?: string;
}

const EMPTY_DEFINITION: ClawDefinition = {
  name: '',
  description: '',
  base_url: '',
  auth_type: 'none',
  auth_value: '',
  auth_header: 'Authorization',
  icon: '🔌',
  tags: [],
  endpoints: [],
};

const EMPTY_ENDPOINT: EndpointDef = {
  name: '',
  path: '/',
  method: 'GET',
  params: {},
  body_template: null,
  extract_field: '',
  result_label: '',
};

const METHOD_COLORS: Record<string, string> = {
  GET:    'bg-green-500/10 text-green-400 border-green-500/30',
  POST:   'bg-blue-500/10 text-blue-400 border-blue-500/30',
  PUT:    'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  PATCH:  'bg-purple-500/10 text-purple-400 border-purple-500/30',
  DELETE: 'bg-red-500/10 text-red-400 border-red-500/30',
};

// ── Main Component ─────────────────────────────────────────────────────────────

export default function CustomClawPage() {
  const [definitions, setDefinitions] = useState<ClawDefinition[]>([]);
  const [loading, setLoading]         = useState(true);
  const [showForm, setShowForm]       = useState(false);
  const [editId, setEditId]           = useState<string | null>(null);
  const [form, setForm]               = useState<ClawDefinition>(EMPTY_DEFINITION);
  const [saving, setSaving]           = useState(false);
  const [expanded, setExpanded]       = useState<string | null>(null);
  const [testResult, setTestResult]   = useState<any>(null);
  const [testing, setTesting]         = useState<string | null>(null);  // def_id being tested
  const [scanResult, setScanResult]   = useState<any>(null);
  const [scanning, setScanning]       = useState<string | null>(null);
  const [msg, setMsg]                 = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [activeEpIdx, setActiveEpIdx] = useState(0);

  const load = async () => {
    setLoading(true);
    try {
      const data = await apiFetch<ClawDefinition[]>('/customclaw/definitions');
      setDefinitions(data);
    } catch (e) { /* empty state is fine */ }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  // ── Form helpers ────────────────────────────────────────────────────────────

  const openCreate = () => {
    setForm(EMPTY_DEFINITION);
    setEditId(null);
    setShowForm(true);
    setActiveEpIdx(0);
  };

  const openEdit = (d: ClawDefinition) => {
    setForm({ ...d });
    setEditId(d.id ?? null);
    setShowForm(true);
    setActiveEpIdx(0);
  };

  const closeForm = () => {
    setShowForm(false);
    setEditId(null);
    setForm(EMPTY_DEFINITION);
    setTestResult(null);
    setScanResult(null);
  };

  const setField = (key: keyof ClawDefinition, value: any) =>
    setForm(f => ({ ...f, [key]: value }));

  const addEndpoint = () =>
    setForm(f => ({ ...f, endpoints: [...f.endpoints, { ...EMPTY_ENDPOINT }] }));

  const removeEndpoint = (i: number) =>
    setForm(f => ({ ...f, endpoints: f.endpoints.filter((_, idx) => idx !== i) }));

  const setEpField = (i: number, key: keyof EndpointDef, value: any) =>
    setForm(f => {
      const eps = [...f.endpoints];
      eps[i] = { ...eps[i], [key]: value };
      return { ...f, endpoints: eps };
    });

  const flash = (type: 'success' | 'error', text: string) => {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 6000);
  };

  // ── Save ────────────────────────────────────────────────────────────────────

  const handleSave = async () => {
    if (!form.name.trim() || !form.base_url.trim()) {
      flash('error', 'Name and Base URL are required.');
      return;
    }
    setSaving(true);
    try {
      if (editId) {
        await apiFetch<any>(`/customclaw/definitions/${editId}`, { method: 'PUT', body: JSON.stringify(form) });
        flash('success', `"${form.name}" updated.`);
      } else {
        await apiFetch<any>('/customclaw/definitions', { method: 'POST', body: JSON.stringify(form) });
        flash('success', `"${form.name}" created.`);
      }
      closeForm();
      await load();
    } catch (e: any) {
      flash('error', `Save failed: ${e?.message ?? 'Unknown error'}`);
    } finally {
      setSaving(false);
    }
  };

  // ── Delete ──────────────────────────────────────────────────────────────────

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
    try {
      await apiFetch(`/customclaw/definitions/${id}`, { method: 'DELETE' });
      flash('success', `"${name}" deleted.`);
      await load();
    } catch (e: any) {
      flash('error', `Delete failed: ${e?.message ?? 'Unknown error'}`);
    }
  };

  // ── Test / Scan ─────────────────────────────────────────────────────────────

  const handleTest = async (id: string, epIdx: number) => {
    setTesting(id);
    setTestResult(null);
    try {
      const r = await apiFetch<any>(`/customclaw/definitions/${id}/test?ep_index=${epIdx}`);
      setTestResult(r);
    } catch (e: any) {
      setTestResult({ error: e?.message ?? 'Request failed' });
    } finally {
      setTesting(null);
    }
  };

  const handleScan = async (id: string, name: string) => {
    setScanning(id);
    setScanResult(null);
    try {
      const r = await apiFetch<any>(`/customclaw/definitions/${id}/scan`, { method: 'POST' });
      setScanResult({ defId: id, data: r });
      flash('success', `"${name}" scanned — ${r.endpoints_success}/${r.endpoints_total} endpoints succeeded.`);
    } catch (e: any) {
      flash('error', `Scan failed: ${e?.message ?? 'Unknown error'}`);
    } finally {
      setScanning(null);
    }
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen p-6 space-y-6" style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-1)' }}>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center text-xl"
               style={{ background: 'var(--rc-accent-violet)20' }}>
            🔌
          </div>
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--rc-text-1)' }}>Capability Builder</h1>
            <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
              Connect any REST API as a governed workflow step
            </p>
          </div>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all"
          style={{ background: 'var(--rc-accent-violet)', color: '#fff' }}
        >
          <Plus size={16} /> New Capability
        </button>
      </div>

      {/* Flash message */}
      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          msg.type === 'success'
            ? 'bg-green-500/10 border-green-500/30 text-green-400'
            : 'bg-red-500/10 border-red-500/30 text-red-400'
        }`}>
          {msg.text}
        </div>
      )}

      {/* Empty state */}
      {!loading && definitions.length === 0 && !showForm && (
        <div className="flex flex-col items-center justify-center py-24 gap-4"
             style={{ border: '2px dashed var(--rc-border)', borderRadius: '1rem' }}>
          <Globe size={48} style={{ color: 'var(--rc-text-3)' }} />
          <p className="text-lg font-semibold" style={{ color: 'var(--rc-text-2)' }}>No custom capabilities yet</p>
          <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
            Define a REST API integration and use it in any workflow
          </p>
          <button
            onClick={openCreate}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium"
            style={{ background: 'var(--rc-accent-violet)', color: '#fff' }}
          >
            <Plus size={16} /> Create Your First Capability
          </button>
        </div>
      )}

      {/* Definition list */}
      {definitions.length > 0 && !showForm && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {definitions.map(d => (
            <div
              key={d.id}
              className="rounded-xl p-5 border transition-all"
              style={{ background: 'var(--rc-bg-surface)', border: '1px solid var(--rc-border)' }}
            >
              {/* Card header */}
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{d.icon || '🔌'}</span>
                  <div>
                    <div className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>{d.name}</div>
                    <div className="text-xs truncate max-w-xs" style={{ color: 'var(--rc-text-3)' }}>
                      {d.base_url}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-0.5 rounded-full border"
                        style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-3)' }}>
                    {d.endpoints.length} endpoint{d.endpoints.length !== 1 ? 's' : ''}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded-full border"
                        style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-3)' }}>
                    {d.auth_type}
                  </span>
                </div>
              </div>

              {d.description && (
                <p className="text-sm mb-3" style={{ color: 'var(--rc-text-2)' }}>{d.description}</p>
              )}

              {/* Tags */}
              {d.tags && d.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-3">
                  {d.tags.map(t => (
                    <span key={t} className="text-xs px-2 py-0.5 rounded-full"
                          style={{ background: 'var(--rc-accent-violet)20', color: 'var(--rc-accent-violet)' }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}

              {/* Endpoints summary */}
              <div className="mb-4 space-y-1">
                {d.endpoints.slice(0, 3).map((ep, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className={`px-1.5 py-0.5 rounded border font-mono font-bold ${METHOD_COLORS[ep.method] || METHOD_COLORS.GET}`}>
                      {ep.method}
                    </span>
                    <span style={{ color: 'var(--rc-text-2)' }}>{ep.name}</span>
                    <span className="font-mono truncate" style={{ color: 'var(--rc-text-3)' }}>{ep.path}</span>
                  </div>
                ))}
                {d.endpoints.length > 3 && (
                  <div className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
                    +{d.endpoints.length - 3} more
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleScan(d.id!, d.name)}
                  disabled={scanning === d.id || d.endpoints.length === 0}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all disabled:opacity-50"
                  style={{ background: 'var(--rc-accent-violet)', color: '#fff' }}
                >
                  {scanning === d.id
                    ? <><span className="animate-spin inline-block w-3 h-3 border border-white/40 border-t-white rounded-full" /> Running…</>
                    : <><Zap size={12} /> Run All</>
                  }
                </button>
                <button
                  onClick={() => openEdit(d)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all"
                  style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)', border: '1px solid var(--rc-border)' }}
                >
                  <Edit2 size={12} /> Edit
                </button>
                <button
                  onClick={() => handleDelete(d.id!, d.name)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all text-red-400"
                  style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)' }}
                >
                  <Trash2 size={12} />
                </button>
              </div>

              {/* Scan result */}
              {scanResult?.defId === d.id && (
                <div className="mt-3 rounded-lg p-3 text-xs"
                     style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)' }}>
                  <div className="font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>
                    Scan Results — {scanResult.data.endpoints_success}/{scanResult.data.endpoints_total} success
                    <span className="ml-2 font-normal" style={{ color: 'var(--rc-text-3)' }}>
                      ({scanResult.data.duration_sec}s)
                    </span>
                  </div>
                  {scanResult.data.results.map((r: any, i: number) => (
                    <div key={i} className={`flex items-start gap-2 mb-1 ${r.success ? 'text-green-400' : 'text-red-400'}`}>
                      <span>{r.success ? '✓' : '✗'}</span>
                      <span className="font-medium">{r.endpoint}</span>
                      <span className="font-mono" style={{ color: 'var(--rc-text-3)' }}>
                        {r.url} ({r.status_code})
                      </span>
                      {r.error && <span className="text-red-400">{r.error}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ── Builder Form ──────────────────────────────────────────────────────── */}
      {showForm && (
        <div className="rounded-xl border" style={{ background: 'var(--rc-bg-surface)', border: '1px solid var(--rc-border)' }}>

          {/* Form header */}
          <div className="flex items-center justify-between p-5 border-b" style={{ borderColor: 'var(--rc-border)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              {editId ? 'Edit Capability' : 'New Custom Capability'}
            </h2>
            <button onClick={closeForm} style={{ color: 'var(--rc-text-3)' }}>
              <X size={20} />
            </button>
          </div>

          <div className="p-5 space-y-6">

            {/* Basic info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                  Capability Name *
                </label>
                <input
                  className="w-full px-3 py-2 rounded-lg text-sm border"
                  style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                  placeholder="e.g. GitHub Issues Tracker"
                  value={form.name}
                  onChange={e => setField('name', e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                  Base URL *
                </label>
                <input
                  className="w-full px-3 py-2 rounded-lg text-sm border font-mono"
                  style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                  placeholder="https://api.github.com"
                  value={form.base_url}
                  onChange={e => setField('base_url', e.target.value)}
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                  Description
                </label>
                <input
                  className="w-full px-3 py-2 rounded-lg text-sm border"
                  style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                  placeholder="What this capability does"
                  value={form.description}
                  onChange={e => setField('description', e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                  Icon (emoji)
                </label>
                <input
                  className="w-full px-3 py-2 rounded-lg text-sm border"
                  style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                  placeholder="🔌"
                  value={form.icon}
                  onChange={e => setField('icon', e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                  Tags (comma-separated)
                </label>
                <input
                  className="w-full px-3 py-2 rounded-lg text-sm border"
                  style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                  placeholder="crm, ticketing, devops"
                  value={(form.tags || []).join(', ')}
                  onChange={e => setField('tags', e.target.value.split(',').map(t => t.trim()).filter(Boolean))}
                />
              </div>
            </div>

            {/* Auth config */}
            <div>
              <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--rc-text-1)' }}>Authentication</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>Auth Type</label>
                  <select
                    className="w-full px-3 py-2 rounded-lg text-sm border"
                    style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                    value={form.auth_type}
                    onChange={e => setField('auth_type', e.target.value)}
                  >
                    <option value="none">None</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="basic">Basic Auth (user:pass)</option>
                    <option value="api_key">API Key (custom header)</option>
                  </select>
                </div>
                {form.auth_type !== 'none' && (
                  <div>
                    <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                      {form.auth_type === 'bearer' ? 'Token'
                       : form.auth_type === 'basic' ? 'Credentials (user:pass)'
                       : 'API Key Value'}
                    </label>
                    <input
                      type="password"
                      className="w-full px-3 py-2 rounded-lg text-sm border font-mono"
                      style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                      placeholder={form.auth_type === 'bearer' ? 'ghp_...' : form.auth_type === 'basic' ? 'user:password' : 'sk-...'}
                      value={form.auth_value}
                      onChange={e => setField('auth_value', e.target.value)}
                    />
                  </div>
                )}
                {form.auth_type === 'api_key' && (
                  <div>
                    <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>Header Name</label>
                    <input
                      className="w-full px-3 py-2 rounded-lg text-sm border font-mono"
                      style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                      placeholder="X-API-Key"
                      value={form.auth_header}
                      onChange={e => setField('auth_header', e.target.value)}
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Endpoints */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                  Endpoints ({form.endpoints.length})
                </h3>
                <button
                  onClick={addEndpoint}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium"
                  style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-2)' }}
                >
                  <Plus size={12} /> Add Endpoint
                </button>
              </div>

              {form.endpoints.length === 0 && (
                <div className="text-sm text-center py-8 rounded-lg"
                     style={{ border: '1px dashed var(--rc-border)', color: 'var(--rc-text-3)' }}>
                  No endpoints yet — add one above
                </div>
              )}

              {/* Endpoint tabs */}
              {form.endpoints.length > 0 && (
                <div>
                  <div className="flex flex-wrap gap-1 mb-3">
                    {form.endpoints.map((ep, i) => (
                      <button
                        key={i}
                        onClick={() => setActiveEpIdx(i)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${activeEpIdx === i ? 'ring-2' : ''}`}
                        style={{
                          background: activeEpIdx === i ? 'var(--rc-accent-violet)20' : 'var(--rc-bg-elevated)',
                          color: activeEpIdx === i ? 'var(--rc-accent-violet)' : 'var(--rc-text-2)',
                          border: `1px solid ${activeEpIdx === i ? 'var(--rc-accent-violet)' : 'var(--rc-border)'}`,
                        }}
                      >
                        <span className={`font-bold mr-1 ${METHOD_COLORS[ep.method]?.split(' ')[1] || 'text-green-400'}`}>
                          {ep.method}
                        </span>
                        {ep.name || `Endpoint ${i + 1}`}
                      </button>
                    ))}
                  </div>

                  {/* Active endpoint editor */}
                  {form.endpoints[activeEpIdx] && (() => {
                    const ep = form.endpoints[activeEpIdx];
                    const i  = activeEpIdx;
                    return (
                      <div className="rounded-xl p-4 space-y-4"
                           style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)' }}>
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold" style={{ color: 'var(--rc-text-2)' }}>
                            Endpoint {i + 1}
                          </span>
                          <button
                            onClick={() => {
                              removeEndpoint(i);
                              setActiveEpIdx(Math.max(0, i - 1));
                            }}
                            className="text-red-400 hover:text-red-300 text-xs flex items-center gap-1"
                          >
                            <Trash2 size={12} /> Remove
                          </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                          <div>
                            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>Display Name</label>
                            <input
                              className="w-full px-3 py-2 rounded-lg text-sm border"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                              placeholder="List Issues"
                              value={ep.name}
                              onChange={e => setEpField(i, 'name', e.target.value)}
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>Method</label>
                            <select
                              className="w-full px-3 py-2 rounded-lg text-sm border"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                              value={ep.method}
                              onChange={e => setEpField(i, 'method', e.target.value)}
                            >
                              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map(m => (
                                <option key={m} value={m}>{m}</option>
                              ))}
                            </select>
                          </div>
                          <div>
                            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>Path</label>
                            <input
                              className="w-full px-3 py-2 rounded-lg text-sm border font-mono"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                              placeholder="/repos/owner/repo/issues"
                              value={ep.path}
                              onChange={e => setEpField(i, 'path', e.target.value)}
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                              Extract Field (dot-path)
                            </label>
                            <input
                              className="w-full px-3 py-2 rounded-lg text-sm border font-mono"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                              placeholder="data.items"
                              value={ep.extract_field ?? ''}
                              onChange={e => setEpField(i, 'extract_field', e.target.value)}
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>Result Label</label>
                            <input
                              className="w-full px-3 py-2 rounded-lg text-sm border"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                              placeholder="Open Issues"
                              value={ep.result_label ?? ''}
                              onChange={e => setEpField(i, 'result_label', e.target.value)}
                            />
                          </div>
                        </div>

                        {/* Body template for POST/PUT/PATCH */}
                        {['POST', 'PUT', 'PATCH'].includes(ep.method) && (
                          <div>
                            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                              Body Template (JSON)
                            </label>
                            <textarea
                              className="w-full px-3 py-2 rounded-lg text-sm border font-mono"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-1)' }}
                              rows={4}
                              placeholder='{"title": "Security Alert", "body": "{{ctx.message}}"}'
                              value={ep.body_template ? JSON.stringify(ep.body_template, null, 2) : ''}
                              onChange={e => {
                                try { setEpField(i, 'body_template', JSON.parse(e.target.value)); }
                                catch { setEpField(i, 'body_template', e.target.value as any); }
                              }}
                            />
                          </div>
                        )}

                        {/* Test button (only when editing saved definition) */}
                        {editId && (
                          <div className="flex items-center gap-3">
                            <button
                              onClick={() => handleTest(editId, i)}
                              disabled={testing === editId}
                              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50"
                              style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-2)' }}
                            >
                              {testing === editId
                                ? <><span className="animate-spin inline-block w-3 h-3 border border-current/40 border-t-current rounded-full" /> Testing…</>
                                : <><Play size={12} /> Test This Endpoint</>
                              }
                            </button>
                            {testResult && (
                              <span className={`text-xs ${testResult.error || !testResult.result?.success ? 'text-red-400' : 'text-green-400'}`}>
                                {testResult.error ? `Error: ${testResult.error}` : `HTTP ${testResult.result?.status_code}`}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>

            {/* Test result panel */}
            {testResult && testResult.result && (
              <div className="rounded-xl p-4 text-xs font-mono"
                   style={{ background: 'var(--rc-bg-base)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-2)', maxHeight: 200, overflowY: 'auto' }}>
                <div className="font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>
                  Response — {testResult.result.status_code}
                </div>
                <pre className="whitespace-pre-wrap break-all">
                  {JSON.stringify(testResult.result.data ?? testResult.result.raw_preview, null, 2)}
                </pre>
              </div>
            )}

            {/* Save / Cancel */}
            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium disabled:opacity-50"
                style={{ background: 'var(--rc-accent-violet)', color: '#fff' }}
              >
                {saving ? 'Saving…' : <><Save size={14} /> {editId ? 'Update Capability' : 'Create Capability'}</>}
              </button>
              <button
                onClick={closeForm}
                className="px-4 py-2.5 rounded-lg text-sm"
                style={{ background: 'var(--rc-bg-elevated)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-2)' }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Info panel when definitions exist and no form */}
      {definitions.length > 0 && !showForm && (
        <div className="rounded-xl p-4 flex items-start gap-3 text-sm"
             style={{ background: 'var(--rc-bg-surface)', border: '1px solid var(--rc-border)', color: 'var(--rc-text-2)' }}>
          <Plug size={18} className="mt-0.5 shrink-0" style={{ color: 'var(--rc-accent-violet)' }} />
          <div>
            <span className="font-medium" style={{ color: 'var(--rc-text-1)' }}>Use in workflows: </span>
            Reference any custom capability endpoint from the Security Copilot by saying something like
            "POST to my Jira capability and create a ticket" or "call the GitHub Issues capability every hour".
            The workflow generator will automatically create the right <code className="font-mono">http_request</code> step.
          </div>
        </div>
      )}

    </div>
  );
}
