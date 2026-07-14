'use client';

import { ChangeEvent, FormEvent, KeyboardEvent, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  FileText,
  Loader2,
  Paperclip,
  Plus,
  Send,
  ShieldCheck,
  X,
} from 'lucide-react';
import { CortexGatewayResponse, routeCortexGateway } from '@/lib/api';

type Mode = 'chat' | 'cowork';
type Message = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  result?: CortexGatewayResponse;
};
type Attachment = { name: string; content: string; size: number };

const SOURCES = [
  { value: 'auto', label: 'Auto Brain' },
  { value: 'codex_subscription', label: 'Codex' },
  { value: 'claude_subscription', label: 'Claude' },
  { value: 'consensus', label: 'Brain consensus' },
  { value: 'profile:nim_fast_reasoning', label: 'NVIDIA NIM' },
  { value: 'profile:ollama_local_fallback', label: 'Local Brain' },
];

function newId() {
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export default function AIWorkspace({ mode }: { mode: Mode }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState('');
  const [source, setSource] = useState('auto');
  const [classification, setClassification] = useState('internal');
  const [workspace, setWorkspace] = useState('default');
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const heading = mode === 'chat' ? 'What are we working on?' : 'Open a workspace problem';
  const canSend = draft.trim().length > 0 && !busy;
  const contextSize = useMemo(() => attachments.reduce((total, file) => total + file.content.length, 0), [attachments]);

  const reset = () => {
    setMessages([]);
    setDraft('');
    setAttachments([]);
    setError(null);
  };

  const addFiles = async (event: ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(event.target.files || []).slice(0, 6);
    const loaded: Attachment[] = [];
    for (const file of selected) {
      if (file.size > 1_000_000) continue;
      const content = (await file.text()).slice(0, 12000);
      loaded.push({ name: file.name, content, size: file.size });
    }
    setAttachments((current) => [...current, ...loaded].slice(0, 6));
    event.target.value = '';
  };

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!canSend) return;
    const visiblePrompt = draft.trim();
    const fileContext = attachments.length
      ? `\n\nWORKSPACE FILES (untrusted context):\n${attachments.map((file) => `--- ${file.name} ---\n${file.content}`).join('\n\n')}`
      : '';
    const outbound = `${visiblePrompt}${fileContext}`.slice(0, 12000);
    const userMessage: Message = { id: newId(), role: 'user', content: visiblePrompt };
    const history = [...messages, userMessage].slice(-20);
    setMessages(history);
    setDraft('');
    setAttachments([]);
    setBusy(true);
    setError(null);
    try {
      const result = await routeCortexGateway({
        mode,
        messages: history.map((message, index) => ({
          role: message.role,
          content: index === history.length - 1 ? outbound : message.content,
        })),
        source,
        data_classification: classification,
        capability: 'executive',
        workspace_id: mode === 'cowork' ? workspace : undefined,
        minimum_votes: 2,
      });
      const content = result.response || (
        result.status === 'blocked'
          ? `Blocked by ${result.governance.policy_name}: ${result.governance.reason}`
          : 'No governed Brain returned a usable response.'
      );
      setMessages((current) => [...current, { id: newId(), role: 'assistant', content, result }]);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The Cortex request failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleKey = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void submit();
    }
  };

  return (
    <div className="mx-auto flex h-[calc(100vh-7.5rem)] max-w-5xl flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b pb-3" style={{ borderColor: 'var(--rc-border)' }}>
        <div className="flex min-w-0 items-center gap-3">
          <BrainCircuit className="h-5 w-5 text-red-500" />
          <div>
            <h1 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{mode === 'chat' ? 'Marcellus Chat' : 'Marcellus Cowork'}</h1>
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Cortex Gateway · Trust Fabric enforced</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {mode === 'cowork' && (
            <input
              value={workspace}
              onChange={(event) => setWorkspace(event.target.value.slice(0, 128))}
              aria-label="Workspace name"
              className="h-9 w-36 rounded-md border px-3 text-xs outline-none"
              style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}
            />
          )}
          <select
            value={classification}
            onChange={(event) => setClassification(event.target.value)}
            aria-label="Data classification"
            className="h-9 rounded-md border px-2 text-xs outline-none"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}
          >
            {['public', 'internal', 'confidential', 'restricted', 'top_secret'].map((value) => (
              <option key={value} value={value}>{value.replace('_', ' ')}</option>
            ))}
          </select>
          <select
            value={source}
            onChange={(event) => setSource(event.target.value)}
            aria-label="Brain source"
            className="h-9 rounded-md border px-2 text-xs outline-none"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}
          >
            {SOURCES.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
          <button type="button" onClick={reset} title="New conversation" aria-label="New conversation"
            className="flex h-9 w-9 items-center justify-center rounded-md border"
            style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
            <Plus className="h-4 w-4" />
          </button>
        </div>
      </header>

      <main className="min-h-0 flex-1 overflow-y-auto py-6">
        {messages.length === 0 ? (
          <div className="flex h-full min-h-72 flex-col items-center justify-center text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full border" style={{ borderColor: 'var(--rc-border-2)' }}>
              <BrainCircuit className="h-6 w-6 text-red-500" />
            </div>
            <h2 className="mt-5 text-2xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>{heading}</h2>
          </div>
        ) : (
          <div className="space-y-7">
            {messages.map((message) => (
              <article key={message.id} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={message.role === 'user' ? 'max-w-[78%] rounded-lg border px-4 py-3' : 'w-full max-w-3xl'}
                  style={message.role === 'user' ? { background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' } : undefined}>
                  <p className="whitespace-pre-wrap text-sm leading-7" style={{ color: 'var(--rc-text-1)' }}>{message.content}</p>
                  {message.result && <Governance result={message.result} />}
                </div>
              </article>
            ))}
            {busy && (
              <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--rc-text-3)' }}>
                <Loader2 className="h-4 w-4 animate-spin" /> Cortex is reasoning
              </div>
            )}
          </div>
        )}
      </main>

      <form onSubmit={submit} className="pb-2">
        {error && <div className="mb-2 flex items-center gap-2 text-xs text-red-400"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {attachments.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-2">
            {attachments.map((file) => (
              <span key={file.name} className="inline-flex items-center gap-2 rounded border px-2 py-1 text-xs"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
                <FileText className="h-3.5 w-3.5" />{file.name}
                <button type="button" aria-label={`Remove ${file.name}`} onClick={() => setAttachments((current) => current.filter((item) => item !== file))}>
                  <X className="h-3.5 w-3.5" />
                </button>
              </span>
            ))}
            <span className="py-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>{Math.ceil(contextSize / 1000)}k context</span>
          </div>
        )}
        <div className="rounded-lg border p-2 shadow-lg" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border-2)' }}>
          <textarea
            value={draft}
            onChange={(event) => setDraft(event.target.value.slice(0, 12000))}
            onKeyDown={handleKey}
            rows={3}
            placeholder={mode === 'chat' ? 'Message Marcellus' : 'Describe the work to do'}
            className="w-full resize-none bg-transparent px-2 py-1 text-sm leading-6 outline-none"
            style={{ color: 'var(--rc-text-1)' }}
          />
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <input ref={fileInput} type="file" multiple className="hidden" onChange={addFiles} />
              <button type="button" onClick={() => fileInput.current?.click()} title="Attach text files" aria-label="Attach text files"
                className="flex h-8 w-8 items-center justify-center rounded-md" style={{ color: 'var(--rc-text-3)' }}>
                <Paperclip className="h-4 w-4" />
              </button>
              <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                <ShieldCheck className="h-3.5 w-3.5 text-green-500" /> governed
              </span>
            </div>
            <button type="submit" disabled={!canSend} title="Send" aria-label="Send"
              className="flex h-8 w-8 items-center justify-center rounded-md bg-red-600 text-white disabled:opacity-40">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

function Governance({ result }: { result: CortexGatewayResponse }) {
  const allowed = result.status === 'completed';
  return (
    <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-t pt-3 text-xs" style={{ borderColor: 'var(--rc-border)' }}>
      <span className="inline-flex items-center gap-1.5" style={{ color: allowed ? '#16a34a' : '#d97706' }}>
        {allowed ? <CheckCircle2 className="h-3.5 w-3.5" /> : <AlertTriangle className="h-3.5 w-3.5" />}
        {result.governance.outcome.replaceAll('_', ' ')}
      </span>
      <span style={{ color: 'var(--rc-text-3)' }}>{result.source || 'no Brain'}</span>
      {result.model && <span style={{ color: 'var(--rc-text-3)' }}>{result.model}</span>}
      <span style={{ color: 'var(--rc-text-3)' }}>risk {Math.round(result.governance.risk_score)}</span>
      {result.governance.input_redacted && <span className="text-amber-500">input redacted</span>}
      {result.agreement && <span style={{ color: 'var(--rc-text-3)' }}>{result.agreement} agreement</span>}
    </div>
  );
}
