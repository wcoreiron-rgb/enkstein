'use client';

import {
  ChangeEvent,
  FormEvent,
  KeyboardEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import {
  AlertTriangle,
  Bot,
  BrainCircuit,
  Check,
  CheckCircle2,
  File,
  FilePlus2,
  Folder,
  FolderOpen,
  FolderPlus,
  GitBranch,
  Globe2,
  ExternalLink,
  Loader2,
  Paperclip,
  Pencil,
  RefreshCcw,
  Save,
  Send,
  ShieldAlert,
  ShieldCheck,
  Square,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import {
  archiveCortexConversation,
  branchCortexConversation,
  renameCortexConversation,
  CortexArtifact,
  CortexChangeProposal,
  CortexConversation,
  CortexMessageRecord,
  CortexNativeWorkspace,
  CortexProject,
  createCortexConversation,
  createCortexProject,
  connectCortexNativeWorkspace,
  createCortexSecurityInvestigation,
  deleteCortexArtifact,
  getArcModels,
  getArcProviders,
  getBrainStatuses,
  getCortexArtifact,
  getCortexArtifacts,
  getCortexChangeProposals,
  getCortexConversation,
  getCortexConversations,
  getCortexProjects,
  getCortexNativeWorkspace,
  getModelClawProfiles,
  ingestCortexArtifacts,
  moveCortexConversation,
  reviewCortexChangeProposal,
  runCortexResearch,
  streamCortexTurn,
  syncCortexNativeWorkspace,
  updateCortexArtifact,
} from '@/lib/api';
import { persistRuntimeGroup, readStoredRuntimeGroup, RuntimeGroup } from '@/lib/runtime-group';

declare global {
  interface Window {
    marcellusNativeWorkspace?: { selectFolder: () => void };
  }
}

type Mode = 'chat' | 'cowork';

type ModelOption = { id: string; label: string };
type SourceOption = { value: string; label: string; ready: boolean; detail?: string; models: ModelOption[] };
type WorkspaceDialog =
  | { kind: 'archive-conversation'; conversation: CortexConversation }
  | { kind: 'move-conversation'; conversation: CortexConversation }
  | { kind: 'rename-conversation'; conversation: CortexConversation }
  | { kind: 'trash-file'; artifact: CortexArtifact };

const BASE_SOURCES: SourceOption[] = [
  { value: 'auto', label: 'Auto Brain', ready: true, detail: 'First available policy-approved Brain', models: [] },
  { value: 'consensus', label: 'Multi-Brain Swarm', ready: true, detail: 'Available Brains work concurrently and preserve dissent', models: [] },
];

const TEXT_EXTENSIONS = new Set([
  'bash', 'c', 'cfg', 'conf', 'cpp', 'cs', 'css', 'csv', 'go', 'h', 'hpp', 'html', 'ini', 'java',
  'js', 'json', 'jsx', 'kt', 'kts', 'log', 'md', 'mjs', 'ps1', 'py', 'rb', 'rs', 'sh', 'sql', 'tf',
  'tfvars', 'toml', 'ts', 'tsx', 'txt', 'xml', 'yaml', 'yml',
]);

function filePath(file: File) {
  return (file.webkitRelativePath || file.name).replaceAll('\\', '/');
}

function isTextFile(file: File) {
  const extension = file.name.split('.').pop()?.toLowerCase() || '';
  return file.type.startsWith('text/') || file.type.includes('json') || file.type.includes('xml') || TEXT_EXTENSIONS.has(extension);
}

export default function AIWorkspace({ mode }: { mode: Mode }) {
  const [projects, setProjects] = useState<CortexProject[]>([]);
  const [projectId, setProjectId] = useState<string>('');
  const [conversations, setConversations] = useState<CortexConversation[]>([]);
  const [active, setActive] = useState<CortexConversation | null>(null);
  const [messages, setMessages] = useState<CortexMessageRecord[]>([]);
  const [artifacts, setArtifacts] = useState<CortexArtifact[]>([]);
  const [proposals, setProposals] = useState<CortexChangeProposal[]>([]);
  const [selectedArtifacts, setSelectedArtifacts] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<CortexArtifact | null>(null);
  const [creatingFile, setCreatingFile] = useState(false);
  const [newFilePath, setNewFilePath] = useState('');
  const [editorContent, setEditorContent] = useState('');
  const [savingFile, setSavingFile] = useState(false);
  const [draft, setDraft] = useState('');
  const [source, setSource] = useState('auto');
  const [model, setModel] = useState('');
  const [sourceOptions, setSourceOptions] = useState<SourceOption[]>(BASE_SOURCES);
  const [classification, setClassification] = useState('internal');
  const [runtimeGroup, setRuntimeGroup] = useState<RuntimeGroup>('hybrid');

  useEffect(() => { setRuntimeGroup(readStoredRuntimeGroup()); }, []);
  const selectRuntimeGroup = (group: RuntimeGroup) => {
    setRuntimeGroup(group);
    persistRuntimeGroup(group);
  };
  const [busy, setBusy] = useState(false);
  const [agentMode, setAgentMode] = useState(mode === 'cowork');
  const [streamText, setStreamText] = useState('');
  const [activity, setActivity] = useState<string[]>([]);
  const [reviewingProposal, setReviewingProposal] = useState<string | null>(null);
  const [researchOpen, setResearchOpen] = useState(false);
  const [researchQuestion, setResearchQuestion] = useState('');
  const [researchUrls, setResearchUrls] = useState('');
  const [researching, setResearching] = useState(false);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const selectedArtifactBytes = artifacts.reduce(
    (total, artifact) => total + (selectedArtifacts.has(artifact.id) ? artifact.size_bytes : 0),
    0,
  );
  const [nativeWorkspace, setNativeWorkspace] = useState<CortexNativeWorkspace | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<WorkspaceDialog | null>(null);
  const [dialogBusy, setDialogBusy] = useState(false);
  const [moveProjectId, setMoveProjectId] = useState('');
  const [renameTitle, setRenameTitle] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const turnAbort = useRef<AbortController | null>(null);

  useEffect(() => {
    folderInput.current?.setAttribute('webkitdirectory', '');
  }, []);

  const loadConversations = useCallback(async (preferredId?: string) => {
    const rows = await getCortexConversations(mode, mode === 'cowork' && projectId ? projectId : undefined);
    setConversations(rows);
    const target = rows.find((item) => item.id === preferredId) || rows[0] || null;
    if (target) {
      const detail = await getCortexConversation(target.id);
      setActive(detail);
      setMessages(detail.messages);
      setSource(detail.selected_source);
      setClassification(detail.classification);
    } else {
      setActive(null);
      setMessages([]);
    }
  }, [mode, projectId]);

  const loadArtifacts = useCallback(async () => {
    if (!projectId) {
      setArtifacts([]);
      setSelectedArtifacts(new Set());
      return;
    }
    const rows = await getCortexArtifacts(projectId);
    setArtifacts(rows);
    setSelectedArtifacts(new Set(rows.slice(0, 20).map((item) => item.id)));
  }, [projectId]);

  const loadProposals = useCallback(async () => {
    if (!projectId || mode !== 'cowork') {
      setProposals([]);
      return;
    }
    setProposals(await getCortexChangeProposals(projectId));
  }, [mode, projectId]);

  useEffect(() => {
    setAgentMode(mode === 'cowork');
    setStreamText('');
    setActivity([]);
  }, [mode]);

  useEffect(() => {
    void loadProposals().catch(() => setProposals([]));
  }, [loadProposals]);

  useEffect(() => {
    let cancelled = false;
    if (!projectId) {
      setNativeWorkspace(null);
      return;
    }
    void getCortexNativeWorkspace(projectId)
      .then((result) => { if (!cancelled) setNativeWorkspace(result); })
      .catch(() => { if (!cancelled) setNativeWorkspace(null); });
    return () => { cancelled = true; };
  }, [projectId]);

  useEffect(() => {
    const selected = (event: Event) => {
      const detail = (event as CustomEvent<{ token?: string; name?: string }>).detail;
      if (!detail?.token || !detail.name) return;
      setUploading(true);
      setError(null);
      void (async () => {
        let targetProjectId = projectId;
        if (!targetProjectId) {
          const matchingProject = projects.find((project) => project.name.toLowerCase() === detail.name!.toLowerCase());
          const project = matchingProject || await createCortexProject({
            name: detail.name!,
            classification: 'internal',
            default_source: 'auto',
          });
          if (!matchingProject) setProjects((current) => [project, ...current]);
          targetProjectId = project.id;
          window.localStorage.setItem('marcellus-cowork-project', targetProjectId);
          setProjectId(targetProjectId);
        }
        const result = await connectCortexNativeWorkspace(targetProjectId, { token: detail.token!, name: detail.name! });
          setNativeWorkspace(result);
        const rows = await getCortexArtifacts(targetProjectId);
        setArtifacts(rows);
        setSelectedArtifacts(new Set(rows.slice(0, 20).map((item) => item.id)));
      })()
        .catch((connectError) => setError(connectError instanceof Error ? connectError.message : 'The local folder could not be connected.'))
        .finally(() => setUploading(false));
    };
    window.addEventListener('marcellus:native-workspace-selected', selected);
    return () => window.removeEventListener('marcellus:native-workspace-selected', selected);
  }, [projectId, projects]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const rows = mode === 'cowork' ? await getCortexProjects() : [];
        if (cancelled) return;
        setProjects(rows);
        const rememberedProject = typeof window !== 'undefined' ? window.localStorage.getItem('marcellus-cowork-project') : '';
        const nextProject = mode === 'cowork'
          ? (projectId || rows.find((item) => item.id === rememberedProject)?.id || rows[0]?.id || '')
          : '';
        if (mode === 'cowork' && nextProject !== projectId) {
          setProjectId(nextProject);
          return;
        }
        const conversationRows = await getCortexConversations(mode, nextProject || undefined);
        if (cancelled) return;
        setConversations(conversationRows);
        const pendingConversation = mode === 'cowork' ? window.localStorage.getItem('marcellus-cowork-conversation') : '';
        const first = conversationRows.find((item) => item.id === pendingConversation) || conversationRows[0];
        if (first) {
          const detail = await getCortexConversation(first.id);
          if (cancelled) return;
          setActive(detail);
          setMessages(detail.messages);
          setSource(detail.selected_source);
          setClassification(detail.classification);
          if (pendingConversation === first.id) window.localStorage.removeItem('marcellus-cowork-conversation');
        } else {
          setActive(null);
          setMessages([]);
        }
        if (nextProject) {
          const artifactRows = await getCortexArtifacts(nextProject);
          setArtifacts(artifactRows);
          setSelectedArtifacts(new Set(artifactRows.slice(0, 20).map((item) => item.id)));
        } else {
          setArtifacts([]);
          setSelectedArtifacts(new Set());
        }
      } catch (loadError) {
        if (!cancelled) setError(loadError instanceof Error ? loadError.message : 'Workspace could not be loaded.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => { cancelled = true; };
    // projectId is intentionally included so changing projects reloads its conversations and files.
  }, [mode, projectId]);

  useEffect(() => {
    let cancelled = false;
    const loadBrains = async () => {
      const [statusResult, profileResult, providerResult, modelResult] = await Promise.allSettled([
        getBrainStatuses(),
        getModelClawProfiles(),
        getArcProviders(),
        getArcModels(),
      ]);
      if (cancelled) return;
      const statuses = statusResult.status === 'fulfilled' ? statusResult.value : [];
      const profiles = profileResult.status === 'fulfilled' ? profileResult.value : [];
      const providers = providerResult.status === 'fulfilled' ? providerResult.value : [];
      const providerModels = modelResult.status === 'fulfilled' ? modelResult.value : {};
      const providerState = new Map(providers.map((item: any) => [item.provider, item]));
      const subscriptionOptions: SourceOption[] = statuses.map((item: any) => ({
        value: item.brain,
        label: item.brain === 'codex_subscription'
          ? 'Codex subscription'
          : item.brain === 'claude_subscription'
            ? 'Claude subscription'
            : item.brain === 'chatgpt_desktop'
              ? 'ChatGPT desktop app'
              : item.brain === 'claude_desktop'
                ? 'Claude desktop app'
                : item.brain === 'chatgpt_browser'
                  ? 'ChatGPT browser session'
                  : item.brain === 'claude_browser'
                    ? 'Claude browser session'
                    : item.brain === 'gemini_browser'
                      ? 'Gemini browser session'
                : item.brain,
        ready: Boolean(item.available && item.authenticated),
        detail: item.detail,
        models: [
          { id: '', label: 'Subscription default' },
          ...(item.models || []).map((id: string) => ({ id, label: id })),
        ],
      }));
      const profileOptions: SourceOption[] = profiles
        .filter((profile: any) => (profile.allowed_claws || []).includes('executive'))
        .map((profile: any) => {
          const providerKey = profile.provider === 'nvidia_nim' ? 'nvidia' : profile.provider;
          const provider = providerState.get(providerKey) as any;
          const allowedModels = new Set<string>(profile.allowed_models || [profile.model]);
          const liveModels = (providerModels[providerKey] || [])
            .filter((item) => providerKey === 'ollama' || allowedModels.has(item.id))
            .map((item) => ({ id: item.id, label: item.name || item.id }));
          const models = liveModels.length ? liveModels : [{ id: profile.model, label: profile.model }];
          return {
            value: `profile:${profile.name}`,
            label: provider?.label || `${profile.provider} · ${profile.name}`,
            ready: Boolean(provider?.ready),
            detail: provider?.setup || 'Provider is not connected.',
            models,
          };
        });
      const next = [...BASE_SOURCES, ...subscriptionOptions, ...profileOptions];
      setSourceOptions(next);
      setSource((current) => {
        const selected = next.find((item) => item.value === current);
        if (selected && !selected.ready) {
          setModel('');
          return 'auto';
        }
        return current;
      });
    };
    void loadBrains();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, busy]);

  const createConversation = async () => {
    if (mode === 'cowork' && !projectId) {
      setError('Create or select a project from the Cowork blade first.');
      return null;
    }
    const conversation = await createCortexConversation({
      project_id: mode === 'cowork' ? projectId : undefined,
      title: 'New conversation',
      mode,
      classification,
      selected_source: source,
    });
    setConversations((current) => [conversation, ...current]);
    setActive(conversation);
    setMessages([]);
    setPreview(null);
    setCreatingFile(false);
    return conversation;
  };

  const openConversation = async (conversation: Pick<CortexConversation, 'id'>) => {
    setLoading(true);
    try {
      const detail = await getCortexConversation(conversation.id);
      setActive(detail);
      setMessages(detail.messages);
      setSource(detail.selected_source);
      setClassification(detail.classification);
      if (detail.project_id) {
        const rows = await getCortexArtifacts(detail.project_id);
        setArtifacts(rows);
        setSelectedArtifacts(new Set(rows.slice(0, 20).map((item) => item.id)));
      }
      setError(null);
    } catch (openError) {
      setError(openError instanceof Error ? openError.message : 'Conversation could not be opened.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const handleAction = (event: Event) => {
      const detail = (event as CustomEvent<{ type?: string; id?: string }>).detail;
      if (!detail?.type) return;
      if (detail.type === 'new-conversation') void createConversation();
      if (detail.type === 'open-conversation' && detail.id) {
        const conversation = conversations.find((item) => item.id === detail.id);
        if (conversation) void openConversation(conversation);
      }
      if (detail.type === 'select-project' && mode === 'cowork') setProjectId(detail.id || '');
      if (
        (detail.type === 'request-archive-conversation'
          || detail.type === 'request-move-conversation'
          || detail.type === 'request-rename-conversation')
        && detail.id
      ) {
        const conversation = conversations.find((item) => item.id === detail.id);
        if (conversation) {
          setMoveProjectId('');
          setRenameTitle(conversation.title);
          setDialog({
            kind: detail.type === 'request-archive-conversation'
              ? 'archive-conversation'
              : detail.type === 'request-move-conversation'
                ? 'move-conversation'
                : 'rename-conversation',
            conversation,
          });
        }
      }
    };
    window.addEventListener('marcellus:workspace-action', handleAction);
    return () => window.removeEventListener('marcellus:workspace-action', handleAction);
  });

  useEffect(() => {
    window.dispatchEvent(new CustomEvent('marcellus:workspace-state', {
      detail: {
        mode,
        conversations,
        projects,
        activeConversationId: active?.id,
        projectId,
        nativeWorkspaceName: nativeWorkspace?.connected ? nativeWorkspace.name : undefined,
      },
    }));
  }, [active?.id, conversations, mode, nativeWorkspace, projectId, projects]);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    const content = draft.trim();
    if (!content || busy) return;
    if (selectedArtifactBytes > 100_000) {
      setError('Selected files exceed the complete-context limit. Select fewer files so no code is truncated.');
      return;
    }
    setBusy(true);
    setError(null);
    setStreamText('');
    setActivity([]);
    try {
      const conversation = active || await createConversation();
      if (!conversation) return;
      const controller = new AbortController();
      turnAbort.current = controller;
      setDraft('');
      const turn = await streamCortexTurn(conversation.id, {
        content,
        source,
        model: model || undefined,
        data_classification: classification,
        runtime_group: runtimeGroup,
        artifact_ids: Array.from(selectedArtifacts),
        include_project_files: mode === 'cowork' && selectedArtifacts.size > 0,
        minimum_votes: 2,
        agent_mode: mode === 'cowork' && agentMode,
      }, ({ event: streamEvent, data }) => {
        if (streamEvent === 'turn_started') setActivity(['Planning governed turn']);
        if (streamEvent === 'context_ready') setActivity((current) => [...current, 'Workspace context prepared']);
        if (streamEvent === 'brain_completed') {
          const state = data.counted ? 'completed' : 'did not return a usable vote';
          setActivity((current) => [...current, `${data.source || 'Brain'} ${state}`]);
        }
        if (streamEvent === 'response_delta') setStreamText((current) => current + String(data.delta || ''));
        if (streamEvent === 'changes_proposed') setActivity((current) => [...current, `${data.count} file change proposal${data.count === 1 ? '' : 's'} ready for review`]);
      }, controller.signal);
      setActive(turn.conversation);
      setMessages((current) => [
        ...current,
        turn.user_message,
        ...(turn.assistant_message ? [turn.assistant_message] : []),
      ]);
      setConversations((current) => [
        turn.conversation,
        ...current.filter((item) => item.id !== turn.conversation.id),
      ]);
      await loadProposals();
    } catch (requestError) {
      if (requestError instanceof Error && requestError.name === 'AbortError') {
        setActivity((current) => [...current, 'Turn stopped by operator']);
      } else {
        setError(requestError instanceof Error ? requestError.message : 'The governed request failed.');
      }
    } finally {
      turnAbort.current = null;
      setBusy(false);
      setStreamText('');
    }
  };

  const stopTurn = () => turnAbort.current?.abort();

  const runResearch = async () => {
    const urls = researchUrls.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    if (!projectId || !active || !researchQuestion.trim() || !urls.length || researching) return;
    setResearching(true);
    setBusy(true);
    setError(null);
    setActivity(['Trust Fabric is evaluating research access']);
    try {
      setActivity((current) => [...current, `Retrieving ${urls.length} governed source${urls.length === 1 ? '' : 's'}`]);
      const result = await runCortexResearch(projectId, {
        conversation_id: active.id,
        question: researchQuestion.trim(),
        urls,
        source,
        model: model || undefined,
        data_classification: classification,
      });
      setActive(result.turn.conversation);
      setMessages((current) => [
        ...current,
        result.turn.user_message,
        ...(result.turn.assistant_message ? [result.turn.assistant_message] : []),
      ]);
      setConversations((current) => [
        result.turn.conversation,
        ...current.filter((item) => item.id !== result.turn.conversation.id),
      ]);
      setActivity((current) => [...current, `${result.citations.length} citations verified`, 'Source bundle and report saved']);
      await loadArtifacts();
      setResearchOpen(false);
      setResearchQuestion('');
      setResearchUrls('');
    } catch (researchError) {
      setError(researchError instanceof Error ? researchError.message : 'Governed research could not be completed.');
    } finally {
      setResearching(false);
      setBusy(false);
    }
  };

  const reviewProposal = async (proposal: CortexChangeProposal, decision: 'approve' | 'reject') => {
    setReviewingProposal(proposal.id);
    setError(null);
    try {
      await reviewCortexChangeProposal(proposal.id, decision);
      await Promise.all([loadProposals(), loadArtifacts()]);
    } catch (reviewError) {
      setError(reviewError instanceof Error ? reviewError.message : 'The proposed change could not be reviewed.');
    } finally {
      setReviewingProposal(null);
    }
  };

  const handleKey = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void submit();
    }
  };

  const selectSource = (value: string) => {
    setSource(value);
    const option = sourceOptions.find((item) => item.value === value);
    setModel(option?.models[0]?.id || '');
  };

  const openFolderPicker = () => {
    if (window.marcellusNativeWorkspace) window.marcellusNativeWorkspace.selectFolder();
    else folderInput.current?.click();
  };

  const syncNativeFolder = async () => {
    if (!projectId || uploading) return;
    setUploading(true);
    setError(null);
    try {
      const result = await syncCortexNativeWorkspace(projectId);
      setNativeWorkspace(result);
      await loadArtifacts();
    } catch (syncError) {
      setError(syncError instanceof Error ? syncError.message : 'The local folder could not be synchronized.');
    } finally {
      setUploading(false);
    }
  };

  const ingestFiles = async (event: ChangeEvent<HTMLInputElement>) => {
    const incoming = Array.from(event.target.files || []).filter(isTextFile).filter((file) => file.size <= 1_000_000).slice(0, 100);
    event.target.value = '';
    if (!incoming.length) return;
    setUploading(true);
    setError(null);
    try {
      let targetProjectId = projectId;
      if (!targetProjectId) {
        const folderName = filePath(incoming[0]).split('/')[0] || 'Local project';
        const matchingProject = projects.find((project) => project.name.toLowerCase() === folderName.toLowerCase());
        const project = matchingProject || await createCortexProject({
          name: folderName,
          classification: 'internal',
          default_source: 'auto',
        });
        if (!matchingProject) setProjects((current) => [project, ...current]);
        targetProjectId = project.id;
        window.localStorage.setItem('marcellus-cowork-project', targetProjectId);
        setProjectId(targetProjectId);
      }
      const files = await Promise.all(incoming.map(async (file) => ({
        path: filePath(file),
        content: await file.text(),
        mime_type: file.type || 'text/plain',
      })));
      const ingested = await ingestCortexArtifacts({
        project_id: targetProjectId,
        conversation_id: active?.id,
        classification,
        files,
      });
      const rows = await getCortexArtifacts(targetProjectId);
      setArtifacts(rows);
      setSelectedArtifacts(new Set(ingested.map((item) => item.id)));
    } catch (uploadError) {
      setError(uploadError instanceof Error ? uploadError.message : 'Files could not be ingested.');
    } finally {
      setUploading(false);
    }
  };

  const previewArtifact = async (artifact: CortexArtifact) => {
    try {
      const detail = await getCortexArtifact(artifact.id);
      setPreview(detail);
      setCreatingFile(false);
      setNewFilePath(detail.path);
      setEditorContent(detail.content || '');
    } catch (previewError) {
      setError(previewError instanceof Error ? previewError.message : 'File could not be opened.');
    }
  };

  const startNewFile = () => {
    setPreview(null);
    setCreatingFile(true);
    setNewFilePath('');
    setEditorContent('');
  };

  const closeEditor = () => {
    setPreview(null);
    setCreatingFile(false);
    setNewFilePath('');
    setEditorContent('');
  };

  const saveFile = async () => {
    const path = newFilePath.trim();
    if (!projectId || !path || savingFile) return;
    setSavingFile(true);
    setError(null);
    try {
      const rows = creatingFile
        ? await ingestCortexArtifacts({
            project_id: projectId,
            conversation_id: active?.id,
            classification,
            files: [{ path, content: editorContent, mime_type: 'text/plain' }],
          })
        : preview
          ? [await updateCortexArtifact(preview.id, { path, content: editorContent, mime_type: preview.mime_type })]
          : [];
      await loadArtifacts();
      if (rows[0]) await previewArtifact(rows[0]);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'File could not be saved.');
    } finally {
      setSavingFile(false);
    }
  };

  const removeFile = () => {
    if (preview) setDialog({ kind: 'trash-file', artifact: preview });
  };

  const toggleArtifact = (id: string) => {
    setSelectedArtifacts((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const branchAt = async (message: CortexMessageRecord) => {
    if (!active) return;
    setBusy(true);
    try {
      const branch = await branchCortexConversation(active.id, { message_id: message.id });
      setConversations((current) => [branch, ...current]);
      setActive(branch);
      setMessages(branch.messages);
      setError(null);
    } catch (branchError) {
      setError(branchError instanceof Error ? branchError.message : 'Conversation could not be branched.');
    } finally {
      setBusy(false);
    }
  };

  const completeDialog = async () => {
    if (!dialog || dialogBusy) return;
    setDialogBusy(true);
    setError(null);
    try {
      if (dialog.kind === 'archive-conversation') {
        await archiveCortexConversation(dialog.conversation.id);
        await loadConversations();
      } else if (dialog.kind === 'trash-file') {
        await deleteCortexArtifact(dialog.artifact.id);
        closeEditor();
        await loadArtifacts();
      } else if (dialog.kind === 'rename-conversation') {
        const title = renameTitle.trim();
        if (!title) return;
        const renamed = await renameCortexConversation(dialog.conversation.id, title);
        setConversations((current) => current.map((item) => (item.id === renamed.id ? renamed : item)));
        setActive((current) => (current?.id === renamed.id ? { ...current, title: renamed.title } : current));
      } else {
        if (!moveProjectId) return;
        const moved = await moveCortexConversation(dialog.conversation.id, moveProjectId);
        window.localStorage.setItem('marcellus-cowork-project', moveProjectId);
        window.localStorage.setItem('marcellus-cowork-conversation', moved.id);
        window.location.hash = 'cowork';
        if (mode === 'cowork') setProjectId(moveProjectId);
      }
      setDialog(null);
    } catch (dialogError) {
      setError(dialogError instanceof Error ? dialogError.message : 'The workspace action could not be completed.');
    } finally {
      setDialogBusy(false);
    }
  };

  const investigateInSecurity = async () => {
    if (!active || investigating) return;
    setInvestigating(true);
    setError(null);
    try {
      const result = await createCortexSecurityInvestigation(active.id, { requires_approval: true });
      window.location.assign(`/swarm/${result.job_id}`);
    } catch (investigationError) {
      setError(investigationError instanceof Error ? investigationError.message : 'Security investigation could not be created.');
      setInvestigating(false);
    }
  };

  return (
    <div className={`mx-auto grid h-[calc(100vh-4rem)] min-h-0 grid-cols-1 overflow-hidden ${mode === 'cowork' ? 'max-w-[1760px] lg:grid-cols-[minmax(420px,1fr)_300px]' : 'max-w-none'} `}
      style={{ background: mode === 'chat' ? 'var(--rc-chat-canvas)' : 'var(--rc-bg-base)' }}>
      <section className="flex min-h-0 min-w-0 flex-col">
        <header className="flex min-h-14 flex-wrap items-center justify-between gap-2 px-4 py-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <BrainCircuit className="h-4 w-4 text-red-500" />
              <h1 className="truncate text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{active?.title || (mode === 'chat' ? 'Enkstein Chat' : 'Enkstein Cowork')}</h1>
            </div>
            <p className="mt-0.5 text-[11px]" style={{ color: 'var(--rc-text-3)' }}>Cortex Gateway · encrypted history · Trust Fabric enforced</p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <select value={classification} onChange={(event) => setClassification(event.target.value)} aria-label="Data classification"
              className="h-8 rounded-md border px-2 text-xs outline-none" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
              {['public', 'internal', 'confidential', 'restricted', 'top_secret'].map((value) => <option key={value} value={value}>{value.replace('_', ' ')}</option>)}
            </select>
            <select value={runtimeGroup} onChange={(event) => selectRuntimeGroup(event.target.value as RuntimeGroup)} aria-label="Runtime group"
              title="Local: only the on-device Brain. Hybrid: local-first with CLI/API fallback. Cloud: approved subscription CLI/API only."
              className="h-8 rounded-md border px-2 text-xs outline-none" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
              <option value="local">Local only</option>
              <option value="hybrid">Hybrid</option>
              <option value="cloud">Cloud only</option>
            </select>
            <select value={source} onChange={(event) => selectSource(event.target.value)} aria-label="Brain source"
              title={sourceOptions.find((item) => item.value === source)?.detail}
              className="h-8 rounded-md border px-2 text-xs outline-none" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
              {sourceOptions.map((option) => <option key={option.value} value={option.value} disabled={!option.ready}>{option.label}{option.ready ? '' : ' — unavailable'}</option>)}
            </select>
            {(sourceOptions.find((item) => item.value === source)?.models.length || 0) > 0 && (
              <select value={model} onChange={(event) => setModel(event.target.value)} aria-label="Brain model"
                className="h-8 max-w-52 rounded-md border px-2 text-xs outline-none"
                style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                {sourceOptions.find((item) => item.value === source)?.models.map((option) => (
                  <option key={option.id || 'default'} value={option.id}>{option.label}</option>
                ))}
              </select>
            )}
            {mode === 'cowork' && (
              <label className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-md border px-2 text-xs"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}>
                <input type="checkbox" checked={agentMode} onChange={(event) => setAgentMode(event.target.checked)} className="h-3.5 w-3.5 accent-red-600" />
                <Bot className="h-3.5 w-3.5 text-red-500" />Agent tools
              </label>
            )}
            {active && (
              <button type="button" onClick={() => void investigateInSecurity()} disabled={investigating}
                title="Investigate this conversation with Security Arms"
                className="inline-flex h-8 items-center gap-1.5 rounded-md border px-2 text-xs disabled:opacity-50"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
                {investigating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5 text-red-500" />}
                Investigate
              </button>
            )}
            {active && mode === 'cowork' && projects.length > 0 && <button type="button" onClick={() => { setMoveProjectId(''); setDialog({ kind: 'move-conversation', conversation: active }); }}
              title="Move to project" aria-label="Move conversation to project" className="flex h-8 w-8 items-center justify-center rounded-md border"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}><FolderOpen className="h-4 w-4" /></button>}
            {active && <button type="button" onClick={() => { setRenameTitle(active.title); setDialog({ kind: 'rename-conversation', conversation: active }); }} title="Rename conversation" aria-label="Rename conversation"
              className="flex h-8 w-8 items-center justify-center rounded-md border" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}><Pencil className="h-4 w-4" /></button>}
            {active && <button type="button" onClick={() => setDialog({ kind: 'archive-conversation', conversation: active })} title="Archive conversation" aria-label="Archive conversation"
              className="flex h-8 w-8 items-center justify-center rounded-md border" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}><Trash2 className="h-4 w-4" /></button>}
          </div>
        </header>

        <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-6 md:px-8">
          {!messages.length && !busy ? (
            <div className="flex h-full min-h-64 flex-col items-center justify-center text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-full border" style={{ borderColor: 'var(--rc-border-2)' }}>
                {mode === 'chat' ? <BrainCircuit className="h-6 w-6 text-red-500" /> : <FolderOpen className="h-6 w-6 text-red-500" />}
              </div>
              <h2 className="mt-5 text-xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>{mode === 'chat' ? 'What are we working on?' : projectId ? 'Work with this project' : 'Create or select a project'}</h2>
              <p className="mt-2 max-w-md text-sm leading-6" style={{ color: 'var(--rc-text-3)' }}>
                {mode === 'chat' ? 'Every Brain request is governed and the conversation is encrypted at rest.' : 'Import a folder and ask about it. Active project files stay attached to this Cowork conversation.'}
              </p>
            </div>
          ) : (
            <div className="mx-auto max-w-3xl space-y-7">
              {messages.map((message) => (
                <article key={message.id} className={`group flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={message.role === 'user' ? 'max-w-[82%] rounded-2xl px-4 py-3' : 'w-full'}
                    style={message.role === 'user' ? { background: 'var(--rc-bg-elevated)' } : undefined}>
                    <p className="whitespace-pre-wrap text-sm leading-7" style={{ color: 'var(--rc-text-1)' }}>{message.content}</p>
                    {message.role === 'assistant' && (
                      <div className="mt-3 flex items-center justify-between gap-3">
                        <GovernanceRecord message={message} />
                        <button type="button" onClick={() => void branchAt(message)} title="Branch from here" aria-label="Branch from here"
                          className="invisible flex h-7 w-7 shrink-0 items-center justify-center rounded group-hover:visible" style={{ color: 'var(--rc-text-3)' }}>
                          <GitBranch className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                </article>
              ))}
              {busy && (
                <article className="space-y-3">
                  <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--rc-text-3)' }}><Loader2 className="h-4 w-4 animate-spin" />Cortex is working</div>
                  {activity.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {activity.map((item, index) => <span key={`${item}-${index}`} className="rounded border px-2 py-1 text-[10px]" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}>{item}</span>)}
                    </div>
                  )}
                  {streamText && <p className="whitespace-pre-wrap text-sm leading-7" style={{ color: 'var(--rc-text-1)' }}>{streamText}</p>}
                </article>
              )}
            </div>
          )}
        </div>

        <form onSubmit={submit} className="px-3 py-3 md:px-6">
          {error && <div className="mx-auto mb-2 flex max-w-3xl items-center gap-2 text-xs text-red-500"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</div>}
          {selectedArtifacts.size > 0 && (
            <div className="mx-auto mb-2 flex max-w-3xl flex-wrap items-center gap-1.5 text-xs" style={{ color: 'var(--rc-text-3)' }}>
              <Paperclip className="h-3.5 w-3.5" /> {selectedArtifacts.size} complete file{selectedArtifacts.size === 1 ? '' : 's'} · {Math.ceil(selectedArtifactBytes / 1024)} KB
              <button type="button" onClick={() => setSelectedArtifacts(new Set())} className="ml-1 text-red-500">clear</button>
            </div>
          )}
          <div className="mx-auto max-w-3xl rounded-2xl border p-2 shadow-sm"
            style={{ background: mode === 'chat' ? 'var(--rc-chat-panel)' : 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <textarea value={draft} onChange={(event) => setDraft(event.target.value.slice(0, 12000))} onKeyDown={handleKey} rows={3}
              placeholder={mode === 'chat' ? 'Message Enkstein' : 'Ask about this project'}
              className="w-full resize-none bg-transparent px-2 py-1 text-sm leading-6 outline-none" style={{ color: 'var(--rc-text-1)' }} />
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-1">
                <span className="inline-flex items-center gap-1.5 px-2 text-xs" style={{ color: 'var(--rc-text-3)' }}><ShieldCheck className="h-3.5 w-3.5 text-green-500" />governed</span>
                {mode === 'cowork' && (
                  <button type="button" onClick={() => setResearchOpen(true)} disabled={!projectId || !active || busy}
                    title="Research public sources" aria-label="Research public sources"
                    className="flex h-8 items-center gap-1.5 rounded-md px-2 text-xs disabled:opacity-40" style={{ color: 'var(--rc-text-2)' }}>
                    <Globe2 className="h-3.5 w-3.5 text-red-500" />Research
                  </button>
                )}
              </div>
              {busy ? (
                <button type="button" onClick={stopTurn} title="Stop turn" aria-label="Stop turn"
                  className="flex h-8 w-8 items-center justify-center rounded-md bg-red-600 text-white"><Square className="h-3.5 w-3.5 fill-current" /></button>
              ) : (
                <button type="submit" disabled={!draft.trim() || (mode === 'cowork' && !projectId)} title="Send" aria-label="Send"
                  className="flex h-8 w-8 items-center justify-center rounded-md bg-red-600 text-white disabled:opacity-40"><Send className="h-4 w-4" /></button>
              )}
            </div>
          </div>
        </form>
      </section>

      {mode === 'cowork' && (
        <aside className="flex min-h-0 flex-col border-t lg:border-l lg:border-t-0" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
          <div className="flex items-center justify-between border-b p-3" style={{ borderColor: 'var(--rc-border)' }}>
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}><Folder className="h-4 w-4 text-red-500" />Project files</div>
              {nativeWorkspace?.connected && <div className="mt-0.5 max-w-40 truncate text-[10px] text-green-600" title={nativeWorkspace.name}>Local folder: {nativeWorkspace.name}</div>}
            </div>
            <div className="flex items-center gap-1">
              <input ref={fileInput} type="file" multiple className="hidden" onChange={ingestFiles} />
              <input ref={folderInput} type="file" multiple className="hidden" onChange={ingestFiles} />
              <button type="button" onClick={startNewFile} disabled={!projectId || uploading} title="Create file" aria-label="Create file"
                className="flex h-8 w-8 items-center justify-center rounded-md disabled:opacity-40"><FilePlus2 className="h-4 w-4" /></button>
              <button type="button" onClick={() => fileInput.current?.click()} disabled={!projectId || uploading} title="Add files" aria-label="Add files"
                className="flex h-8 w-8 items-center justify-center rounded-md disabled:opacity-40"><Paperclip className="h-4 w-4" /></button>
              <button type="button" onClick={openFolderPicker} disabled={uploading} title={projectId ? 'Import folder' : 'Choose folder and create project'} aria-label="Import folder"
                className="flex h-8 w-8 items-center justify-center rounded-md disabled:opacity-40">{uploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FolderPlus className="h-4 w-4" />}</button>
              {nativeWorkspace?.connected && <button type="button" onClick={() => void syncNativeFolder()} disabled={uploading} title="Sync local folder" aria-label="Sync local folder"
                className="flex h-8 w-8 items-center justify-center rounded-md disabled:opacity-40">{uploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCcw className="h-4 w-4" />}</button>}
            </div>
          </div>
          {proposals.length > 0 && (
            <div className="max-h-64 overflow-y-auto border-b p-2" style={{ borderColor: 'var(--rc-border)' }}>
              <div className="mb-2 flex items-center gap-2 px-1 text-xs font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                <Wrench className="h-3.5 w-3.5 text-amber-500" />Changes awaiting review
              </div>
              <div className="space-y-1.5">
                {proposals.map((proposal) => (
                  <details key={proposal.id} className="rounded-md border p-2" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-base)' }}>
                    <summary className="cursor-pointer list-none">
                      <div className="flex items-center gap-2">
                        <span className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase text-amber-700 dark:text-amber-300" style={{ background: 'rgba(245,158,11,.14)' }}>{proposal.operation}</span>
                        <span className="min-w-0 flex-1 truncate text-[11px]" title={proposal.path} style={{ color: 'var(--rc-text-2)' }}>{proposal.path}</span>
                      </div>
                    </summary>
                    <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap border-t pt-2 text-[9px] leading-4" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}>
                      {proposal.operation === 'delete' ? proposal.current_content : proposal.proposed_content}
                    </pre>
                    <div className="mt-2 flex justify-end gap-1.5">
                      <button type="button" onClick={() => void reviewProposal(proposal, 'reject')} disabled={reviewingProposal === proposal.id}
                        className="flex h-7 items-center gap-1 rounded border px-2 text-[10px] disabled:opacity-50" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}><X className="h-3 w-3" />Reject</button>
                      <button type="button" onClick={() => void reviewProposal(proposal, 'approve')} disabled={reviewingProposal === proposal.id}
                        className="flex h-7 items-center gap-1 rounded bg-green-600 px-2 text-[10px] text-white disabled:opacity-50"><Check className="h-3 w-3" />Apply</button>
                    </div>
                  </details>
                ))}
              </div>
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-y-auto">
            {preview || creatingFile ? (
              <div className="flex h-full flex-col">
                <div className="flex items-center justify-between border-b p-3" style={{ borderColor: 'var(--rc-border)' }}>
                  <div className="min-w-0 flex-1">
                    <input value={newFilePath} onChange={(event) => setNewFilePath(event.target.value.slice(0, 1024))}
                      placeholder="folder/file.md" aria-label={creatingFile ? 'New file path' : 'File path'}
                      className="h-8 w-full rounded border px-2 text-xs outline-none"
                      style={{ background: 'var(--rc-bg)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} />
                    {!creatingFile && <div className="text-[10px]" style={{ color: 'var(--rc-text-3)' }}>v{preview?.version} · {preview?.size_bytes} bytes · edit path to move</div>}
                  </div>
                  <div className="ml-2 flex items-center gap-1">
                    {!creatingFile && <button type="button" onClick={removeFile} aria-label="Move file to trash" title="Move file to trash"><Trash2 className="h-4 w-4" /></button>}
                    <button type="button" onClick={() => void saveFile()} disabled={savingFile || (creatingFile && !newFilePath.trim())} aria-label="Save file" title="Save file"
                      className="flex h-7 w-7 items-center justify-center disabled:opacity-40">{savingFile ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}</button>
                    <button type="button" onClick={closeEditor} aria-label="Close editor"><X className="h-4 w-4" /></button>
                  </div>
                </div>
                <textarea value={editorContent} onChange={(event) => setEditorContent(event.target.value.slice(0, 1_000_000))}
                  aria-label="File content" spellCheck={false}
                  className="min-h-0 flex-1 resize-none bg-transparent p-3 font-mono text-[11px] leading-5 outline-none"
                  style={{ color: 'var(--rc-text-2)' }} />
              </div>
            ) : artifacts.length ? (
              <div className="p-2">
                {artifacts.map((artifact) => {
                  const depth = Math.min(4, artifact.path.split('/').length - 1);
                  return (
                    <div key={artifact.id} className="group flex items-center gap-1 rounded px-1 py-1 hover:bg-black/5 dark:hover:bg-white/5" style={{ paddingLeft: `${4 + depth * 12}px` }}>
                      <button type="button" onClick={() => toggleArtifact(artifact.id)} aria-label={`${selectedArtifacts.has(artifact.id) ? 'Remove' : 'Add'} ${artifact.path} context`}
                        className="flex h-5 w-5 shrink-0 items-center justify-center rounded border" style={{ borderColor: selectedArtifacts.has(artifact.id) ? '#dc2626' : 'var(--rc-border)', background: selectedArtifacts.has(artifact.id) ? '#dc2626' : 'transparent', color: 'white' }}>
                        {selectedArtifacts.has(artifact.id) && <Check className="h-3 w-3" />}
                      </button>
                      <File className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                      <button type="button" onClick={() => void previewArtifact(artifact)} className="min-w-0 flex-1 truncate text-left text-xs" title={artifact.path} style={{ color: 'var(--rc-text-2)' }}>{artifact.path}</button>
                      <span className="text-[9px]" style={{ color: 'var(--rc-text-3)' }}>v{artifact.version}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-5 text-center">
                <FolderOpen className="mx-auto h-7 w-7" style={{ color: 'var(--rc-text-3)' }} />
                <p className="mt-3 text-xs leading-5" style={{ color: 'var(--rc-text-3)' }}>{projectId ? 'Import files or a folder. Text files are encrypted and versioned.' : 'Choose a local folder to create a matching Cowork project.'}</p>
              </div>
            )}
          </div>
        </aside>
      )}
      {researchOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4" role="presentation"
          onMouseDown={(event) => { if (event.target === event.currentTarget && !researching) setResearchOpen(false); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="research-dialog-title" className="w-full max-w-xl rounded-lg border p-5 shadow-2xl"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="research-dialog-title" className="flex items-center gap-2 text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                  <Globe2 className="h-4 w-4 text-red-500" />Governed research
                </h2>
                <p className="mt-1 text-xs leading-5" style={{ color: 'var(--rc-text-3)' }}>
                  Public HTTPS sources are checked by Trust Fabric, SSRF defenses, and prompt-injection scanning before any Brain sees them.
                </p>
              </div>
              <button type="button" onClick={() => setResearchOpen(false)} disabled={researching} aria-label="Close research"><X className="h-4 w-4" /></button>
            </div>
            <label className="mt-4 block text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>
              Question
              <textarea value={researchQuestion} onChange={(event) => setResearchQuestion(event.target.value.slice(0, 4000))} rows={3}
                placeholder="What should Enkstein investigate across these sources?" autoFocus
                className="mt-1 w-full resize-none rounded-md border p-3 text-sm outline-none"
                style={{ background: 'var(--rc-bg)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} />
            </label>
            <label className="mt-3 block text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>
              Source URLs, one per line
              <textarea value={researchUrls} onChange={(event) => setResearchUrls(event.target.value)} rows={5}
                placeholder={'https://example.com/report\nhttps://example.org/advisory'}
                className="mt-1 w-full resize-none rounded-md border p-3 font-mono text-xs outline-none"
                style={{ background: 'var(--rc-bg)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} />
            </label>
            <div className="mt-4 flex items-center justify-between gap-3">
              <span className="text-[11px]" style={{ color: 'var(--rc-text-3)' }}>Up to 8 sources · 512 KB each · no redirects or private networks</span>
              <button type="button" onClick={() => void runResearch()}
                disabled={researching || !researchQuestion.trim() || !researchUrls.trim()}
                className="inline-flex h-9 items-center gap-2 rounded-md bg-red-600 px-3 text-sm text-white disabled:opacity-40">
                {researching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe2 className="h-4 w-4" />}Research
              </button>
            </div>
          </section>
        </div>
      )}
      {dialog && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !dialogBusy) setDialog(null); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="workspace-dialog-title" className="w-full max-w-md rounded-lg border p-5 shadow-2xl"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="workspace-dialog-title" className="text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                  {dialog.kind === 'move-conversation' ? 'Move conversation' : dialog.kind === 'trash-file' ? 'Move file to trash' : dialog.kind === 'rename-conversation' ? 'Rename conversation' : 'Archive conversation'}
                </h2>
                <p className="mt-2 text-sm leading-6" style={{ color: 'var(--rc-text-3)' }}>
                  {dialog.kind === 'move-conversation'
                    ? `Choose the Cowork project for “${dialog.conversation.title}”.`
                    : dialog.kind === 'trash-file'
                      ? `${dialog.artifact.path} will leave the active project but remain recoverable.`
                      : dialog.kind === 'rename-conversation'
                        ? `Choose a new title for “${dialog.conversation.title}”.`
                        : `“${dialog.conversation.title}” will leave your active history but remain recoverable.`}
                </p>
              </div>
              <button type="button" onClick={() => setDialog(null)} disabled={dialogBusy} aria-label="Close dialog"><X className="h-4 w-4" /></button>
            </div>
            {dialog.kind === 'move-conversation' && (
              <select value={moveProjectId} onChange={(event) => setMoveProjectId(event.target.value)} autoFocus aria-label="Destination project"
                className="mt-4 h-10 w-full rounded-md border px-3 text-sm outline-none"
                style={{ background: 'var(--rc-bg)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                <option value="">Select a project</option>
                {projects.filter((project) => project.id !== dialog.conversation.project_id).map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
              </select>
            )}
            {dialog.kind === 'rename-conversation' && (
              <input value={renameTitle} onChange={(event) => setRenameTitle(event.target.value.slice(0, 255))} autoFocus aria-label="Conversation title"
                onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); void completeDialog(); } }}
                className="mt-4 h-10 w-full rounded-md border px-3 text-sm outline-none"
                style={{ background: 'var(--rc-bg)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} />
            )}
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" onClick={() => setDialog(null)} disabled={dialogBusy} className="h-9 rounded-md border px-3 text-sm" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>Cancel</button>
              <button type="button" onClick={() => void completeDialog()}
                disabled={dialogBusy || (dialog.kind === 'move-conversation' && !moveProjectId) || (dialog.kind === 'rename-conversation' && !renameTitle.trim())}
                className="inline-flex h-9 items-center gap-2 rounded-md bg-red-600 px-3 text-sm text-white disabled:opacity-40">
                {dialogBusy && <Loader2 className="h-4 w-4 animate-spin" />}{dialog.kind === 'move-conversation' ? 'Move' : dialog.kind === 'trash-file' ? 'Move to trash' : dialog.kind === 'rename-conversation' ? 'Rename' : 'Archive'}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function GovernanceRecord({ message }: { message: CortexMessageRecord }) {
  const governance = message.governance || {};
  const routing = governance.routing as { strategy?: string; reason?: string } | undefined;
  const votes = Array.isArray(governance.votes) ? governance.votes : [];
  const citations = Array.isArray(governance.citations) ? governance.citations : [];
  const allowed = governance.outcome === 'allowed';
  return (
    <div className="min-w-0 text-[11px]" style={{ color: 'var(--rc-text-3)' }}>
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        <span className="inline-flex items-center gap-1" style={{ color: allowed ? '#16a34a' : '#d97706' }}>
          {allowed ? <CheckCircle2 className="h-3.5 w-3.5" /> : <AlertTriangle className="h-3.5 w-3.5" />}
          {(governance.outcome || 'recorded').replaceAll('_', ' ')}
        </span>
        <span title={routing?.reason}>{routing?.strategy === 'adaptive' ? 'auto → ' : ''}{message.source || 'no Brain'}</span>
        {message.model && <span className="truncate">{message.model}</span>}
        {typeof governance.risk_score === 'number' && <span>risk {Math.round(governance.risk_score)}</span>}
        {governance.input_redacted && <span className="text-amber-500">input redacted</span>}
      </div>
      {votes.length > 1 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-red-500">{votes.filter((vote: any) => vote.counted).length}/{votes.length} Brain results · {governance.agreement || 'agreement pending'}</summary>
          <div className="mt-1.5 space-y-1">
            {votes.map((vote: any) => (
              <div key={vote.source} className="flex flex-wrap items-center gap-x-2 rounded border px-2 py-1" style={{ borderColor: 'var(--rc-border)' }}>
                <span style={{ color: vote.counted ? '#16a34a' : '#d97706' }}>{vote.counted ? 'completed' : 'unavailable'}</span>
                <span>{vote.source}</span>
                {vote.model && <span>{vote.model}</span>}
                {typeof vote.latency_ms === 'number' && <span>{vote.latency_ms}ms</span>}
                {vote.reason && <span className="truncate" title={vote.reason}>{vote.reason}</span>}
              </div>
            ))}
          </div>
        </details>
      )}
      {citations.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-red-500">{citations.length} governed citation{citations.length === 1 ? '' : 's'}</summary>
          <div className="mt-1.5 space-y-1">
            {citations.map((citation: any) => (
              <a key={`${citation.id}-${citation.content_digest}`} href={citation.url} target="_blank" rel="noreferrer"
                className="flex items-center gap-2 rounded border px-2 py-1 hover:text-red-500" style={{ borderColor: 'var(--rc-border)' }}>
                <span>[{citation.id}]</span><span className="min-w-0 flex-1 truncate">{citation.title}</span><ExternalLink className="h-3 w-3 shrink-0" />
              </a>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
