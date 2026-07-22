'use client';

import {
  ChangeEvent,
  FormEvent,
  KeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useRouter } from 'next/navigation';
import {
  AlertTriangle,
  Archive,
  Bot,
  Zap,
  BrainCircuit,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Ban,
  ClipboardCopy,
  Copy,
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
  RotateCcw,
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
  ContextManifest,
  CortexArtifact,
  CortexCodexApproval,
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
  getCortexCodexStatus,
  getCortexConversations,
  getCortexProjects,
  getCortexNativeWorkspace,
  getModelClawProfiles,
  ingestCortexArtifacts,
  moveCortexConversation,
  permanentlyDeleteCortexConversation,
  reopenCortexConversation,
  reviewCortexChangeProposal,
  runCortexResearch,
  startCortexCodex,
  sendCortexCodexTurn,
  decideCortexCodexApproval,
  cancelCortexCodex,
  streamCortexTurn,
  syncCortexNativeWorkspace,
  updateCortexArtifact,
} from '@/lib/api';
import SafeMarkdown from '@/components/markdown/SafeMarkdown';
import CodeBlock from '@/components/markdown/CodeBlock';
import { persistRuntimeGroup, readStoredRuntimeGroup, RuntimeGroup } from '@/lib/runtime-group';
import { persistCustomSwarm, readStoredCustomSwarm } from '@/lib/custom-swarm';
import { consumeForceNewProjectIntent } from '@/lib/native-folder-intent';
import { allFolderPaths, buildFileTree, type FileTreeNode } from '@/lib/file-tree';
import { useCopyToClipboard } from '@/lib/use-copy-to-clipboard';
import {
  persistLastActiveConversation,
  readLastActiveConversation,
  workspaceModeBasePath,
  workspaceRoutePath,
} from '@/lib/workspace-routes';

declare global {
  interface Window {
    marcellusNativeWorkspace?: { selectFolder: () => void };
  }
}

type Mode = 'chat' | 'cowork' | 'security';

type TurnFailureKind = 'failed' | 'timeout' | 'interrupted';
type TurnFailure = { content: string; kind: TurnFailureKind; detail: string };

/** Maps a terminal turn error message to a compact operational state so the UI
 * can present failed / timeout / interrupted turns distinctly. The strings come
 * from the governed backend events (turn_failed / turn_timeout) and the idle
 * stream guard in streamCortexTurn. */
function classifyTurnFailure(detail: string): TurnFailureKind {
  const text = detail.toLowerCase();
  if (text.includes('timed out') || text.includes('timeout') || text.includes('deadline') || text.includes('stalled')) return 'timeout';
  if (text.includes('interrupted') || text.includes('cancelled') || text.includes('canceled')) return 'interrupted';
  return 'failed';
}

type ModelOption = { id: string; label: string };
type SourceOption = { value: string; label: string; ready: boolean; detail?: string; models: ModelOption[] };
type WorkspaceDialog =
  | { kind: 'archive-conversation'; conversation: CortexConversation }
  | { kind: 'delete-conversation'; conversation: CortexConversation }
  | { kind: 'move-conversation'; conversation: CortexConversation }
  | { kind: 'rename-conversation'; conversation: CortexConversation }
  | { kind: 'trash-file'; artifact: CortexArtifact };

const BASE_SOURCES: SourceOption[] = [
  { value: 'auto', label: 'Auto Brain', ready: true, detail: 'First available policy-approved Brain', models: [] },
  { value: 'consensus', label: 'Multi-Brain Swarm', ready: true, detail: 'Available Brains work concurrently and preserve dissent', models: [] },
  {
    value: 'custom_swarm',
    label: 'Build a Swarm…',
    ready: true,
    detail: 'Pick any mix of browser, subscription, API, and local Brains to run this turn concurrently.',
    models: [],
  },
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

/** Groups a Brain source into the swarm-picker's category so the picker
 * reads like "one browser, one API, one local" rather than a flat list.
 * Purely presentational: the actual runtime/governance grouping (local vs
 * hybrid vs cloud) remains the existing runtime_group axis and is
 * unaffected by this categorization. */
function swarmSourceKind(value: string): 'browser' | 'subscription' | 'local' | 'api' {
  if (value.endsWith('_browser')) return 'browser';
  if (value.endsWith('_subscription') || value.endsWith('_desktop')) return 'subscription';
  if (value === 'profile:ollama_local_fallback' || value === 'profile:gemma_scanner') return 'local';
  return 'api';
}

const SWARM_KIND_LABELS: Record<ReturnType<typeof swarmSourceKind>, string> = {
  browser: 'Browser Companion sessions',
  subscription: 'Subscription CLIs & desktop apps',
  api: 'API & governed profiles',
  local: 'Local (on-device)',
};

export default function AIWorkspace({
  mode,
  initialProjectId,
  initialConversationId,
}: {
  mode: Mode;
  initialProjectId?: string;
  initialConversationId?: string;
}) {
  const router = useRouter();
  const [projects, setProjects] = useState<CortexProject[]>([]);
  // Chat and Cowork each organize their own conversations into lightweight
  // folders (CortexProject rows scoped by kind="chat"/"cowork"); Security has
  // no project concept. hasProjects gates every project-scoping behavior that
  // both Chat and Cowork share; folder-binding/artifacts/native sync remain
  // strictly Cowork-only below.
  const hasProjects = mode === 'cowork' || mode === 'chat';
  const [projectId, setProjectId] = useState<string>(hasProjects ? initialProjectId || '' : '');
  const [conversations, setConversations] = useState<CortexConversation[]>([]);
  const [active, setActive] = useState<CortexConversation | null>(null);
  const [messages, setMessages] = useState<CortexMessageRecord[]>([]);
  const [artifacts, setArtifacts] = useState<CortexArtifact[]>([]);
  const [proposals, setProposals] = useState<CortexChangeProposal[]>([]);
  const [selectedArtifacts, setSelectedArtifacts] = useState<Set<string>>(new Set());
  // Which folder paths in the VS Code-style tree are expanded. Reset
  // whenever the active project changes so a folder left open in one
  // project's tree never leaks into another project's tree.
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const fileTree = useMemo(() => buildFileTree(artifacts), [artifacts]);
  const expandedFoldersProjectRef = useRef<string | null>(null);
  useEffect(() => {
    const folderPaths = allFolderPaths(fileTree);
    if (expandedFoldersProjectRef.current !== projectId) {
      // A genuine project switch (including the initial artifact load,
      // which starts from an empty tree before the real files arrive):
      // start every currently-known folder expanded, VS Code-style.
      expandedFoldersProjectRef.current = projectId;
      setExpandedFolders(new Set(folderPaths));
      return;
    }
    // Same project, artifacts refreshed (e.g. a native folder sync added
    // files): expand any newly-appeared folder without touching folders the
    // operator already collapsed by hand.
    setExpandedFolders((current) => {
      const missing = folderPaths.filter((path) => !current.has(path));
      if (!missing.length) return current;
      return new Set([...Array.from(current), ...missing]);
    });
  }, [projectId, fileTree]);
  const toggleFolder = (path: string) => {
    setExpandedFolders((current) => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };
  const [preview, setPreview] = useState<CortexArtifact | null>(null);
  const [creatingFile, setCreatingFile] = useState(false);
  const [newFilePath, setNewFilePath] = useState('');
  const [editorContent, setEditorContent] = useState('');
  const [savingFile, setSavingFile] = useState(false);
  const [draft, setDraft] = useState('');
  const [source, setSource] = useState('auto');
  const [model, setModel] = useState('');
  const [sourceOptions, setSourceOptions] = useState<SourceOption[]>(BASE_SOURCES);
  // A "Build a Swarm…" selection: any mix of ready browser/subscription/
  // API/local sources the operator explicitly checks. Kept separate from
  // `source` itself so switching to/from custom_swarm never clobbers the
  // last-built list, and so it can be resumed next time the picker opens.
  const [customSwarmSources, setCustomSwarmSources] = useState<string[]>([]);
  const [swarmPickerOpen, setSwarmPickerOpen] = useState(false);
  const [swarmMinVotes, setSwarmMinVotes] = useState(1);
  useEffect(() => { setCustomSwarmSources(readStoredCustomSwarm()); }, []);
  const [classification, setClassification] = useState('internal');
  const [runtimeGroup, setRuntimeGroup] = useState<RuntimeGroup>('hybrid');

  useEffect(() => { setRuntimeGroup(readStoredRuntimeGroup()); }, []);
  const selectRuntimeGroup = (group: RuntimeGroup) => {
    setRuntimeGroup(group);
    persistRuntimeGroup(group);
  };
  const [busy, setBusy] = useState(false);
  const [agentMode, setAgentMode] = useState(mode === 'cowork');
  const [structureMode, setStructureMode] = useState<'auto' | 'smart' | 'fast'>('auto');
  const [autoApply, setAutoApply] = useState(false);
  const [streamText, setStreamText] = useState('');
  const [nativeResult, setNativeResult] = useState('');
  const [activity, setActivity] = useState<string[]>([]);
  const [codexApprovals, setCodexApprovals] = useState<CortexCodexApproval[]>([]);
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
  const [lastFailure, setLastFailure] = useState<TurnFailure | null>(null);
  const [notFound, setNotFound] = useState<string | null>(null);
  const [dialog, setDialog] = useState<WorkspaceDialog | null>(null);
  const [dialogBusy, setDialogBusy] = useState(false);
  const [moveProjectId, setMoveProjectId] = useState('');
  const [renameTitle, setRenameTitle] = useState('');
  const [reopeningId, setReopeningId] = useState<string | null>(null);
  const [archivedOpen, setArchivedOpen] = useState(false);
  const [archivedConversations, setArchivedConversations] = useState<CortexConversation[]>([]);
  const [archivedLoading, setArchivedLoading] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const draftRef = useRef<HTMLTextAreaElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const turnAbort = useRef<AbortController | null>(null);
  const nativeCodexConversation = useRef<string | null>(null);

  useEffect(() => {
    folderInput.current?.setAttribute('webkitdirectory', '');
  }, []);

  /** Pushes (or replaces, for silent same-load syncing) the URL to match the
   * conversation now active in this mode, and remembers it as this mode's
   * (and, for Cowork, this project's) last active conversation. */
  const navigateToConversation = useCallback((conversation: CortexConversation | null, opts: { replace?: boolean } = {}) => {
    // Only Cowork encodes its project into the URL (/cowork/{projectId}/...);
    // Chat's project is sidebar-organizational only, so its URL never gains a
    // project segment even though a Chat conversation may still have one.
    const targetProjectId = mode === 'cowork' ? (conversation?.project_id || projectId || undefined) : undefined;
    const path = workspaceRoutePath(mode, { projectId: targetProjectId, conversationId: conversation?.id });
    persistLastActiveConversation(mode, conversation?.id || null, targetProjectId);
    if (typeof window !== 'undefined' && window.location.pathname === path) return;
    if (opts.replace) router.replace(path);
    else router.push(path);
  }, [mode, projectId, router]);

  const loadConversations = useCallback(async (preferredId?: string) => {
    const rows = await getCortexConversations(mode, hasProjects && projectId ? projectId : undefined);
    setConversations(rows);
    const target = rows.find((item) => item.id === preferredId) || rows[0] || null;
    if (target) {
      const detail = await getCortexConversation(target.id);
      setActive(detail);
      setMessages(detail.messages);
      setSource(detail.selected_source);
      setClassification(detail.classification);
      navigateToConversation(detail, { replace: true });
    } else {
      setActive(null);
      setMessages([]);
    }
  }, [mode, navigateToConversation, projectId, hasProjects]);

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
    setNativeResult('');
    setActivity([]);
  }, [mode]);

  useEffect(() => {
    void loadProposals().catch(() => setProposals([]));
  }, [loadProposals]);

  useEffect(() => {
    let cancelled = false;
    if (mode !== 'cowork' || !projectId) {
      setNativeWorkspace(null);
      return;
    }
    void getCortexNativeWorkspace(projectId)
      .then((result) => { if (!cancelled) setNativeWorkspace(result); })
      .catch(() => { if (!cancelled) setNativeWorkspace(null); });
    return () => { cancelled = true; };
  }, [mode, projectId]);

  useEffect(() => {
    const selected = (event: Event) => {
      const detail = (event as CustomEvent<{ token?: string; name?: string }>).detail;
      if (!detail?.token || !detail.name) return;
      if (mode !== 'cowork') return;
      const forceNewProject = consumeForceNewProjectIntent();
      setUploading(true);
      setError(null);
      void (async () => {
        let targetProjectId = forceNewProject ? '' : projectId;
        if (!targetProjectId) {
          // Always create a brand-new project here rather than guessing at a
          // name match against an existing one: silently reusing an
          // unrelated older project (because it happened to share a folder
          // name) is exactly the "keeps adding on top of old projects"
          // confusion this replaces. New Project's folder picker arms
          // forceNewProject, so it always lands here with no active project.
          const project = await createCortexProject({
            name: detail.name!,
            classification: 'internal',
            default_source: 'auto',
            kind: 'cowork',
          });
          setProjects((current) => [project, ...current]);
          targetProjectId = project.id;
          window.localStorage.setItem('marcellus-cowork-project', targetProjectId);
          setProjectId(targetProjectId);
          router.push(workspaceRoutePath('cowork', { projectId: targetProjectId }));
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
  }, [mode, projectId, projects, router]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      setNotFound(null);
      try {
        const rows = hasProjects ? await getCortexProjects(mode === 'cowork' ? 'cowork' : 'chat') : [];
        if (cancelled) return;
        setProjects(rows);
        const remembered = readLastActiveConversation(mode);
        // Cowork's project comes from the URL (initialProjectId) first, since
        // it's deep-linked; Chat has no project URL segment at all, so its
        // project selection is remembered sidebar state only.
        const nextProject = hasProjects
          ? (initialProjectId || projectId || rows.find((item) => item.id === remembered.projectId)?.id || rows[0]?.id || '')
          : '';
        if (mode === 'cowork' && nextProject !== projectId) {
          setProjectId(nextProject);
          return;
        }
        if (mode === 'chat' && nextProject !== projectId) {
          setProjectId(nextProject);
        }
        if (mode === 'cowork' && initialProjectId && rows.length > 0 && !rows.some((item) => item.id === initialProjectId)) {
          setNotFound('This Cowork project was not found, was moved, or is not owned by you.');
          setConversations([]);
          setActive(null);
          setMessages([]);
          setArtifacts([]);
          setSelectedArtifacts(new Set());
          return;
        }
        const conversationRows = await getCortexConversations(mode, nextProject || undefined);
        if (cancelled) return;
        setConversations(conversationRows);

        if (initialConversationId) {
          try {
            const detail = await getCortexConversation(initialConversationId);
            if (cancelled) return;
            const modeLabel = detail.mode === 'cowork' ? 'Cowork' : detail.mode === 'security' ? 'Security' : 'Chat';
            const thisModeLabel = mode === 'cowork' ? 'Cowork' : mode === 'security' ? 'Security' : 'Chat';
            if (detail.mode !== mode) {
              setNotFound(`This conversation belongs to ${modeLabel}, not ${thisModeLabel}.`);
              setActive(null);
              setMessages([]);
            } else if (mode === 'cowork' && detail.project_id !== nextProject) {
              setNotFound('This conversation belongs to a different Cowork project.');
              setActive(null);
              setMessages([]);
            } else {
              setActive(detail);
              setMessages(detail.messages);
              setSource(detail.selected_source);
              setClassification(detail.classification);
              persistLastActiveConversation(mode, detail.id, detail.project_id || undefined);
            }
          } catch {
            if (cancelled) return;
            setNotFound('This conversation was not found, was deleted, or is not owned by you.');
            setActive(null);
            setMessages([]);
          }
        } else {
          const first = conversationRows.find((item) => item.id === remembered.conversationId) || conversationRows[0];
          if (first) {
            const detail = await getCortexConversation(first.id);
            if (cancelled) return;
            setActive(detail);
            setMessages(detail.messages);
            setSource(detail.selected_source);
            setClassification(detail.classification);
            const canonical = workspaceRoutePath(mode, {
              projectId: detail.project_id || undefined,
              conversationId: detail.id,
            });
            persistLastActiveConversation(mode, detail.id, detail.project_id || undefined);
            if (window.location.pathname !== canonical) router.replace(canonical);
          } else {
            setActive(null);
            setMessages([]);
          }
        }
        if (mode === 'cowork' && nextProject) {
          const artifactRows = await getCortexArtifacts(nextProject);
          if (cancelled) return;
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
  }, [mode, hasProjects, projectId, initialProjectId, initialConversationId, router]);

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
      // Cowork requires an active project (its native folder/artifacts are
      // project-scoped); Chat's project is optional organizational grouping,
      // so a new Chat conversation joins whichever Chat folder is currently
      // selected in the sidebar, or stays unfiled if none is selected.
      project_id: hasProjects && projectId ? projectId : undefined,
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
    setNotFound(null);
    navigateToConversation(conversation);
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
      setNotFound(null);
      navigateToConversation(detail);
    } catch (openError) {
      setError(openError instanceof Error ? openError.message : 'Conversation could not be opened.');
    } finally {
      setLoading(false);
    }
  };

  const loadArchived = useCallback(async () => {
    setArchivedLoading(true);
    try {
      const rows = await getCortexConversations(mode, hasProjects && projectId ? projectId : undefined, true);
      setArchivedConversations(rows.filter((item) => item.status === 'archived'));
    } catch {
      setArchivedConversations([]);
    } finally {
      setArchivedLoading(false);
    }
  }, [mode, projectId, hasProjects]);

  const toggleArchived = () => {
    setArchivedOpen((current) => {
      const next = !current;
      if (next) void loadArchived();
      return next;
    });
  };

  const reopenConversation = async (conversation: CortexConversation) => {
    setReopeningId(conversation.id);
    setError(null);
    try {
      const reopened = await reopenCortexConversation(conversation.id);
      setArchivedConversations((current) => current.filter((item) => item.id !== reopened.id));
      setConversations((current) => [reopened, ...current.filter((item) => item.id !== reopened.id)]);
      await openConversation(reopened);
    } catch (reopenError) {
      setError(reopenError instanceof Error ? reopenError.message : 'Conversation could not be reopened.');
    } finally {
      setReopeningId(null);
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
      if (detail.type === 'select-project' && hasProjects) {
        setProjectId(detail.id || '');
        setNotFound(null);
        if (mode === 'cowork') {
          router.push(workspaceRoutePath('cowork', { projectId: detail.id || undefined }));
        } else {
          // Chat's project is sidebar-organizational only (no URL segment).
          // Fetch directly with the newly selected id rather than calling
          // loadConversations(), which would otherwise close over the
          // pre-update projectId from this render and refetch the old scope.
          void (async () => {
            const rows = await getCortexConversations(mode, detail.id || undefined);
            setConversations(rows);
            const target = rows[0] || null;
            if (target) {
              const conversationDetail = await getCortexConversation(target.id);
              setActive(conversationDetail);
              setMessages(conversationDetail.messages);
              setSource(conversationDetail.selected_source);
              setClassification(conversationDetail.classification);
              persistLastActiveConversation(mode, conversationDetail.id, detail.id || undefined);
            } else {
              setActive(null);
              setMessages([]);
            }
          })().catch((selectError) => setError(selectError instanceof Error ? selectError.message : 'This Chat folder could not be loaded.'));
        }
      }
      if (
        (detail.type === 'request-archive-conversation'
          || detail.type === 'request-delete-conversation'
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
              : detail.type === 'request-delete-conversation'
                ? 'delete-conversation'
                : detail.type === 'request-move-conversation'
                  ? 'move-conversation'
                  : 'rename-conversation',
            conversation,
          });
        }
      }
      if (detail.type === 'request-reopen-conversation' && detail.id) {
        const conversation = conversations.find((item) => item.id === detail.id)
          || archivedConversations.find((item) => item.id === detail.id);
        if (conversation) void reopenConversation(conversation);
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

  const submit = async (event?: FormEvent, retryContent?: string) => {
    event?.preventDefault();
    const content = (retryContent ?? draft).trim();
    if (!content || busy) return;
    if (selectedArtifactBytes > 100_000) {
      setError('Selected files exceed the complete-context limit. Select fewer files so no code is truncated.');
      return;
    }
    if (source === 'custom_swarm' && customSwarmSources.length === 0) {
      setError('Build a swarm first: pick at least one Brain from the swarm picker.');
      return;
    }
    setBusy(true);
    setError(null);
    setLastFailure(null);
    setStreamText('');
    setActivity([]);
    setCodexApprovals([]);
    let keepTransientOutput = false;
    try {
      const conversation = active || await createConversation();
      if (!conversation) return;
      const controller = new AbortController();
      turnAbort.current = controller;
      // A retry replays a preserved message, so it must not disturb whatever the
      // operator may have since typed into the composer.
      if (retryContent === undefined) setDraft('');
      const useNativeCodex = mode === 'cowork'
        && agentMode
        && Boolean(nativeWorkspace?.connected)
        && runtimeGroup !== 'local'
        && (source === 'auto' || source === 'codex_subscription');
      if (useNativeCodex) {
        nativeCodexConversation.current = conversation.id;
        setActivity(['Trust Fabric is authorizing the Codex subscription CLI']);
        await startCortexCodex(conversation.id, {
          sandbox: 'workspace-write',
          runtime_group: runtimeGroup,
        });
        setActivity((current) => [...current, 'Official Codex App Server session ready']);
        const started = await sendCortexCodexTurn(conversation.id, {
          prompt: content,
          runtime_group: runtimeGroup,
        });
        if (started.policy.input_redacted) {
          setActivity((current) => [...current, 'Sensitive input redacted before CLI execution']);
        }
        let cursor = started.cursor;
        let nativeText = '';
        const deadline = Date.now() + 120_000;
        while (Date.now() < deadline) {
          if (controller.signal.aborted) throw new DOMException('Turn stopped', 'AbortError');
          const status = await getCortexCodexStatus(conversation.id, cursor);
          cursor = status.cursor;
          setCodexApprovals(status.pending_approvals);
          for (const nativeEvent of status.events) {
            const transient = nativeEvent.fields?.transient;
            if (transient?.kind === 'item/agentMessage/delta' && typeof transient.text === 'string') {
              nativeText += transient.text;
              setStreamText(nativeText);
            }
            if (transient?.kind === 'item/plan/delta' && typeof transient.text === 'string') {
              setActivity((current) => [...current.slice(-7), `Plan: ${transient.text.slice(0, 160)}`]);
            }
            if (transient?.kind === 'turn/diff/updated') {
              setActivity((current) => [...current, 'Workspace diff updated; changes remain approval-governed']);
            }
          }
          if (status.turn === 'completed') {
            keepTransientOutput = true;
            setNativeResult(nativeText || 'Codex completed without a textual response. Review the governed workspace diff and activity record.');
            setActivity((current) => [...current, 'Codex completed through the governed native bridge']);
            break;
          }
          if (status.turn === 'interrupted' || status.transport === 'interrupted') {
            throw new Error('The Codex App Server turn was interrupted. Restart the desktop bridge and retry.');
          }
          await new Promise((resolve) => window.setTimeout(resolve, 500));
        }
        if (!keepTransientOutput) {
          await cancelCortexCodex(conversation.id).catch(() => undefined);
          throw new Error('The Codex App Server turn timed out after 120 seconds and was cancelled.');
        }
        return;
      }
      // "custom_swarm" is a UI-only sentinel: the backend's consensus
      // mechanism is what actually fans a turn out across several Brains, so
      // a custom swarm submits as source="consensus" with the operator's
      // explicit source list and vote threshold instead of the Gateway's
      // own fixed default list.
      const isCustomSwarm = source === 'custom_swarm';
      const turn = await streamCortexTurn(conversation.id, {
        content,
        source: isCustomSwarm ? 'consensus' : source,
        ...(isCustomSwarm ? { consensus_sources: customSwarmSources } : {}),
        model: model || undefined,
        data_classification: classification,
        runtime_group: runtimeGroup,
        artifact_ids: Array.from(selectedArtifacts),
        include_project_files: mode === 'cowork' && selectedArtifacts.size > 0,
        minimum_votes: isCustomSwarm ? swarmMinVotes : 2,
        agent_mode: mode === 'cowork' && agentMode,
        ...(mode === 'cowork' && agentMode ? { structure_mode: structureMode, auto_apply: autoApply } : {}),
      }, ({ event: streamEvent, data }) => {
        if (streamEvent === 'turn_started') setActivity(['Planning governed turn']);
        if (streamEvent === 'context_ready') setActivity((current) => [...current, 'Workspace context prepared']);
        if (streamEvent === 'brain_completed') {
          const state = data.counted ? 'completed' : 'did not return a usable vote';
          setActivity((current) => [...current, `${data.source || 'Brain'} ${state}`]);
        }
        if (streamEvent === 'response_delta') setStreamText((current) => current + String(data.delta || ''));
        if (streamEvent === 'changes_proposed') setActivity((current) => [...current, `${data.count} file change proposal${data.count === 1 ? '' : 's'} ready for review`]);
        if (streamEvent === 'changes_applied') setActivity((current) => [...current, `${data.count} file change${data.count === 1 ? '' : 's'} applied to the local folder`]);
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
      // Auto-applied changes create/update artifacts directly, so refresh the
      // file tree to surface them without waiting for a manual reload.
      await loadArtifacts();
    } catch (requestError) {
      if (requestError instanceof Error && requestError.name === 'AbortError') {
        setActivity((current) => [...current, 'Turn stopped by operator']);
      } else {
        const detail = requestError instanceof Error ? requestError.message : 'The governed request failed.';
        // The governed backend rolls the turn back on failed/timeout/cancelled,
        // so nothing was persisted — the preserved content can be replayed as a
        // fresh turn without duplicating a submission.
        setLastFailure({ content, kind: classifyTurnFailure(detail), detail });
      }
    } finally {
      turnAbort.current = null;
      nativeCodexConversation.current = null;
      setBusy(false);
      setStreamText('');
    }
  };

  const stopTurn = () => {
    turnAbort.current?.abort();
    const conversationId = nativeCodexConversation.current;
    if (conversationId) void cancelCortexCodex(conversationId).catch(() => undefined);
  };

  /** Replays the preserved message as a brand-new governed turn on the same
   * conversation. Safe because the failed turn rolled back server-side. */
  const retryFailedTurn = () => {
    if (!lastFailure || busy) return;
    void submit(undefined, lastFailure.content);
  };

  /** Returns the preserved message to the composer so the operator can adjust
   * and continue, without clobbering anything already typed there. */
  const continueFailedTurn = () => {
    if (!lastFailure) return;
    const content = lastFailure.content;
    setLastFailure(null);
    setDraft((current) => (current.trim() ? current : content));
    requestAnimationFrame(() => draftRef.current?.focus());
  };

  const decideCodexApproval = async (approval: CortexCodexApproval, decision: 'accept' | 'decline') => {
    if (!active) return;
    try {
      await decideCortexCodexApproval(active.id, approval.approval_id, decision);
      setCodexApprovals((current) => current.filter((item) => item.approval_id !== approval.approval_id));
      setActivity((current) => [...current, `Codex ${approval.method.split('/')[1] || 'action'} ${decision}ed`]);
    } catch (approvalError) {
      setError(approvalError instanceof Error ? approvalError.message : 'The governed approval failed.');
    }
  };

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
    if (value === 'custom_swarm') setSwarmPickerOpen(true);
  };

  const toggleSwarmSource = (value: string) => {
    setCustomSwarmSources((current) => {
      const next = current.includes(value) ? current.filter((item) => item !== value) : [...current, value];
      persistCustomSwarm(next);
      return next;
    });
  };

  const confirmSwarmSelection = () => {
    setSwarmMinVotes((current) => Math.min(Math.max(current, 1), Math.max(customSwarmSources.length, 1)));
    setSwarmPickerOpen(false);
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
        // Always create fresh here too, for the same reason as the native
        // folder-picker path: silently reusing an unrelated older project by
        // name match is the confusing "old files/projects keep showing up"
        // behavior this replaces.
        const project = await createCortexProject({
          name: folderName,
          classification: 'internal',
          default_source: 'auto',
          kind: 'cowork',
        });
        setProjects((current) => [project, ...current]);
        targetProjectId = project.id;
        window.localStorage.setItem('marcellus-cowork-project', targetProjectId);
        setProjectId(targetProjectId);
        router.push(workspaceRoutePath('cowork', { projectId: targetProjectId }));
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
      navigateToConversation(branch);
    } catch (branchError) {
      setError(branchError instanceof Error ? branchError.message : 'Conversation could not be branched.');
    } finally {
      setBusy(false);
    }
  };

  const { copied: chatCopied, copy: copyChat } = useCopyToClipboard();
  const copyWholeChat = () => {
    const transcript = messages
      .map((message) => `${message.role === 'user' ? 'You' : 'Enkstein'}:\n${message.content}`)
      .join('\n\n---\n\n');
    void copyChat(transcript);
  };

  const completeDialog = async () => {
    if (!dialog || dialogBusy) return;
    setDialogBusy(true);
    setError(null);
    try {
      if (dialog.kind === 'archive-conversation') {
        await archiveCortexConversation(dialog.conversation.id);
        await loadConversations();
        setArchivedConversations((current) => [dialog.conversation, ...current.filter((item) => item.id !== dialog.conversation.id)]);
        if (active?.id === dialog.conversation.id) {
          setActive(null);
          setMessages([]);
          navigateToConversation(null, { replace: true });
        }
      } else if (dialog.kind === 'delete-conversation') {
        await permanentlyDeleteCortexConversation(dialog.conversation.id);
        setConversations((current) => current.filter((item) => item.id !== dialog.conversation.id));
        setArchivedConversations((current) => current.filter((item) => item.id !== dialog.conversation.id));
        if (active?.id === dialog.conversation.id) {
          setActive(null);
          setMessages([]);
          navigateToConversation(null, { replace: true });
        }
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
        setConversations((current) => current.filter((item) => item.id !== dialog.conversation.id));
        if (mode === 'cowork') setProjectId(moveProjectId);
        router.push(workspaceRoutePath('cowork', { projectId: moveProjectId, conversationId: moved.id }));
        persistLastActiveConversation('cowork', moved.id, moveProjectId);
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
              title={source === 'custom_swarm'
                ? `Custom swarm: ${customSwarmSources.length} Brain${customSwarmSources.length === 1 ? '' : 's'} selected`
                : sourceOptions.find((item) => item.value === source)?.detail}
              className="h-8 rounded-md border px-2 text-xs outline-none" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
              {sourceOptions.map((option) => <option key={option.value} value={option.value} disabled={!option.ready}>{option.label}{option.ready ? '' : ' — unavailable'}</option>)}
            </select>
            {source === 'custom_swarm' && (
              <button type="button" onClick={() => setSwarmPickerOpen(true)} title="Edit swarm selection"
                className="inline-flex h-8 items-center gap-1.5 rounded-md border px-2 text-xs"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}>
                <Bot className="h-3.5 w-3.5 text-red-500" />{customSwarmSources.length} Brain{customSwarmSources.length === 1 ? '' : 's'}
              </button>
            )}
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
            {mode === 'cowork' && agentMode && (
              <select
                value={structureMode}
                onChange={(event) => setStructureMode(event.target.value as 'auto' | 'smart' | 'fast')}
                title="How the agent turns a Brain's answer into file changes"
                aria-label="File structuring mode"
                className="h-8 rounded-md border px-2 text-xs"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}
              >
                <option value="auto">Auto structure</option>
                <option value="smart">Smart (strict protocol)</option>
                <option value="fast">Fast (code blocks)</option>
              </select>
            )}
            {mode === 'cowork' && agentMode && (
              <label
                className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-md border px-2 text-xs"
                title={nativeWorkspace?.connected
                  ? 'Write changes straight into the connected local folder instead of pending review'
                  : 'Connect a local folder to enable auto-apply; changes stay pending review until then'}
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}
              >
                <input type="checkbox" checked={autoApply} onChange={(event) => setAutoApply(event.target.checked)} className="h-3.5 w-3.5 accent-red-600" />
                <Zap className="h-3.5 w-3.5 text-red-500" />Auto-apply
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
            {active && messages.length > 0 && (
              <button type="button" onClick={copyWholeChat} title={chatCopied ? 'Chat copied' : 'Copy whole chat'} aria-label={chatCopied ? 'Whole chat copied to clipboard' : 'Copy whole chat to clipboard'}
                className="flex h-8 w-8 items-center justify-center rounded-md border" style={{ borderColor: 'var(--rc-border)', color: chatCopied ? '#16a34a' : 'var(--rc-text-3)' }}>
                {chatCopied ? <Check className="h-4 w-4" /> : <ClipboardCopy className="h-4 w-4" />}
              </button>
            )}
            {active && <button type="button" onClick={() => { setRenameTitle(active.title); setDialog({ kind: 'rename-conversation', conversation: active }); }} title="Rename conversation" aria-label="Rename conversation"
              className="flex h-8 w-8 items-center justify-center rounded-md border" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}><Pencil className="h-4 w-4" /></button>}
            {active && <button type="button" onClick={() => setDialog({ kind: 'archive-conversation', conversation: active })} title="Archive conversation" aria-label="Archive conversation"
              className="flex h-8 w-8 items-center justify-center rounded-md border" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}><Trash2 className="h-4 w-4" /></button>}
          </div>
        </header>

        <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-6 md:px-8">
          {!messages.length && !busy && !nativeResult && !lastFailure ? (
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
                  <div className={message.role === 'user' ? 'max-w-[82%] rounded-2xl px-4 py-3' : 'w-full min-w-0'}
                    style={message.role === 'user' ? { background: 'var(--rc-bg-elevated)' } : undefined}>
                    {message.role === 'assistant'
                      ? <SafeMarkdown content={message.content} />
                      : <p className="whitespace-pre-wrap text-sm leading-7" style={{ color: 'var(--rc-text-1)' }}>{message.content}</p>}
                    <div className={`mt-3 flex items-center gap-3 ${message.role === 'assistant' ? 'justify-between' : 'justify-end'}`}>
                      {message.role === 'assistant' && <GovernanceRecord message={message} />}
                      <div className="flex items-center gap-1">
                        <MessageCopyButton content={message.content} />
                        {message.role === 'assistant' && (
                          <button type="button" onClick={() => void branchAt(message)} title="Branch from here" aria-label="Branch from here"
                            className="invisible flex h-7 w-7 shrink-0 items-center justify-center rounded group-hover:visible" style={{ color: 'var(--rc-text-3)' }}>
                            <GitBranch className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
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
                  {streamText && <SafeMarkdown content={streamText} />}
                  {codexApprovals.map((approval) => (
                    <div key={approval.approval_id} className="rounded-lg border p-3 text-xs" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
                      <div className="font-medium" style={{ color: 'var(--rc-text-1)' }}>
                        Codex requests {approval.method.includes('commandExecution') ? 'command execution' : approval.method.includes('fileChange') ? 'a file change' : 'additional permissions'}
                      </div>
                      {approval.detail.command && (
                        <div className="mt-2">
                          <CodeBlock language="bash" value={approval.detail.command} compact />
                        </div>
                      )}
                      {approval.detail.reason && <p className="mt-2" style={{ color: 'var(--rc-text-3)' }}>{approval.detail.reason}</p>}
                      {approval.detail.cwd && <p className="mt-1" style={{ color: 'var(--rc-text-3)' }}>Folder: {approval.detail.cwd}</p>}
                      {approval.deny_only && <p className="mt-2 text-amber-600">This permission request is deny-only because the bridge cannot safely scope a grant.</p>}
                      <div className="mt-3 flex gap-2">
                        {!approval.deny_only && (
                          <button type="button" onClick={() => void decideCodexApproval(approval, 'accept')} className="rounded bg-red-600 px-2.5 py-1.5 text-white">Approve once</button>
                        )}
                        <button type="button" onClick={() => void decideCodexApproval(approval, 'decline')} className="rounded border px-2.5 py-1.5" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>Decline</button>
                      </div>
                    </div>
                  ))}
                </article>
              )}
              {!busy && nativeResult && (
                <article className="rounded-lg border p-4" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
                  <div className="mb-2 flex items-center gap-2 text-[11px]" style={{ color: 'var(--rc-text-3)' }}>
                    <ShieldCheck className="h-3.5 w-3.5 text-green-600" />Codex subscription CLI · native App Server · Trust Fabric governed
                  </div>
                  <SafeMarkdown content={nativeResult} />
                </article>
              )}
              {!busy && lastFailure && (
                <TurnFailureBlock
                  failure={lastFailure}
                  onRetry={retryFailedTurn}
                  onContinue={continueFailedTurn}
                  onDismiss={() => setLastFailure(null)}
                />
              )}
            </div>
          )}
        </div>

        <form onSubmit={submit} className="px-3 py-3 md:px-6">
          {error && <div className="mx-auto mb-2 flex max-w-3xl items-center gap-2 text-xs text-red-500"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</div>}
          {selectedArtifacts.size > 0 && (
            <div className="mx-auto mb-2 flex max-w-3xl flex-wrap items-center gap-1.5 text-xs" style={{ color: selectedArtifactBytes > 100_000 ? '#dc2626' : 'var(--rc-text-3)' }}>
              <Paperclip className="h-3.5 w-3.5" /> {selectedArtifacts.size} complete file{selectedArtifacts.size === 1 ? '' : 's'} ·{' '}
              {selectedArtifactBytes.toLocaleString()} chars / {Math.ceil(selectedArtifactBytes / 1024)} KB · ~{Math.ceil(selectedArtifactBytes / 4).toLocaleString()} tokens ·{' '}
              {selectedArtifactBytes.toLocaleString()} / 100,000 char budget
              <button type="button" onClick={() => setSelectedArtifacts(new Set())} className="ml-1 text-red-500">clear</button>
            </div>
          )}
          <div className="mx-auto max-w-3xl rounded-2xl border p-2 shadow-sm"
            style={{ background: mode === 'chat' ? 'var(--rc-chat-panel)' : 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <textarea ref={draftRef} value={draft} onChange={(event) => setDraft(event.target.value.slice(0, 12000))} onKeyDown={handleKey} rows={3}
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
                    <div className="mt-2">
                      <CodeBlock
                        language={proposal.path.split('.').pop() || 'text'}
                        value={(proposal.operation === 'delete' ? proposal.current_content : proposal.proposed_content) || ''}
                        compact
                      />
                    </div>
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
                <FileTreeView
                  nodes={fileTree}
                  depth={0}
                  expandedFolders={expandedFolders}
                  onToggleFolder={toggleFolder}
                  selectedArtifacts={selectedArtifacts}
                  onToggleArtifact={toggleArtifact}
                  onPreviewArtifact={previewArtifact}
                />
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
      {swarmPickerOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4" role="presentation"
          onMouseDown={(event) => { if (event.target === event.currentTarget) setSwarmPickerOpen(false); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="swarm-picker-title" className="w-full max-w-lg rounded-lg border p-5 shadow-2xl"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="swarm-picker-title" className="text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>Build a Swarm</h2>
                <p className="mt-2 text-sm leading-6" style={{ color: 'var(--rc-text-3)' }}>
                  Pick any mix of ready Brains. Every checked Brain runs this turn concurrently; the response with enough
                  agreement wins, and dissenting answers stay visible in the governance record.
                </p>
              </div>
              <button type="button" onClick={() => setSwarmPickerOpen(false)} aria-label="Close swarm picker"><X className="h-4 w-4" /></button>
            </div>
            <div className="mt-4 max-h-72 space-y-4 overflow-y-auto pr-1">
              {(['browser', 'subscription', 'api', 'local'] as const).map((kind) => {
                const group = sourceOptions.filter((option) => option.value !== 'auto' && option.value !== 'consensus' && option.value !== 'custom_swarm' && swarmSourceKind(option.value) === kind);
                if (!group.length) return null;
                return (
                  <div key={kind}>
                    <p className="mb-1.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
                      {kind === 'browser' && <Globe2 className="h-3 w-3" />}{SWARM_KIND_LABELS[kind]}
                    </p>
                    <div className="space-y-1">
                      {group.map((option) => (
                        <label key={option.value} title={option.detail}
                          className={`flex items-center gap-2 rounded-md border px-2.5 py-2 text-xs ${option.ready ? 'cursor-pointer' : 'cursor-not-allowed opacity-50'}`}
                          style={{ borderColor: 'var(--rc-border)', background: customSwarmSources.includes(option.value) ? 'var(--rc-bg-elevated)' : 'var(--rc-bg)' }}>
                          <input type="checkbox" checked={customSwarmSources.includes(option.value)} disabled={!option.ready}
                            onChange={() => toggleSwarmSource(option.value)} className="h-3.5 w-3.5 accent-red-600" />
                          <span className="flex-1" style={{ color: 'var(--rc-text-1)' }}>{option.label}</span>
                          {customSwarmSources.includes(option.value) && <Check className="h-3.5 w-3.5 text-red-500" />}
                          {!option.ready && <span className="text-[10px]" style={{ color: 'var(--rc-text-3)' }}>unavailable</span>}
                        </label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-4 flex items-center justify-between gap-3 border-t pt-4" style={{ borderColor: 'var(--rc-border)' }}>
              <label className="flex items-center gap-2 text-xs" style={{ color: 'var(--rc-text-2)' }}>
                Minimum agreement
                <select value={swarmMinVotes} onChange={(event) => setSwarmMinVotes(Number(event.target.value))} aria-label="Minimum votes required"
                  className="h-8 rounded-md border px-2 text-xs outline-none" style={{ background: 'var(--rc-bg)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                  {Array.from({ length: Math.max(customSwarmSources.length, 1) }, (_, index) => index + 1).map((count) => (
                    <option key={count} value={count}>{count} of {Math.max(customSwarmSources.length, 1)}</option>
                  ))}
                </select>
              </label>
              <span className="text-[11px]" style={{ color: 'var(--rc-text-3)' }}>{customSwarmSources.length} selected</span>
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => { setSwarmPickerOpen(false); if (customSwarmSources.length === 0) setSource('auto'); }}
                className="h-9 rounded-md border px-3 text-sm" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>Cancel</button>
              <button type="button" onClick={confirmSwarmSelection} disabled={customSwarmSources.length === 0}
                className="inline-flex h-9 items-center gap-2 rounded-md bg-red-600 px-3 text-sm text-white disabled:opacity-40">
                Use this swarm
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

const FAILURE_PRESENTATION: Record<TurnFailureKind, { label: string; Icon: typeof AlertTriangle; accent: string }> = {
  failed: { label: 'Turn failed', Icon: AlertTriangle, accent: '#dc2626' },
  timeout: { label: 'Turn timed out', Icon: Clock, accent: '#d97706' },
  interrupted: { label: 'Turn interrupted', Icon: Ban, accent: '#d97706' },
};

/** Compact terminal-state block for a failed / timed-out / interrupted normal
 * turn. Retry replays the preserved message as a fresh governed turn; Continue
 * returns it to the composer. Neither duplicates a submission because the turn
 * rolled back server-side. */
function TurnFailureBlock({
  failure,
  onRetry,
  onContinue,
  onDismiss,
}: {
  failure: TurnFailure;
  onRetry: () => void;
  onContinue: () => void;
  onDismiss: () => void;
}) {
  const { label, Icon, accent } = FAILURE_PRESENTATION[failure.kind];
  return (
    <article role="alert" className="rounded-lg border p-3.5" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2">
          <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color: accent }} aria-hidden="true" />
          <div className="min-w-0">
            <div className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{label}</div>
            <p className="mt-0.5 text-xs leading-5" style={{ color: 'var(--rc-text-3)' }}>{failure.detail}</p>
          </div>
        </div>
        <button type="button" onClick={onDismiss} aria-label="Dismiss failure notice" title="Dismiss"
          className="shrink-0 rounded p-1" style={{ color: 'var(--rc-text-3)' }}><X className="h-3.5 w-3.5" /></button>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button type="button" onClick={onRetry} title="Re-run this turn" aria-label="Retry the failed turn"
          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-red-600 px-3 text-xs font-medium text-white">
          <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />Retry
        </button>
        <button type="button" onClick={onContinue} title="Return the message to the composer to adjust and continue"
          aria-label="Continue from the failed turn in the composer"
          className="inline-flex h-8 items-center gap-1.5 rounded-md border px-3 text-xs" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />Continue
        </button>
      </div>
    </article>
  );
}

/** Recursive VS Code-style folder tree for the Cowork "Project files" panel.
 * Folders collapse/expand independently; files show the same context
 * checkbox, path, and version the old flat list did. Rebuilt fresh from
 * `artifacts` on every render (see buildFileTree), so it can never drift
 * from what the active project's own file list actually contains. */
function FileTreeView({
  nodes,
  depth,
  expandedFolders,
  onToggleFolder,
  selectedArtifacts,
  onToggleArtifact,
  onPreviewArtifact,
}: {
  nodes: FileTreeNode[];
  depth: number;
  expandedFolders: Set<string>;
  onToggleFolder: (path: string) => void;
  selectedArtifacts: Set<string>;
  onToggleArtifact: (id: string) => void;
  onPreviewArtifact: (artifact: CortexArtifact) => void;
}) {
  const indent = 4 + Math.min(6, depth) * 14;
  return (
    <>
      {nodes.map((node) => {
        if (node.kind === 'folder') {
          const expanded = expandedFolders.has(node.path);
          return (
            <div key={node.path}>
              <button type="button" onClick={() => onToggleFolder(node.path)}
                aria-expanded={expanded} aria-label={`${expanded ? 'Collapse' : 'Expand'} ${node.name} folder`}
                className="flex w-full items-center gap-1 rounded px-1 py-1 text-left hover:bg-black/5 dark:hover:bg-white/5"
                style={{ paddingLeft: `${indent}px` }}>
                {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--rc-text-3)' }} /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--rc-text-3)' }} />}
                {expanded ? <FolderOpen className="h-3.5 w-3.5 shrink-0 text-red-500" /> : <Folder className="h-3.5 w-3.5 shrink-0 text-red-500" />}
                <span className="min-w-0 flex-1 truncate text-xs font-medium" style={{ color: 'var(--rc-text-1)' }}>{node.name}</span>
              </button>
              {expanded && (
                <FileTreeView
                  nodes={node.children}
                  depth={depth + 1}
                  expandedFolders={expandedFolders}
                  onToggleFolder={onToggleFolder}
                  selectedArtifacts={selectedArtifacts}
                  onToggleArtifact={onToggleArtifact}
                  onPreviewArtifact={onPreviewArtifact}
                />
              )}
            </div>
          );
        }
        const artifact = node.artifact;
        return (
          <div key={artifact.id} className="group flex items-center gap-1 rounded px-1 py-1 hover:bg-black/5 dark:hover:bg-white/5" style={{ paddingLeft: `${indent + 18}px` }}>
            <button type="button" onClick={() => onToggleArtifact(artifact.id)} aria-label={`${selectedArtifacts.has(artifact.id) ? 'Remove' : 'Add'} ${artifact.path} context`}
              className="flex h-5 w-5 shrink-0 items-center justify-center rounded border" style={{ borderColor: selectedArtifacts.has(artifact.id) ? '#dc2626' : 'var(--rc-border)', background: selectedArtifacts.has(artifact.id) ? '#dc2626' : 'transparent', color: 'white' }}>
              {selectedArtifacts.has(artifact.id) && <Check className="h-3 w-3" />}
            </button>
            <File className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--rc-text-3)' }} />
            <button type="button" onClick={() => void onPreviewArtifact(artifact)} className="min-w-0 flex-1 truncate text-left text-xs" title={artifact.path} style={{ color: 'var(--rc-text-2)' }}>{node.name}</button>
            <span className="text-[9px]" style={{ color: 'var(--rc-text-3)' }}>v{artifact.version}</span>
          </div>
        );
      })}
    </>
  );
}

/** Copies a single message's plain-text content to the clipboard. Shown for
 * both user and assistant turns, matching the copy-a-message affordance
 * every mainstream chat AI tool already offers. */
function MessageCopyButton({ content }: { content: string }) {
  const { copied, copy } = useCopyToClipboard();
  return (
    <button type="button" onClick={() => void copy(content)}
      title={copied ? 'Copied' : 'Copy message'} aria-label={copied ? 'Message copied to clipboard' : 'Copy message to clipboard'}
      className="invisible flex h-7 w-7 shrink-0 items-center justify-center rounded group-hover:visible" style={{ color: copied ? '#16a34a' : 'var(--rc-text-3)' }}>
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

function GovernanceRecord({ message }: { message: CortexMessageRecord }) {
  const governance = message.governance || {};
  const routing = governance.routing as { strategy?: string; reason?: string } | undefined;
  const votes = Array.isArray(governance.votes) ? governance.votes : [];
  const citations = Array.isArray(governance.citations) ? governance.citations : [];
  const contextManifest = governance.context_manifest as ContextManifest | null | undefined;
  const allowed = governance.outcome === 'allowed';
  const runtimeGroup = typeof governance.runtime_group === 'string' ? governance.runtime_group : undefined;
  const latencyMs = typeof governance.latency_ms === 'number' ? governance.latency_ms : undefined;
  const confidence = typeof governance.confidence === 'number' ? governance.confidence : undefined;
  const fallbackReason = contextManifest?.fallback_reason || undefined;
  return (
    <div className="min-w-0 text-[11px]" style={{ color: 'var(--rc-text-3)' }}>
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        <span className="inline-flex items-center gap-1" title={governance.policy_name ? `Policy: ${governance.policy_name}` : undefined} style={{ color: allowed ? '#16a34a' : '#d97706' }}>
          {allowed ? <CheckCircle2 className="h-3.5 w-3.5" /> : <AlertTriangle className="h-3.5 w-3.5" />}
          {(governance.outcome || 'recorded').replaceAll('_', ' ')}
        </span>
        <span title={routing?.reason}>{routing?.strategy === 'adaptive' ? 'auto → ' : ''}{message.source || 'no Brain'}</span>
        {message.provider && <span className="truncate">{message.provider}</span>}
        {message.model && <span className="truncate">{message.model}</span>}
        {runtimeGroup && <span title="Runtime group used for this turn">{runtimeGroup}</span>}
        {typeof confidence === 'number' && <span title="Response confidence">{Math.round(confidence * 100)}% conf</span>}
        {typeof latencyMs === 'number' && <span>{latencyMs}ms</span>}
        {typeof governance.risk_score === 'number' && <span>risk {Math.round(governance.risk_score)}</span>}
        {governance.input_redacted && <span className="text-amber-500">input redacted</span>}
        {governance.output_redacted && <span className="text-amber-500">output redacted</span>}
        {fallbackReason && <span className="text-amber-500" title={`Fallback: ${fallbackReason}`}>fallback</span>}
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
      {contextManifest && (
        <details className="mt-2">
          <summary className="cursor-pointer text-red-500">
            Context sent · {contextManifest.entries.length} file{contextManifest.entries.length === 1 ? '' : 's'} ·{' '}
            {contextManifest.total_characters_sent.toLocaleString()}/{contextManifest.budget_characters.toLocaleString()} chars ·{' '}
            ~{contextManifest.total_estimated_tokens.toLocaleString()} tokens · {contextManifest.selected_destination || contextManifest.destination}
            {contextManifest.explicit ? ' · explicit' : ' · automatic'}
            {contextManifest.effective_classification && ` · ${contextManifest.effective_classification}`}
            {contextManifest.blocked && ' · blocked'}
          </summary>
          <div className="mt-1.5 space-y-1">
            {contextManifest.blocked && contextManifest.block_reason && (
              <div className="rounded border px-2 py-1 text-amber-500" style={{ borderColor: 'var(--rc-border)' }}>{contextManifest.block_reason}</div>
            )}
            {contextManifest.attempts?.map((attempt, index) => (
              <div key={`${attempt.source}-${index}`} className="rounded border px-2 py-1" style={{ borderColor: 'var(--rc-border)' }}>
                attempt {index + 1}: {attempt.source}{attempt.provider ? ` · ${attempt.provider}` : ''}{attempt.model ? ` · ${attempt.model}` : ''}
                {' · '}{attempt.policy_outcome} · {attempt.status}{attempt.reason ? ` · ${attempt.reason}` : ''}
              </div>
            ))}
            {contextManifest.fallback_reason && (
              <div className="rounded border px-2 py-1 text-amber-500" style={{ borderColor: 'var(--rc-border)' }}>
                fallback: {contextManifest.fallback_reason}
              </div>
            )}
            {contextManifest.entries.map((entry) => (
              <div key={entry.artifact_id} className="rounded border px-2 py-1" style={{ borderColor: 'var(--rc-border)' }}>
                <div className="flex flex-wrap items-center gap-x-2">
                  <span className="min-w-0 flex-1 truncate">{entry.path}</span>
                  <span style={{ color: entry.disposition === 'sent_full' ? '#16a34a' : entry.disposition === 'blocked_by_policy' ? '#dc2626' : '#d97706' }}>
                    {entry.disposition.replaceAll('_', ' ')}
                  </span>
                  <span>{entry.characters_sent.toLocaleString()} chars</span>
                  <span>~{entry.estimated_tokens.toLocaleString()} tok</span>
                  {entry.redacted && <span className="text-amber-500">redacted</span>}
                </div>
                <div className="mt-0.5 text-[10px]" style={{ color: 'var(--rc-text-3)' }}>
                  {entry.selection_reason.replaceAll('_', ' ')}
                  {entry.citations.length > 0 &&
                    ` · lines ${entry.citations.map((citation) => `${citation.line_start}-${citation.line_end}`).join(', ')}`}
                </div>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
