'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  LayoutDashboard, Shield, Cpu, Zap, Users, FileText,
  Activity, ScrollText, Plug, AlertTriangle, Sun, Moon,
  ChevronDown, ChevronRight, ChevronLeft,
  Cloud, Key, Monitor, Globe, Database, Code, Package,
  Target, BookOpen, Eye, UserCheck, UserX,
  Bot, GitMerge, Radar, ClipboardCheck, Lock, Handshake,
  GitBranch, Settings, RefreshCcw, Network, CalendarClock, Layers, Workflow, Webhook, Sparkles,
  MessageSquare, ShoppingBag, PanelLeftClose, ShieldAlert,
  Users2, Rocket, Container, BriefcaseBusiness, ShieldCheck,
  Plus, Search, FolderPlus, Loader2, Trash2, FolderInput, BrainCircuit, Folder, Pencil, Compass,
} from 'lucide-react';
import clsx from 'clsx';
import { GLASS_LEVELS, useTheme } from '@/components/ThemeProvider';
import {
  CortexConversation,
  CortexProject,
  createCortexProject,
  getCortexConversations,
  getCortexProjects,
  searchCortexConversations,
} from '@/lib/api';
import { persistWorkspaceMode, WorkspaceMode } from '@/lib/workspace-mode';
import { workspaceModeBasePath, workspaceModeFromPath } from '@/lib/workspace-routes';
import { markNextFolderPickAsNewProject } from '@/lib/native-folder-intent';

type NavItem = {
  label: string;
  href: string;
  icon: React.ElementType;
  tag?: string;
};

type NavGroup = {
  label: string;
  defaultOpen?: boolean;
  items: NavItem[];
};

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Cortex & Hearts',
    defaultOpen: true,
    items: [
      { label: 'Mission Control',  href: '/marcellus/security', icon: Compass,        tag: 'Overview' },
      { label: 'Control Center',   href: '/control-center',   icon: Shield,           tag: 'Command' },
      { label: 'Dashboard',        href: '/dashboard',        icon: LayoutDashboard },
      { label: 'Findings',         href: '/findings',         icon: AlertTriangle,    tag: 'All Nodes' },
      { label: 'Trust Fabric',     href: '/trust-fabric',     icon: Shield },
      { label: 'CoreOS',           href: '/coreos',           icon: Cpu },
      { label: 'Policies',         href: '/policies',         icon: FileText },
      { label: 'Policy Packs',     href: '/policy-packs',     icon: Layers,           tag: 'Compliance' },
      { label: 'Zero Trust',       href: '/zero-trust',       icon: Shield,           tag: 'Coverage' },
      { label: 'Events',           href: '/events',           icon: Activity },
      { label: 'Audit',            href: '/audit',            icon: ScrollText },
      { label: 'Connectors',       href: '/connectors',       icon: Plug },
      { label: 'Agents',           href: '/agents',           icon: Bot,              tag: 'AI Ops' },
      { label: 'Schedules',        href: '/schedules',        icon: CalendarClock,    tag: 'Automation' },
      { label: 'Orchestrations',   href: '/orchestrations',   icon: Workflow,         tag: 'Workflows' },
      { label: 'Swarm',            href: '/swarm',            icon: Users2,           tag: 'Parallel' },
      { label: 'Triggers',         href: '/triggers',         icon: Webhook,          tag: 'Reactive' },
      { label: 'Autonomy',         href: '/autonomy',         icon: Shield,           tag: 'Governance' },
      { label: 'Remediation',      href: '/remediation',      icon: ShieldAlert,      tag: 'Auto-Fix' },
      { label: 'Run History',      href: '/runs',             icon: Activity,         tag: 'Replay' },
      { label: 'Aegis',            href: '/aegis',            icon: Sparkles,         tag: 'Workflow' },
      { label: 'External Agents',  href: '/external-agents',  icon: Globe,            tag: 'External' },
      { label: 'Model Router',     href: '/model-router',     icon: Cpu,              tag: 'LLM Sec' },
      { label: 'Model Cortex',     href: '/model-cortex',     icon: Sparkles,         tag: 'Profiles' },
      { label: 'Memory',           href: '/memory',           icon: Layers,           tag: 'State' },
      { label: 'Skill Packs',      href: '/skill-packs',      icon: Package,          tag: 'Skills' },
      { label: 'Connector Health', href: '/connectors/health',icon: Activity,         tag: 'Monitor' },
      { label: 'Exchange',         href: '/exchange',         icon: ShoppingBag,      tag: 'Marketplace' },
      { label: 'Channel Gateway',  href: '/channel-gateway',  icon: MessageSquare,    tag: 'ChatOps' },
      { label: 'Exec Channels',    href: '/exec-channels',    icon: Shield,           tag: 'Governed' },
    ],
  },
  {
    label: 'Capability Studio',
    defaultOpen: true,
    items: [
      { label: 'Custom Capability', href: '/capabilities/custom', icon: Plug, tag: 'Builder' },
    ],
  },
  {
    label: 'Protection Arm',
    defaultOpen: true,
    items: [
      { label: 'AI Security',          href: '/capabilities/ai-security',          icon: Zap,      tag: 'AI' },
      { label: 'Cloud Security',       href: '/capabilities/cloud-security',       icon: Cloud,    tag: 'Cloud' },
      { label: 'Identity Security',    href: '/capabilities/identity-security',    icon: Users,    tag: 'Identity' },
      { label: 'Privileged Access',    href: '/capabilities/privileged-access',    icon: Key,      tag: 'PAM' },
      { label: 'Endpoint Security',    href: '/capabilities/endpoint-security',    icon: Monitor,  tag: 'Endpoint' },
      { label: 'Network Security',     href: '/capabilities/network-security',     icon: Network,  tag: 'Network' },
      { label: 'Data Security',        href: '/capabilities/data-security',        icon: Database, tag: 'Data' },
      { label: 'Application Security', href: '/capabilities/application-security', icon: Code,     tag: 'App/API' },
      { label: 'SaaS Security',        href: '/capabilities/saas-security',        icon: Package,  tag: 'SaaS' },
    ],
  },
  {
    label: 'Detection Arm',
    defaultOpen: true,
    items: [
      { label: 'Threat Analysis',       href: '/capabilities/threat-analysis',      icon: Target,    tag: 'D&R' },
      { label: 'Security Telemetry',    href: '/capabilities/security-telemetry',   icon: BookOpen,  tag: 'SIEM' },
      { label: 'Threat Intelligence',   href: '/capabilities/threat-intelligence',  icon: Eye,       tag: 'Intel' },
      { label: 'User Risk',             href: '/capabilities/user-risk',            icon: UserCheck, tag: 'UBA' },
      { label: 'Insider Risk',          href: '/capabilities/insider-risk',         icon: UserX,     tag: 'Insider' },
    ],
  },
  {
    label: 'Response Arm',
    defaultOpen: true,
    items: [
      { label: 'Security Automation', href: '/capabilities/security-automation', icon: Bot,      tag: 'SOAR' },
      { label: 'Attack Path Analysis', href: '/capabilities/attack-path-analysis', icon: GitMerge, tag: 'Paths' },
      { label: 'Exposure Management', href: '/capabilities/exposure-management', icon: Radar,    tag: 'ASM' },
    ],
  },
  {
    label: 'Governance Arm',
    defaultOpen: true,
    items: [
      { label: 'Compliance Assurance', href: '/capabilities/compliance-assurance', icon: ClipboardCheck, tag: 'GRC' },
      { label: 'Privacy Governance',   href: '/capabilities/privacy-governance',   icon: Lock,           tag: 'Privacy' },
      { label: 'Vendor Risk',          href: '/capabilities/vendor-risk',          icon: Handshake,      tag: 'Vendor' },
    ],
  },
  {
    label: 'Engineering Arm',
    defaultOpen: true,
    items: [
      { label: 'Terraform Governance', href: '/capabilities/terraform-governance', icon: Container, tag: 'IaC Sec' },
      { label: 'Developer Security',   href: '/capabilities/developer-security', icon: GitBranch, tag: 'DevSecOps' },
      { label: 'Configuration Security', href: '/capabilities/configuration-security', icon: Settings, tag: 'Hardening' },
      { label: 'Release Governance',   href: '/capabilities/release-governance', icon: Rocket, tag: 'Deploy' },
      { label: 'Recovery Readiness',   href: '/capabilities/recovery-readiness', icon: RefreshCcw,tag: 'Resilience' },
    ],
  },
];

const WORKSPACE_MODES: Array<{ id: WorkspaceMode; label: string; icon: React.ElementType }> = [
  { id: 'chat', label: 'Chat', icon: MessageSquare },
  { id: 'cowork', label: 'Cowork', icon: BriefcaseBusiness },
  { id: 'security', label: 'Security', icon: ShieldCheck },
];

function WorkspaceSwitch({ mode, collapsed, onModeChange }: { mode: WorkspaceMode; collapsed: boolean; onModeChange: (mode: WorkspaceMode) => void }) {
  return (
    <div className={clsx('border-b', collapsed ? 'px-2 py-2' : 'px-3 py-3')} style={{ borderColor: 'var(--rc-border)' }}>
      {!collapsed && (
        <p className="mb-2 px-1 text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'var(--rc-text-3)' }}>
          Workspace
        </p>
      )}
      <div
        className={clsx('grid gap-1 rounded-md border p-1', collapsed ? 'grid-cols-1' : 'grid-cols-3')}
        style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-base)' }}
      >
        {WORKSPACE_MODES.map(({ id, label, icon: Icon }) => {
          const active = mode === id;
          return (
            <button
              key={id}
              type="button"
              title={label}
              aria-current={active ? 'page' : undefined}
              onClick={() => onModeChange(id)}
              className={clsx(
                'flex min-h-10 items-center justify-center rounded transition-colors',
                collapsed ? 'w-10' : 'min-w-0 flex-col gap-1 px-1 py-1.5',
                active ? 'bg-regent-600 text-white' : 'hover:bg-[var(--rc-bg-elevated)]',
              )}
              style={active ? {} : { color: 'var(--rc-text-2)' }}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="w-full truncate text-center text-[10px] font-medium">{label}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}

type WorkspaceStateDetail = {
  mode: 'chat' | 'cowork';
  conversations: CortexConversation[];
  projects: CortexProject[];
  activeConversationId?: string;
  projectId?: string;
  nativeWorkspaceName?: string;
};

function dispatchWorkspaceAction(detail: { type: 'new-conversation' | 'open-conversation' | 'select-project' | 'request-archive-conversation' | 'request-move-conversation' | 'request-rename-conversation'; id?: string }) {
  window.dispatchEvent(new CustomEvent('marcellus:workspace-action', { detail }));
}

// Chat's remembered project uses its own key so selecting a Chat folder can
// never clobber Cowork's remembered project (and vice versa) -- the two are
// entirely separate CortexProject kinds sharing only the same table/UI shape.
const CHAT_PROJECT_STORAGE_KEY = 'marcellus-chat-project';
const COWORK_PROJECT_STORAGE_KEY = 'marcellus-cowork-project';

function WorkspaceModeNav({ mode, collapsed }: { mode: 'chat' | 'cowork'; collapsed: boolean }) {
  const [conversations, setConversations] = useState<CortexConversation[]>([]);
  const [projects, setProjects] = useState<CortexProject[]>([]);
  const [activeConversationId, setActiveConversationId] = useState('');
  const [projectId, setProjectId] = useState('');
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);
  // Content matches come from the encrypted-message search endpoint, which the
  // local title filter cannot see. Kept separate so titles still filter
  // instantly while the network result fills in behind it.
  const [contentMatches, setContentMatches] = useState<Map<string, { conversation: CortexConversation; excerpt?: string }>>(new Map());
  const [searching, setSearching] = useState(false);
  const [creatingProject, setCreatingProject] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [nativeWorkspaceName, setNativeWorkspaceName] = useState('');
  const projectStorageKey = mode === 'chat' ? CHAT_PROJECT_STORAGE_KEY : COWORK_PROJECT_STORAGE_KEY;
  const projectLabel = mode === 'chat' ? 'Chat folder' : 'Project';

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const projectRows = await getCortexProjects(mode);
        // The blade opens unscoped so it lists every conversation, including
        // unfiled ones. Restoring a remembered project silently hid the rest.
        const selectedProject = '';
        const conversationRows = await getCortexConversations(mode, selectedProject || undefined);
        if (!cancelled) {
          setProjects(projectRows);
          setProjectId(selectedProject);
          setConversations(conversationRows);
          setActiveConversationId('');
        }
      } catch {
        if (!cancelled) {
          setProjects([]);
          setConversations([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    const sync = (event: Event) => {
      const detail = (event as CustomEvent<WorkspaceStateDetail>).detail;
      if (!detail || detail.mode !== mode) return;
      setConversations(detail.conversations);
      setProjects(detail.projects);
      setActiveConversationId(detail.activeConversationId || '');
      setProjectId(detail.projectId || '');
      setNativeWorkspaceName(detail.nativeWorkspaceName || '');
      setLoading(false);
    };
    void load();
    window.addEventListener('marcellus:workspace-state', sync);
    return () => {
      cancelled = true;
      window.removeEventListener('marcellus:workspace-state', sync);
    };
  }, [mode, projectStorageKey]);

  const selectProject = async (id: string) => {
    if (id) window.localStorage.setItem(projectStorageKey, id);
    else window.localStorage.removeItem(projectStorageKey);
    setProjectId(id);
    setActiveConversationId('');
    setLoading(true);
    try {
      setConversations(await getCortexConversations(mode, id || undefined));
    } finally {
      setLoading(false);
    }
    dispatchWorkspaceAction({ type: 'select-project', id });
  };

  const submitProject = async (event: React.FormEvent) => {
    event.preventDefault();
    const name = projectName.trim();
    if (!name) return;
    const project = await createCortexProject({ name, classification: 'internal', default_source: 'auto', kind: mode });
    setProjects((current) => [project, ...current]);
    setProjectName('');
    setCreatingProject(false);
    await selectProject(project.id);
  };

  const pickFolderForNewProject = () => {
    // Reuses the same working native-folder-picker round trip AIWorkspace
    // already uses for "Import folder" on an existing project. The native
    // round trip itself only ever returns {token, name} with no room for an
    // extra flag, so markNextFolderPickAsNewProject() arms a one-shot signal
    // AIWorkspace's listener reads when the picker resolves, telling it to
    // always create a brand-new project instead of guessing at a name match.
    if (!window.marcellusNativeWorkspace) return;
    markNextFolderPickAsNewProject();
    setCreatingProject(false);
    window.marcellusNativeWorkspace.selectFolder();
  };

  // Message-content search runs against the server because history is
  // encrypted at rest and never fully present on the client. Debounced so
  // typing does not issue a request per keystroke.
  useEffect(() => {
    const query = filter.trim();
    if (query.length < 2) {
      setContentMatches(new Map());
      setSearching(false);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const timer = window.setTimeout(async () => {
      try {
        const results = await searchCortexConversations(query);
        if (cancelled) return;
        const matches = new Map<string, { conversation: CortexConversation; excerpt?: string }>();
        for (const result of results) {
          // The endpoint is workspace-wide; this blade only ever renders one mode.
          if (result.conversation.mode !== mode) continue;
          if (!result.excerpt) continue;
          matches.set(result.conversation.id, { conversation: result.conversation, excerpt: result.excerpt });
        }
        setContentMatches(matches);
      } catch {
        if (!cancelled) setContentMatches(new Map());
      } finally {
        if (!cancelled) setSearching(false);
      }
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [filter, mode]);

  const query = filter.trim().toLowerCase();
  const titleMatches = conversations.filter((conversation) => conversation.title.toLowerCase().includes(query));
  const titleMatchIds = new Set(titleMatches.map((conversation) => conversation.id));
  const visibleConversations = query
    ? [
        ...titleMatches,
        ...Array.from(contentMatches.values())
          .filter((match) => !titleMatchIds.has(match.conversation.id))
          .map((match) => match.conversation),
      ]
    : titleMatches;

  if (collapsed) {
    return (
      <div className="space-y-1 py-1">
        <button type="button" onClick={() => dispatchWorkspaceAction({ type: 'new-conversation' })}
          className="mx-auto flex h-10 w-10 items-center justify-center rounded-lg text-white"
          style={{ background: 'var(--rc-brand)' }} title={`New ${mode === 'chat' ? 'chat' : 'Cowork conversation'}`}>
          <Plus className="h-4 w-4" />
        </button>
        {visibleConversations.slice(0, 8).map((conversation) => (
          <button key={conversation.id} type="button" title={conversation.title}
            onClick={() => dispatchWorkspaceAction({ type: 'open-conversation', id: conversation.id })}
            className={clsx('mx-auto flex h-10 w-10 items-center justify-center rounded-lg', activeConversationId === conversation.id ? 'bg-[var(--rc-bg-elevated)]' : 'hover:bg-[var(--rc-bg-elevated)]')}
            style={{ color: activeConversationId === conversation.id ? 'var(--rc-brand)' : 'var(--rc-text-2)' }}>
            {mode === 'chat' ? <MessageSquare className="h-4 w-4" /> : <BriefcaseBusiness className="h-4 w-4" />}
          </button>
        ))}
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center justify-between px-2 pb-2 pt-1">
        <div>
          <p className="text-xs font-semibold" style={{ color: 'var(--rc-text-1)' }}>{mode === 'chat' ? 'Chats' : 'Cowork'}</p>
          <p className="text-[10px]" style={{ color: 'var(--rc-text-3)' }}>{mode === 'chat' ? 'Encrypted history' : 'Projects and conversations'}</p>
        </div>
        <button type="button" onClick={() => dispatchWorkspaceAction({ type: 'new-conversation' })}
          className="flex h-8 w-8 items-center justify-center rounded-md text-white" style={{ background: 'var(--rc-brand)' }} title="New conversation" aria-label="New conversation">
          <Plus className="h-4 w-4" />
        </button>
      </div>

      <div className="border-y px-2 py-2" style={{ borderColor: 'var(--rc-border)' }}>
        <div className="mb-1.5 flex items-center justify-between">
          <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>{projectLabel}</span>
          <button type="button" onClick={() => setCreatingProject((current) => !current)} title={`New ${projectLabel.toLowerCase()}`} aria-label={`New ${projectLabel.toLowerCase()}`}>
            <FolderPlus className="h-4 w-4" style={{ color: 'var(--rc-text-3)' }} />
          </button>
        </div>
        <select value={projectId} onChange={(event) => void selectProject(event.target.value)} aria-label={mode === 'chat' ? 'Chat folder' : 'Cowork project'}
          className="h-9 w-full rounded-md border px-2 text-xs outline-none transition-colors focus:border-[var(--rc-border-2)]"
          style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-input)', color: 'var(--rc-text-1)' }}>
          <option value="">{mode === 'chat' ? 'All chats' : 'Select a project'}</option>
          {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
        </select>
        {mode === 'cowork' && nativeWorkspaceName && (
          <div className="mt-2 flex min-w-0 items-center gap-2 rounded-md border px-2 py-2"
            style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-input)' }}>
            <Folder className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--rc-brand)' }} />
            <div className="min-w-0">
              <p className="text-[9px] font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>Local folder</p>
              <p className="truncate text-xs" title={nativeWorkspaceName} style={{ color: 'var(--rc-text-1)' }}>{nativeWorkspaceName}</p>
            </div>
          </div>
        )}
        {creatingProject && (
          <div className="mt-2 space-y-1.5">
            <form onSubmit={submitProject} className="flex gap-1.5">
              <input value={projectName} onChange={(event) => setProjectName(event.target.value.slice(0, 255))} autoFocus
                placeholder={mode === 'chat' ? 'Folder name' : 'Project name'}
                className="h-8 min-w-0 flex-1 rounded-md border px-2 text-xs outline-none transition-colors focus:border-[var(--rc-border-2)]"
                style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-input)', color: 'var(--rc-text-1)' }} />
              <button type="submit" className="flex h-8 w-8 items-center justify-center rounded-md text-white transition-opacity hover:opacity-90" style={{ background: 'var(--rc-brand)' }} aria-label="Create project">
                <Plus className="h-4 w-4" />
              </button>
            </form>
            {mode === 'cowork' && (
              <button type="button" onClick={pickFolderForNewProject}
                className="flex h-8 w-full items-center justify-center gap-1.5 rounded-md border text-xs transition-colors hover:bg-[var(--rc-panel-hover)]"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
                <FolderInput className="h-3.5 w-3.5" />Pick a local folder instead
              </button>
            )}
          </div>
        )}
      </div>

      <div className="p-2">
        <Link href="/marcellus/brains"
          className="mb-2 flex h-9 items-center gap-2 rounded-md border px-2 text-xs transition-colors hover:bg-[var(--rc-bg-elevated)]"
          style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
          <BrainCircuit className="h-3.5 w-3.5" style={{ color: 'var(--rc-brand)' }} />
          <span className="flex-1">Brain Connections</span>
          <ChevronRight className="h-3.5 w-3.5" />
        </Link>
        <div className="flex items-center gap-2 rounded-md border px-2 transition-colors focus-within:border-[var(--rc-border-2)]"
          style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-input)' }}>
          {loading || searching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" style={{ color: 'var(--rc-text-3)' }} />}
          <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder={mode === 'chat' ? 'Search chats' : 'Search conversations'}
            className="h-8 min-w-0 flex-1 bg-transparent text-xs outline-none" style={{ color: 'var(--rc-text-1)' }} />
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {visibleConversations.map((conversation) => (
          <div key={conversation.id}
            className="group relative mb-0.5 flex items-center rounded-md pr-1 transition-colors hover:bg-[var(--rc-panel-hover)]"
            style={{ background: activeConversationId === conversation.id ? 'var(--rc-bg-elevated)' : 'transparent' }}>
            {activeConversationId === conversation.id && (
              <span aria-hidden className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full"
                style={{ background: 'var(--rc-brand)' }} />
            )}
            <button type="button" onClick={() => dispatchWorkspaceAction({ type: 'open-conversation', id: conversation.id })}
              className="min-w-0 flex-1 px-2.5 py-2 text-left">
              <p className="truncate text-xs font-medium" style={{ color: 'var(--rc-text-1)' }}>{conversation.title}</p>
              {contentMatches.get(conversation.id)?.excerpt
                ? <p className="mt-0.5 line-clamp-2 text-[10px] leading-4" style={{ color: 'var(--rc-text-3)' }}>{contentMatches.get(conversation.id)?.excerpt}</p>
                : <p className="mt-0.5 text-[10px] tabular-nums" style={{ color: 'var(--rc-text-3)' }}>{conversation.message_count} messages</p>}
            </button>
            <button type="button" onClick={() => dispatchWorkspaceAction({ type: 'request-rename-conversation', id: conversation.id })}
              aria-label={`Rename ${conversation.title}`} title="Rename conversation"
              className="hidden h-7 w-7 shrink-0 items-center justify-center rounded transition-colors hover:bg-[var(--rc-panel-hover)] group-hover:flex">
              <Pencil className="h-3.5 w-3.5" style={{ color: 'var(--rc-text-3)' }} />
            </button>
            {projects.length > 0 && (
              <button type="button" onClick={() => dispatchWorkspaceAction({ type: 'request-move-conversation', id: conversation.id })}
                aria-label={`Move ${conversation.title} to project`} title="Move to project"
                className="hidden h-7 w-7 shrink-0 items-center justify-center rounded transition-colors hover:bg-[var(--rc-panel-hover)] group-hover:flex">
                <FolderInput className="h-3.5 w-3.5" style={{ color: 'var(--rc-text-3)' }} />
              </button>
            )}
            <button type="button" onClick={() => dispatchWorkspaceAction({ type: 'request-archive-conversation', id: conversation.id })} aria-label={`Archive ${conversation.title}`} title="Archive conversation"
              className="hidden h-7 w-7 shrink-0 items-center justify-center rounded transition-colors hover:bg-[var(--rc-panel-hover)] group-hover:flex">
              <Trash2 className="h-3.5 w-3.5" style={{ color: 'var(--rc-text-3)' }} />
            </button>
          </div>
        ))}
        {!loading && !searching && visibleConversations.length === 0 && (
          <p className="px-2 py-4 text-xs leading-5" style={{ color: 'var(--rc-text-3)' }}>
            {query ? `No conversations match “${filter.trim()}”.` : 'No conversations yet.'}
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Sidebar group (collapsed: icons only) ────────────────────────────────────

function SidebarGroup({
  group, pathname, collapsed,
}: {
  group: NavGroup; pathname: string; collapsed: boolean;
}) {
  const hasActive = group.items.some(
    item => pathname === item.href || pathname.startsWith(item.href + '/'),
  );
  const [open, setOpen] = useState(group.defaultOpen || hasActive);

  if (collapsed) {
    // Icon-only mode — no group headers, just icon links with tooltips
    return (
      <div className="mb-1">
        {group.items.map(({ label, href, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/');
          return (
            <Link
              key={href}
              href={href}
              title={label}
              className={clsx(
                'flex items-center justify-center w-10 h-10 mx-auto rounded-lg transition-all duration-150 mb-0.5',
                active
                  ? 'bg-regent-600 text-white'
                  : 'hover:bg-[var(--rc-bg-elevated)]',
              )}
              style={active ? {} : { color: 'var(--rc-text-2)' }}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
            </Link>
          );
        })}
      </div>
    );
  }

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-2 py-1.5 mb-0.5 rounded-md text-xs font-semibold uppercase tracking-widest transition-opacity hover:opacity-80"
        style={{ color: 'var(--rc-text-3)' }}
      >
        <span className="flex-1 text-left">{group.label}</span>
        {open
          ? <ChevronDown className="w-3 h-3 opacity-60" />
          : <ChevronRight className="w-3 h-3 opacity-60" />}
      </button>

      {open && (
        <div className="space-y-0.5 mb-3">
          {group.items.map(({ label, href, icon: Icon, tag }) => {
            const active = pathname === href || pathname.startsWith(href + '/');
            return (
              <Link
                key={href}
                href={href}
                className={clsx(
                  'flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-sm transition-all duration-150',
                  active
                    ? 'bg-regent-600 text-white font-medium'
                    : 'hover:bg-[var(--rc-bg-elevated)]',
                )}
                style={active ? {} : { color: 'var(--rc-text-2)' }}
              >
                <Icon className="w-3.5 h-3.5 flex-shrink-0" />
                <span className="flex-1 truncate text-xs">{label}</span>
                {tag && (
                  <span
                    className="text-xs px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{
                      background: active ? 'rgba(255,255,255,0.2)' : 'var(--rc-bg-elevated)',
                      color: active ? 'rgba(255,255,255,0.8)' : 'var(--rc-text-3)',
                      fontSize: '9px',
                    }}
                  >
                    {tag}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Main sidebar ─────────────────────────────────────────────────────────────

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, toggle, glassLevel, setGlassLevel } = useTheme();
  const isLight   = theme === 'light';
  const isLiquid  = theme === 'liquid';
  // The canonical red/orange mark sits on a white tile, which reads as a bright
  // box against the dark console. Dark mode uses the inverse treatment: a white
  // octopus on a dark tile with identical rounded geometry.
  const sidebarLogo = theme === 'dark' ? '/enkstein-icon-dark.png' : '/enkstein-icon.png';
  const [collapsed, setCollapsed] = useState(false);
  const [runtimeVersion, setRuntimeVersion] = useState<string | null>(null);
  const [workspaceMode, setWorkspaceMode] = useState<WorkspaceMode>('security');

  useEffect(() => {
    const next = workspaceModeFromPath(pathname);
    if (!next) {
      setWorkspaceMode('security');
      return;
    }
    setWorkspaceMode(next);
    persistWorkspaceMode(next);
  }, [pathname]);

  useEffect(() => {
    let active = true;
    fetch('/runtime-info', { cache: 'no-store' })
      .then(response => response.ok ? response.json() : Promise.reject(new Error('version unavailable')))
      .then(payload => {
        if (active && typeof payload.version === 'string') {
          setRuntimeVersion(payload.version.replace(/^v/i, ''));
        }
      })
      .catch(() => {
        if (active) setRuntimeVersion(null);
      });
    return () => { active = false; };
  }, []);

  return (
    <aside
      className="min-h-screen flex flex-col border-r transition-all duration-300 flex-shrink-0"
      style={{
        width: collapsed ? '64px' : '224px',
        background: 'var(--rc-bg-surface)',
        borderColor: 'var(--rc-border)',
      }}
    >
      {/* Logo + collapse toggle */}
      <div
        className="border-b flex items-center justify-between"
        style={{ borderColor: 'var(--rc-border)', padding: collapsed ? '8px' : '12px 16px' }}
      >
        {collapsed ? (
          /* Collapsed — just the icon centred */
          <button onClick={() => setCollapsed(false)} className="mx-auto" title="Expand sidebar">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={sidebarLogo} alt="Enkstein" width={40} height={40} style={{ display: 'block' }} />
          </button>
        ) : (
          /* Expanded — logo centred on top, text below, collapse button top-right */
          <div className="w-full">
            <div className="flex justify-end mb-1">
              <button
                onClick={() => setCollapsed(true)}
                title="Collapse sidebar"
                className="p-1 rounded-lg hover:bg-[var(--rc-bg-elevated)] transition-colors"
                style={{ color: 'var(--rc-text-3)' }}
              >
                <PanelLeftClose className="w-4 h-4" />
              </button>
            </div>
            <div className="flex flex-col items-center gap-2 pb-1">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img className="enkstein-app-icon" src={sidebarLogo} alt="Enkstein" width={104} height={104} style={{ display: 'block' }} />
              <div className="text-center">
                <h1 className="font-bold text-sm leading-tight" style={{ color: 'var(--rc-text-1)' }}>
                  Enkstein
                </h1>
                <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                  Distributed Security OS
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      <WorkspaceSwitch mode={workspaceMode} collapsed={collapsed} onModeChange={(mode) => {
        persistWorkspaceMode(mode);
        router.push(workspaceModeBasePath(mode));
        setWorkspaceMode(mode);
      }} />

      {/* Nav */}
      <nav
        className="flex-1 overflow-y-auto p-2 space-y-0.5"
        style={{ scrollbarWidth: 'thin', scrollbarColor: 'var(--rc-border) transparent' }}
      >
        {workspaceMode === 'security' ? NAV_GROUPS.map(group => (
          <SidebarGroup key={group.label} group={group} pathname={pathname} collapsed={collapsed} />
        )) : (
          <WorkspaceModeNav key={workspaceMode} mode={workspaceMode} collapsed={collapsed} />
        )}
      </nav>

      {/* Footer */}
      <div className="p-2 border-t space-y-2" style={{ borderColor: 'var(--rc-border)' }}>
        {collapsed ? (
          /* Collapsed footer — just theme icon */
          <button
            onClick={toggle}
            title={isLiquid ? 'Switch to Dark' : isLight ? 'Switch to Liquid Glass' : 'Switch to Light'}
            className="flex items-center justify-center w-10 h-10 mx-auto rounded-lg hover:bg-[var(--rc-bg-elevated)] transition-colors"
            style={{ color: 'var(--rc-text-2)' }}
          >
            {isLiquid
              ? <Sparkles className="w-4 h-4 text-slate-500" />
              : isLight
                ? <Moon className="w-4 h-4 text-indigo-400" />
                : <Sun className="w-4 h-4 text-yellow-400" />}
          </button>
        ) : (
          <>
            <button
              onClick={toggle}
              className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-all duration-150 hover:opacity-80"
              style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}
            >
              {isLiquid
                ? <Sparkles className="w-3.5 h-3.5 text-slate-500" />
                : isLight
                  ? <Moon className="w-3.5 h-3.5 text-indigo-400" />
                  : <Sun className="w-3.5 h-3.5 text-yellow-400" />}
              <span className="flex-1 text-left">
                {isLiquid ? 'Liquid Glass · Switch to Dark' : isLight ? 'Light · Switch to Liquid Glass' : 'Dark · Switch to Light'}
              </span>
              <div
                className="relative w-8 h-4 rounded-full transition-colors duration-200"
                style={{ background: isLiquid ? '#64748b' : isLight ? 'var(--regent-600)' : '#374151' }}
              >
                <div
                  className="absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-all duration-200"
                  style={{ left: isLiquid ? '23px' : isLight ? '17px' : '2px' }}
                />
              </div>
            </button>
            {/* Only meaningful under Liquid Glass, so it stays out of the way in
                the opaque themes rather than showing a disabled control. */}
            {isLiquid && (
              <div
                role="radiogroup"
                aria-label="Liquid Glass transparency"
                className="flex items-center gap-1 rounded-lg p-1"
                style={{ background: 'var(--rc-bg-elevated)' }}
              >
                {GLASS_LEVELS.map((level) => {
                  const active = glassLevel === level;
                  return (
                    <button
                      key={level}
                      type="button"
                      role="radio"
                      aria-checked={active}
                      onClick={() => setGlassLevel(level)}
                      title={`Liquid Glass: ${level}`}
                      className="flex-1 rounded-md px-2 py-1 text-[11px] capitalize transition-colors"
                      style={{
                        background: active ? 'var(--rc-bg-surface)' : 'transparent',
                        color: active ? 'var(--rc-text-1)' : 'var(--rc-text-3)',
                      }}
                    >
                      {level}
                    </button>
                  );
                })}
              </div>
            )}
            <p className="text-xs px-1" style={{ color: 'var(--rc-text-3)' }}>
              {runtimeVersion ? `v${runtimeVersion}` : 'version unavailable'} · {NAV_GROUPS.reduce((s, g) => s + g.items.length, 0)} modules
            </p>
          </>
        )}
      </div>
    </aside>
  );
}
