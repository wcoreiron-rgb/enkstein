'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard, Shield, Cpu, Zap, Users, FileText,
  Activity, ScrollText, Plug, AlertTriangle, Sun, Moon,
  ChevronDown, ChevronRight, ChevronLeft,
  Cloud, Key, Monitor, Globe, Database, Code, Package,
  Target, BookOpen, Eye, UserCheck, UserX,
  Bot, GitMerge, Radar, ClipboardCheck, Lock, Handshake,
  GitBranch, Settings, RefreshCcw, Network, CalendarClock, Layers, Workflow, Webhook, Sparkles,
  MessageSquare, ShoppingBag, PanelLeftClose, PanelLeftOpen, ShieldAlert,
  Users2, Rocket, Container, BrainCircuit,
} from 'lucide-react';
import clsx from 'clsx';
import { useTheme } from '@/components/ThemeProvider';

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
      { label: 'Marcellus',        href: '/marcellus',        icon: BrainCircuit,     tag: 'Architecture' },
      { label: 'Control Center',   href: '/control-center',   icon: Shield,           tag: 'Command' },
      { label: 'Dashboard',        href: '/dashboard',        icon: LayoutDashboard },
      { label: 'Findings',         href: '/findings',         icon: AlertTriangle,    tag: 'All Nodes' },
      { label: 'Trust Fabric',     href: '/trust-fabric',     icon: Shield },
      { label: 'CoreOS',           href: '/coreos',           icon: Cpu },
      { label: 'Policies',         href: '/policies',         icon: FileText },
      { label: 'Policy Packs',     href: '/policy-packs',     icon: Layers,           tag: 'Compliance' },
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
    defaultOpen: false,
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
    defaultOpen: false,
    items: [
      { label: 'Security Automation', href: '/capabilities/security-automation', icon: Bot,      tag: 'SOAR' },
      { label: 'Attack Path Analysis', href: '/capabilities/attack-path-analysis', icon: GitMerge, tag: 'Paths' },
      { label: 'Exposure Management', href: '/capabilities/exposure-management', icon: Radar,    tag: 'ASM' },
    ],
  },
  {
    label: 'Governance Arm',
    defaultOpen: false,
    items: [
      { label: 'Compliance Assurance', href: '/capabilities/compliance-assurance', icon: ClipboardCheck, tag: 'GRC' },
      { label: 'Privacy Governance',   href: '/capabilities/privacy-governance',   icon: Lock,           tag: 'Privacy' },
      { label: 'Vendor Risk',          href: '/capabilities/vendor-risk',          icon: Handshake,      tag: 'Vendor' },
    ],
  },
  {
    label: 'Engineering Arm',
    defaultOpen: false,
    items: [
      { label: 'Terraform Governance', href: '/capabilities/terraform-governance', icon: Container, tag: 'IaC Sec' },
      { label: 'Developer Security',   href: '/capabilities/developer-security', icon: GitBranch, tag: 'DevSecOps' },
      { label: 'Configuration Security', href: '/capabilities/configuration-security', icon: Settings, tag: 'Hardening' },
      { label: 'Release Governance',   href: '/capabilities/release-governance', icon: Rocket, tag: 'Deploy' },
      { label: 'Recovery Readiness',   href: '/capabilities/recovery-readiness', icon: RefreshCcw,tag: 'Resilience' },
    ],
  },
];

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
  const { theme, toggle } = useTheme();
  const isLight   = theme === 'light';
  const [collapsed, setCollapsed] = useState(false);
  const [runtimeVersion, setRuntimeVersion] = useState<string | null>(null);

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
            <img src="/favicon.png" alt="Marcellus" width={40} height={40} style={{ display: 'block' }} />
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
              <img src="/favicon.png" alt="Marcellus" width={104} height={104} style={{ display: 'block' }} />
              <div className="text-center">
                <h1 className="font-bold text-sm leading-tight" style={{ color: 'var(--rc-text-1)' }}>
                  Marcellus
                </h1>
                <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                  Distributed Security OS
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav
        className="flex-1 overflow-y-auto p-2 space-y-0.5"
        style={{ scrollbarWidth: 'thin', scrollbarColor: 'var(--rc-border) transparent' }}
      >
        {NAV_GROUPS.map(group => (
          <SidebarGroup key={group.label} group={group} pathname={pathname} collapsed={collapsed} />
        ))}
      </nav>

      {/* Footer */}
      <div className="p-2 border-t space-y-2" style={{ borderColor: 'var(--rc-border)' }}>
        {collapsed ? (
          /* Collapsed footer — just theme icon */
          <button
            onClick={toggle}
            title={isLight ? 'Switch to Dark' : 'Switch to Light'}
            className="flex items-center justify-center w-10 h-10 mx-auto rounded-lg hover:bg-[var(--rc-bg-elevated)] transition-colors"
            style={{ color: 'var(--rc-text-2)' }}
          >
            {isLight
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
              {isLight
                ? <Moon className="w-3.5 h-3.5 text-indigo-400" />
                : <Sun className="w-3.5 h-3.5 text-yellow-400" />}
              <span className="flex-1 text-left">{isLight ? 'Switch to Dark' : 'Switch to Light'}</span>
              <div
                className="relative w-8 h-4 rounded-full transition-colors duration-200"
                style={{ background: isLight ? 'var(--regent-600)' : '#374151' }}
              >
                <div
                  className="absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-all duration-200"
                  style={{ left: isLight ? '17px' : '2px' }}
                />
              </div>
            </button>
            <p className="text-xs px-1" style={{ color: 'var(--rc-text-3)' }}>
              {runtimeVersion ? `v${runtimeVersion}` : 'version unavailable'} · {NAV_GROUPS.reduce((s, g) => s + g.items.length, 0)} modules
            </p>
          </>
        )}
      </div>
    </aside>
  );
}
