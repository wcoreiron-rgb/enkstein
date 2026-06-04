'use client';
import { useState } from 'react';
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
  Users2, Rocket, Container,
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
    label: 'Platform',
    defaultOpen: true,
    items: [
      { label: 'Control Center',   href: '/control-center',   icon: Shield,           tag: 'Command' },
      { label: 'Dashboard',        href: '/dashboard',        icon: LayoutDashboard },
      { label: 'Findings',         href: '/findings',         icon: AlertTriangle,    tag: 'All Claws' },
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
      { label: 'External Agents',  href: '/external-agents',  icon: Globe,            tag: 'OpenClaw' },
      { label: 'Model Router',     href: '/model-router',     icon: Cpu,              tag: 'LLM Sec' },
      { label: 'ModelClaw',        href: '/modelclaw',        icon: Sparkles,         tag: 'Profiles' },
      { label: 'Memory',           href: '/memory',           icon: Layers,           tag: 'State' },
      { label: 'Skill Packs',      href: '/skill-packs',      icon: Package,          tag: 'Skills' },
      { label: 'Connector Health', href: '/connectors/health',icon: Activity,         tag: 'Monitor' },
      { label: 'Exchange',         href: '/exchange',         icon: ShoppingBag,      tag: 'Marketplace' },
      { label: 'Channel Gateway',  href: '/channel-gateway',  icon: MessageSquare,    tag: 'ChatOps' },
      { label: 'Exec Channels',    href: '/exec-channels',    icon: Shield,           tag: 'Governed' },
    ],
  },
  {
    label: 'Open Automation',
    defaultOpen: true,
    items: [
      { label: 'Custom Claw',  href: '/customclaw',   icon: Plug,    tag: 'Builder' },
    ],
  },
  {
    label: 'Core Security',
    defaultOpen: true,
    items: [
      { label: 'ArcClaw',      href: '/arcclaw',      icon: Zap,     tag: 'AI' },
      { label: 'CloudClaw',    href: '/cloudclaw',    icon: Cloud,   tag: 'Cloud' },
      { label: 'IdentityClaw', href: '/identityclaw', icon: Users,   tag: 'Identity' },
      { label: 'AccessClaw',   href: '/accessclaw',   icon: Key,     tag: 'PAM' },
      { label: 'EndpointClaw', href: '/endpointclaw', icon: Monitor, tag: 'Endpoint' },
      { label: 'NetClaw',      href: '/netclaw',      icon: Network, tag: 'Network' },
      { label: 'DataClaw',     href: '/dataclaw',     icon: Database,tag: 'Data' },
      { label: 'AppClaw',      href: '/appclaw',      icon: Code,    tag: 'App/API' },
      { label: 'SaaSClaw',     href: '/saasclaw',     icon: Package, tag: 'SaaS' },
    ],
  },
  {
    label: 'Detection',
    defaultOpen: false,
    items: [
      { label: 'ThreatClaw',  href: '/threatclaw',  icon: Target,    tag: 'D&R' },
      { label: 'LogClaw',     href: '/logclaw',     icon: BookOpen,  tag: 'SIEM' },
      { label: 'IntelClaw',   href: '/intelclaw',   icon: Eye,       tag: 'Intel' },
      { label: 'UserClaw',    href: '/userclaw',    icon: UserCheck, tag: 'UBA' },
      { label: 'InsiderClaw', href: '/insiderclaw', icon: UserX,     tag: 'Insider' },
    ],
  },
  {
    label: 'SecOps',
    defaultOpen: false,
    items: [
      { label: 'AutomationClaw',  href: '/automationclaw',  icon: Bot,      tag: 'SOAR' },
      { label: 'AttackPathClaw',  href: '/attackpathclaw',  icon: GitMerge, tag: 'Paths' },
      { label: 'ExposureClaw',    href: '/exposureclaw',    icon: Radar,    tag: 'ASM' },
    ],
  },
  {
    label: 'Governance',
    defaultOpen: false,
    items: [
      { label: 'ComplianceClaw', href: '/complianceclaw', icon: ClipboardCheck, tag: 'GRC' },
      { label: 'PrivacyClaw',    href: '/privacyclaw',    icon: Lock,           tag: 'Privacy' },
      { label: 'VendorClaw',     href: '/vendorclaw',     icon: Handshake,      tag: 'Vendor' },
    ],
  },
  {
    label: 'Infrastructure',
    defaultOpen: false,
    items: [
      { label: 'TerraClaw',    href: '/terraclaw',    icon: Container, tag: 'IaC Sec' },
      { label: 'DevClaw',      href: '/devclaw',      icon: GitBranch, tag: 'DevSecOps' },
      { label: 'ConfigClaw',   href: '/configclaw',   icon: Settings,  tag: 'Hardening' },
      { label: 'ReleaseClaw',  href: '/releaseclaw',  icon: Rocket,    tag: 'Deploy' },
      { label: 'RecoveryClaw', href: '/recoveryclaw', icon: RefreshCcw,tag: 'Resilience' },
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
            <img src="/favicon.png" alt="RegentClaw" width={40} height={40} style={{ display: 'block' }} />
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
              <img src="/favicon.png" alt="RegentClaw" width={104} height={104} style={{ display: 'block' }} />
              <div className="text-center">
                <h1 className="font-bold text-sm leading-tight" style={{ color: 'var(--rc-text-1)' }}>
                  RegentClaw
                </h1>
                <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                  Zero Trust Ecosystem
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
              v0.2.0 · {NAV_GROUPS.reduce((s, g) => s + g.items.length, 0)} modules
            </p>
          </>
        )}
      </div>
    </aside>
  );
}
