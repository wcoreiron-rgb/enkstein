import { readStoredWorkspaceMode, type WorkspaceMode } from './workspace-mode';

/** Route-addressable paths for the Chat/Cowork/Security workspace. Deep
 * links, browser back/forward, bookmarks, and refresh all resolve through
 * these paths instead of the legacy `/marcellus#mode` hash. */

const LAST_CHAT_CONVERSATION_KEY = 'marcellus-last-chat-conversation';
// Reused verbatim from the pre-route-addressable implementation so existing
// bookmarks/localStorage from before this change keep resolving.
const LAST_COWORK_PROJECT_KEY = 'marcellus-cowork-project';
const LAST_COWORK_CONVERSATION_KEY = 'marcellus-cowork-conversation';
const LAST_SECURITY_CONVERSATION_KEY = 'marcellus-last-security-conversation';

export function chatPath(conversationId?: string | null): string {
  return conversationId ? `/marcellus/chat/${conversationId}` : '/marcellus/chat';
}

export function coworkPath(projectId?: string | null, conversationId?: string | null): string {
  if (projectId && conversationId) return `/marcellus/cowork/${projectId}/${conversationId}`;
  if (projectId) return `/marcellus/cowork/${projectId}`;
  return '/marcellus/cowork';
}

export function securityPath(conversationId?: string | null): string {
  return conversationId ? `/marcellus/security/${conversationId}` : '/marcellus/security';
}

/** Builds the stable route path for a mode, optionally deep-linked to a
 * project and/or conversation. Cowork ignores conversationId without a
 * projectId, since a conversation can't be addressed without its project. */
export function workspaceRoutePath(
  mode: WorkspaceMode,
  opts: { projectId?: string | null; conversationId?: string | null } = {},
): string {
  if (mode === 'chat') return chatPath(opts.conversationId);
  if (mode === 'cowork') return coworkPath(opts.projectId, opts.conversationId);
  return securityPath(opts.conversationId);
}

/** Base (conversation-less) route path for a mode's switcher/nav links. */
export function workspaceModeBasePath(mode: WorkspaceMode): string {
  return mode === 'chat' ? '/marcellus/chat' : mode === 'cowork' ? '/marcellus/cowork' : '/marcellus/security';
}

export function workspaceModeFromPath(pathname: string): WorkspaceMode | null {
  if (pathname.startsWith('/marcellus/chat')) return 'chat';
  if (pathname.startsWith('/marcellus/cowork')) return 'cowork';
  if (pathname.startsWith('/marcellus/security')) return 'security';
  return null;
}

export function persistLastActiveConversation(
  mode: WorkspaceMode,
  conversationId: string | null,
  projectId?: string | null,
): void {
  if (typeof window === 'undefined') return;
  if (mode === 'chat') {
    if (conversationId) window.localStorage.setItem(LAST_CHAT_CONVERSATION_KEY, conversationId);
    else window.localStorage.removeItem(LAST_CHAT_CONVERSATION_KEY);
  } else if (mode === 'cowork') {
    if (projectId) window.localStorage.setItem(LAST_COWORK_PROJECT_KEY, projectId);
    if (conversationId) window.localStorage.setItem(LAST_COWORK_CONVERSATION_KEY, conversationId);
    else window.localStorage.removeItem(LAST_COWORK_CONVERSATION_KEY);
  } else {
    if (conversationId) window.localStorage.setItem(LAST_SECURITY_CONVERSATION_KEY, conversationId);
    else window.localStorage.removeItem(LAST_SECURITY_CONVERSATION_KEY);
  }
}

export function readLastActiveConversation(mode: WorkspaceMode): { conversationId?: string; projectId?: string } {
  if (typeof window === 'undefined') return {};
  if (mode === 'chat') {
    return { conversationId: window.localStorage.getItem(LAST_CHAT_CONVERSATION_KEY) || undefined };
  }
  if (mode === 'cowork') {
    return {
      projectId: window.localStorage.getItem(LAST_COWORK_PROJECT_KEY) || undefined,
      conversationId: window.localStorage.getItem(LAST_COWORK_CONVERSATION_KEY) || undefined,
    };
  }
  return { conversationId: window.localStorage.getItem(LAST_SECURITY_CONVERSATION_KEY) || undefined };
}

/** Resolves a legacy `/marcellus` or `/marcellus#mode` URL to its stable
 * replacement path so old bookmarks keep working. Falls back to the last
 * remembered mode/conversation, then to Chat. */
export function resolveLegacyWorkspacePath(hash: string): string {
  const requested = hash.replace(/^#/, '').toLowerCase();
  const mode: WorkspaceMode = requested === 'cowork' || requested === 'security'
    ? requested
    : requested === 'chat'
      ? 'chat'
      : readStoredWorkspaceMode() || 'chat';
  const last = readLastActiveConversation(mode);
  return workspaceRoutePath(mode, last);
}
