import type { Page } from '@playwright/test';

export type MockProject = {
  id: string;
  tenant_id: string;
  owner_id: string;
  name: string;
  description: string;
  classification: string;
  default_source: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type MockConversation = {
  id: string;
  tenant_id: string;
  owner_id: string;
  project_id: string | null;
  title: string;
  mode: 'chat' | 'cowork' | 'security';
  classification: string;
  selected_source: string;
  status: string;
  branch_of_id?: string | null;
  branch_message_id?: string | null;
  message_count: number;
  created_at: string;
  updated_at: string;
};

export type WorkspaceStore = {
  projects: MockProject[];
  conversations: MockConversation[];
  nativeWorkspace: Record<string, { connected: boolean; name?: string; file_count: number; synced_files: number }>;
};

const ARCHITECTURE_STUB = {
  name: 'Enkstein',
  version: 'e2e',
  working_name: true,
  source_lineage: 'e2e',
  compatibility_mode: 'e2e',
  thesis: 'Test thesis',
  cortex: [],
  hearts: [],
  arms: [],
  capability_nodes: [],
  reflexes: { implementation_state: 'shipped', purpose: '', existing_foundation: [], invariants: [] },
  plexus: { implementation_state: 'shipped', purpose: '', current_transport: '', target_transport: '', invariants: [] },
  regeneration: { implementation_state: 'shipped', purpose: '', recovery_sequence: [], invariants: [] },
  invariants: [],
};

let counter = 0;
function nextId(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter}`;
}

export function createWorkspaceStore(): WorkspaceStore {
  return { projects: [], conversations: [], nativeWorkspace: {} };
}

/** Mocks every Marcellus workspace endpoint AIWorkspace/Sidebar rely on, backed
 * by an in-memory store, so tests exercise real create/rename/archive/move
 * flows without a live backend. */
export async function mockMarcellusWorkspace(page: Page, store: WorkspaceStore = createWorkspaceStore()): Promise<WorkspaceStore> {
  // The Security workspace's runtime console / mission control fetch these
  // on mount. Without a mock, the unmocked calls 401 against the real
  // backend and the shared apiFetch client redirects the whole tab to
  // /login mid-test. Each is shaped to match its real response type so
  // components reading nested fields (e.g. brief.security_twin_health)
  // don't crash on an empty array.
  await page.route('**/api/v1/marcellus/missions/memory/observations*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/marcellus/missions/overnight-brief*', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      id: 'brief-e2e',
      generated_at: new Date().toISOString(),
      window_start: new Date().toISOString(),
      window_end: new Date().toISOString(),
      headline: 'No material changes detected.',
      active_missions: [],
      material_changes: [],
      decisions_needed: [],
      running_arms: [],
      recent_reflex_actions: [],
      blocked_actions: [],
      security_twin_health: { status: 'unconfigured' },
    }),
  }));
  await page.route('**/api/v1/marcellus/reflexes/executions*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/marcellus/reflexes*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/marcellus/regeneration/checkpoints*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/marcellus/regeneration/runs*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/marcellus/regeneration/runtimes*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/marcellus/plexus/messages*', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/modelclaw/brains/status', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/modelclaw/profiles', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/arcclaw/providers', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/v1/arcclaw/agent/models', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/v1/marcellus/architecture', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(ARCHITECTURE_STUB) }));
  await page.route('**/api/v1/marcellus/missions', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/runtime-info', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ version: '0.3.6' }) }));

  await page.route('**/api/v1/marcellus/workspace/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const segments = url.pathname.split('/marcellus/workspace/')[1]?.split('/') || [];
    const now = new Date().toISOString();

    const json = (status: number, data: unknown) =>
      route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });

    if (segments[0] === 'projects' && segments.length === 1) {
      if (method === 'GET') return json(200, store.projects);
      if (method === 'POST') {
        const body = request.postDataJSON();
        const project: MockProject = {
          id: nextId('project'),
          tenant_id: 'default',
          owner_id: 'e2e-owner',
          name: body.name,
          description: body.description || '',
          classification: body.classification || 'internal',
          default_source: body.default_source || 'auto',
          status: 'active',
          created_at: now,
          updated_at: now,
        };
        store.projects.unshift(project);
        return json(200, project);
      }
    }

    if (segments[0] === 'projects' && segments[2] === 'native-workspace' && !segments[3]) {
      const projectId = segments[1];
      if (method === 'GET') {
        return json(200, store.nativeWorkspace[projectId] || { connected: false, file_count: 0, synced_files: 0 });
      }
      if (method === 'POST') {
        const body = request.postDataJSON();
        const workspace = { connected: true, name: body.name, file_count: 1, synced_files: 1 };
        store.nativeWorkspace[projectId] = workspace;
        return json(200, workspace);
      }
    }

    if (segments[0] === 'projects' && segments[2] === 'native-workspace' && segments[3] === 'sync') {
      const projectId = segments[1];
      const workspace = store.nativeWorkspace[projectId] || { connected: true, name: 'synced', file_count: 1, synced_files: 1 };
      return json(200, workspace);
    }

    if (segments[0] === 'projects' && segments[2] === 'artifacts') {
      return json(200, []);
    }

    if (segments[0] === 'projects' && segments[2] === 'change-proposals') {
      return json(200, []);
    }

    if (segments[0] === 'conversations' && segments.length === 1) {
      if (method === 'GET') {
        const mode = url.searchParams.get('mode');
        const projectId = url.searchParams.get('project_id');
        const rows = store.conversations.filter((item) => item.status === 'active'
          && (!mode || item.mode === mode)
          && (!projectId || item.project_id === projectId));
        return json(200, rows);
      }
      if (method === 'POST') {
        const body = request.postDataJSON();
        const conversation: MockConversation = {
          id: nextId('conversation'),
          tenant_id: 'default',
          owner_id: 'e2e-owner',
          project_id: body.project_id || null,
          title: body.title || 'New conversation',
          mode: body.mode || 'chat',
          classification: body.classification || 'internal',
          selected_source: body.selected_source || 'auto',
          status: 'active',
          message_count: 0,
          created_at: now,
          updated_at: now,
        };
        store.conversations.unshift(conversation);
        return json(200, conversation);
      }
    }

    if (segments[0] === 'conversations' && segments.length === 2) {
      const conversation = store.conversations.find((item) => item.id === segments[1]);
      if (!conversation) return json(404, { detail: 'not found' });
      if (method === 'GET') return json(200, { ...conversation, messages: [] });
      if (method === 'DELETE') {
        conversation.status = 'archived';
        conversation.updated_at = now;
        return json(200, conversation);
      }
    }

    if (segments[0] === 'conversations' && segments[2] === 'rename') {
      const conversation = store.conversations.find((item) => item.id === segments[1]);
      if (!conversation) return json(404, { detail: 'not found' });
      const body = request.postDataJSON();
      conversation.title = body.title;
      conversation.updated_at = now;
      return json(200, conversation);
    }

    if (segments[0] === 'conversations' && segments[2] === 'move') {
      const conversation = store.conversations.find((item) => item.id === segments[1]);
      if (!conversation) return json(404, { detail: 'not found' });
      const body = request.postDataJSON();
      conversation.project_id = body.project_id;
      conversation.mode = 'cowork';
      conversation.updated_at = now;
      return json(200, conversation);
    }

    return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ detail: 'unmocked route' }) });
  });

  return store;
}
