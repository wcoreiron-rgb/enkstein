/**
 * Dedicated proxy for AI Security (arcclaw) agent/chat.
 *
 * Why this exists:
 *   Next.js rewrites have a hard ~30 s socket timeout. NVIDIA NIM (and any
 *   large LLM) can take 45–90 s for a full agentic response with tool calls.
 *   The rewrite was dropping the backend connection mid-flight (ECONNRESET).
 *
 *   By handling the route here we get:
 *   1. `maxDuration = 300` → Vercel / self-hosted Next edge timeout lifted to 5 min
 *   2. Full control over the upstream fetch (AbortSignal, stream passthrough)
 *   3. Proper error surfacing — the frontend receives the real HTTP status + body
 */

export const maxDuration = 300; // seconds — enough for any LLM + tool chain

export async function POST(request: Request): Promise<Response> {
  const target = process.env.INTERNAL_API_URL ?? 'http://localhost:8000';
  const url    = `${target}/api/v1/arcclaw/agent/chat`;

  let body: string;
  try {
    body = await request.text();
  } catch {
    return Response.json({ detail: 'Invalid request body' }, { status: 400 });
  }

  // Forward Authorization header so the backend JWT check passes in production
  // (DEBUG=false). Without this the backend gets no Bearer token and returns 401.
  const authHeader = request.headers.get('authorization') ?? '';

  try {
    const upstream = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authHeader ? { Authorization: authHeader } : {}),
      },
      body,
      // No AbortSignal — let it run until the LLM finishes
    });

    // Pass the upstream body + status straight back to the browser
    const upstreamBody = await upstream.text();
    return new Response(upstreamBody, {
      status:  upstream.status,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    // Surface a readable error instead of a generic 500
    const message = err?.message ?? 'Upstream error';
    return Response.json(
      { detail: `Security Copilot backend unreachable: ${message}` },
      { status: 502 },
    );
  }
}
