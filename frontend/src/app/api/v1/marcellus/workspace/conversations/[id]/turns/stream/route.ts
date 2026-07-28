/**
 * Long-lived Cortex turn proxy.
 *
 * Next.js rewrites are fine for ordinary JSON calls but can terminate or buffer
 * an upstream stream around the 30-second mark. Browser Companion turns may
 * legitimately run for several minutes, so they must bypass the generic
 * `/api/:path*` rewrite and pass each SSE frame straight through to the
 * desktop webview.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 900;

type RouteContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: RouteContext): Promise<Response> {
  const { id } = await context.params;
  const target = process.env.INTERNAL_API_URL ?? 'http://localhost:8000';
  const url = `${target}/api/v1/marcellus/workspace/conversations/${encodeURIComponent(id)}/turns/stream`;

  let body: string;
  try {
    body = await request.text();
  } catch {
    return Response.json({ detail: 'Invalid request body' }, { status: 400 });
  }

  const authorization = request.headers.get('authorization') ?? '';
  try {
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        ...(authorization ? { Authorization: authorization } : {}),
      },
      body,
      // Do not attach the request abort signal: closing a transient desktop
      // webview connection must not silently cancel a governed provider turn.
    });

    if (!upstream.body) {
      return new Response(await upstream.text(), {
        status: upstream.status,
        headers: { 'Content-Type': upstream.headers.get('content-type') ?? 'application/json' },
      });
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        'Content-Type': upstream.headers.get('content-type') ?? 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'X-Accel-Buffering': 'no',
      },
    });
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : 'Upstream stream unavailable';
    return Response.json({ detail: `Cortex workspace backend unreachable: ${detail}` }, { status: 502 });
  }
}
