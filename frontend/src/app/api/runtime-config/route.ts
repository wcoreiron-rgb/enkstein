import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * Browser-visible runtime configuration.
 *
 * `NEXT_PUBLIC_*` values are inlined when the image is built, but the launcher
 * picks a free backend port at start time, so the published port is not known
 * until then. Next does not proxy WebSocket upgrades, so the client has to
 * connect to that port directly — this endpoint is how it learns which one.
 */
export function GET() {
  const explicit = process.env.PUBLIC_WS_URL;
  const backendPort = process.env.BACKEND_PORT || '8000';
  return NextResponse.json({
    wsPort: backendPort,
    wsUrl: explicit || null,
  });
}
