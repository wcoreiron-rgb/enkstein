'use client';

import { useParams } from 'next/navigation';
import AIWorkspace from '../../ai-workspace';

export default function CoworkProjectPage() {
  const { projectId } = useParams<{ projectId: string }>();
  return (
    <div className="min-h-[calc(100vh-2rem)]">
      <AIWorkspace mode="cowork" initialProjectId={projectId} />
    </div>
  );
}
