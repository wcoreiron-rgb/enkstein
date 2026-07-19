'use client';

import { useParams } from 'next/navigation';
import AIWorkspace from '../../../ai-workspace';

export default function CoworkConversationPage() {
  const { projectId, conversationId } = useParams<{ projectId: string; conversationId: string }>();
  return (
    <div className="min-h-[calc(100vh-2rem)]">
      <AIWorkspace mode="cowork" initialProjectId={projectId} initialConversationId={conversationId} />
    </div>
  );
}
