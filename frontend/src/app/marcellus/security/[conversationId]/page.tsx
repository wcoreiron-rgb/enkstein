'use client';

import { useParams } from 'next/navigation';
import AIWorkspace from '../../ai-workspace';

export default function SecurityConversationPage() {
  const { conversationId } = useParams<{ conversationId: string }>();
  return (
    <div className="min-h-[calc(100vh-2rem)]">
      <AIWorkspace mode="security" initialConversationId={conversationId} />
    </div>
  );
}
