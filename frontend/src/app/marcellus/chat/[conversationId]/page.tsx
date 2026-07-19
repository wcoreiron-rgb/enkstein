'use client';

import { useParams } from 'next/navigation';
import AIWorkspace from '../../ai-workspace';

export default function ChatConversationPage() {
  const { conversationId } = useParams<{ conversationId: string }>();
  return (
    <div className="min-h-[calc(100vh-2rem)]">
      <AIWorkspace mode="chat" initialConversationId={conversationId} />
    </div>
  );
}
