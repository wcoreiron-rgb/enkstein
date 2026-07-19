'use client';

import AIWorkspace from '../ai-workspace';

export default function ChatPage() {
  return (
    <div className="min-h-[calc(100vh-2rem)]">
      <AIWorkspace mode="chat" />
    </div>
  );
}
