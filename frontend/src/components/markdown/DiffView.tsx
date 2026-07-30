'use client';

import { Check, Copy } from 'lucide-react';
import { useCopyToClipboard } from '@/lib/use-copy-to-clipboard';

type LineKind = 'add' | 'remove' | 'hunk' | 'meta' | 'context';

function lineKind(line: string): LineKind {
  if (line.startsWith('+++') || line.startsWith('---')) return 'meta';
  if (line.startsWith('@@')) return 'hunk';
  if (line.startsWith('+')) return 'add';
  if (line.startsWith('-')) return 'remove';
  return 'context';
}

const LINE_CLASS: Record<LineKind, string> = {
  add: 'rc-diff-line rc-diff-add',
  remove: 'rc-diff-line rc-diff-remove',
  hunk: 'rc-diff-line rc-diff-hunk',
  meta: 'rc-diff-line rc-diff-meta',
  context: 'rc-diff-line rc-diff-context',
};

/** Presentation-only unified-diff renderer for pending governed file changes.
 * Renders the backend-computed diff verbatim with per-line add/remove coloring
 * so a reviewer can judge a write without reading the whole file. Never
 * interprets or executes the content. */
export default function DiffView({ diff, compact = false }: { diff: string; compact?: boolean }) {
  const { copied, copy } = useCopyToClipboard();
  const lines = diff.split('\n');

  return (
    <div className="rc-code-block" data-language="diff">
      <div className="rc-code-head">
        <span className="rc-code-lang">Diff</span>
        <button
          type="button"
          onClick={() => void copy(diff)}
          className="rc-code-copy"
          aria-label={copied ? 'Diff copied to clipboard' : 'Copy diff to clipboard'}
          title={copied ? 'Copied' : 'Copy'}
        >
          {copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
          <span aria-hidden="true">{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre className={compact ? 'rc-code-body rc-code-body-compact' : 'rc-code-body'} tabIndex={0}>
        <code>
          {lines.map((line, index) => (
            <span key={index} className={LINE_CLASS[lineKind(line)]}>
              {line || ' '}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
