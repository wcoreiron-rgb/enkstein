'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

/** Human labels for the languages Enkstein most often streams back. Anything not
 * listed falls back to the raw fence token (already lowercased) or "text". */
const LANGUAGE_LABELS: Record<string, string> = {
  bash: 'Bash',
  sh: 'Shell',
  shell: 'Shell',
  zsh: 'Shell',
  ps1: 'PowerShell',
  powershell: 'PowerShell',
  py: 'Python',
  python: 'Python',
  js: 'JavaScript',
  javascript: 'JavaScript',
  jsx: 'JSX',
  ts: 'TypeScript',
  typescript: 'TypeScript',
  tsx: 'TSX',
  json: 'JSON',
  yaml: 'YAML',
  yml: 'YAML',
  toml: 'TOML',
  hcl: 'Terraform',
  tf: 'Terraform',
  terraform: 'Terraform',
  sql: 'SQL',
  go: 'Go',
  rust: 'Rust',
  rs: 'Rust',
  java: 'Java',
  c: 'C',
  cpp: 'C++',
  cs: 'C#',
  ruby: 'Ruby',
  rb: 'Ruby',
  php: 'PHP',
  html: 'HTML',
  css: 'CSS',
  md: 'Markdown',
  markdown: 'Markdown',
  diff: 'Diff',
  dockerfile: 'Dockerfile',
  ini: 'INI',
  xml: 'XML',
  text: 'Text',
  plaintext: 'Text',
};

function labelFor(language?: string): string {
  if (!language) return 'Text';
  return LANGUAGE_LABELS[language.toLowerCase()] || language;
}

/** A governed, presentation-only fenced code block. It preserves exact
 * whitespace, scrolls horizontally so long PowerShell/Python/Terraform lines are
 * never truncated or wrapped, keeps a stable header, and exposes an accessible
 * copy control with a transient "Copied" state. No raw HTML is ever rendered. */
export default function CodeBlock({
  language,
  value,
  compact = false,
}: {
  language?: string;
  value: string;
  /** Bounds the body height with vertical scrolling for embedded operational
   * blocks (e.g. change proposals) so a long file never dominates the panel. */
  compact?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (resetTimer.current) clearTimeout(resetTimer.current);
  }, []);

  const copy = useCallback(async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        // Legacy fallback keeps copy working without the async clipboard API.
        const area = document.createElement('textarea');
        area.value = value;
        area.setAttribute('readonly', '');
        area.style.position = 'absolute';
        area.style.left = '-9999px';
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
      }
      setCopied(true);
      if (resetTimer.current) clearTimeout(resetTimer.current);
      resetTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      /* Clipboard was denied; leave the control in its idle state. */
    }
  }, [value]);

  return (
    <div className="rc-code-block" data-language={language || 'text'}>
      <div className="rc-code-head">
        <span className="rc-code-lang">{labelFor(language)}</span>
        <button
          type="button"
          onClick={() => void copy()}
          className="rc-code-copy"
          aria-label={copied ? 'Code copied to clipboard' : 'Copy code to clipboard'}
          title={copied ? 'Copied' : 'Copy'}
        >
          {copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
          <span aria-hidden="true">{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre className={compact ? 'rc-code-body rc-code-body-compact' : 'rc-code-body'} tabIndex={0}>
        <code>{value}</code>
      </pre>
    </div>
  );
}
