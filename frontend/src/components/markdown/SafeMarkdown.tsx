'use client';

import { memo } from 'react';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import CodeBlock from './CodeBlock';

/** Assistant output is untrusted model text, so raw HTML is never enabled here:
 * ReactMarkdown escapes HTML by default (no rehype-raw), and its default
 * urlTransform strips dangerous URL protocols (javascript:, data:, vbscript:).
 * Links additionally open safely with rel="noopener noreferrer". */
const COMPONENTS: Components = {
  a({ children, href, node, ...rest }) {
    void node;
    return (
      <a href={href} target="_blank" rel="noopener noreferrer nofollow" {...rest}>
        {children}
      </a>
    );
  },
  // Fenced/indented code renders through the governed CodeBlock; inline code is
  // styled plainly. ReactMarkdown wraps block code in <pre><code>, so we detect
  // a block by its language class or by containing a newline.
  code({ className, children, node }) {
    const match = /language-(\w[\w+-]*)/.exec(className || '');
    const text = String(children ?? '');
    const isMultiline = text.includes('\n');
    if (!match && !isMultiline && (node?.position?.start.line === node?.position?.end.line)) {
      return <code className="rc-md-inline">{children}</code>;
    }
    return <CodeBlock language={match?.[1]} value={text.replace(/\n$/, '')} />;
  },
  // The <code> renderer already emits the full block wrapper, so collapse the
  // surrounding <pre> to avoid a redundant nested block.
  pre({ children }) {
    return <>{children}</>;
  },
  // Wide tables scroll horizontally instead of overflowing the message column.
  table({ children }) {
    return (
      <div className="rc-md-table-wrap">
        <table>{children}</table>
      </div>
    );
  },
};

function SafeMarkdownImpl({ content, className }: { content: string; className?: string }) {
  return (
    <div className={`rc-md${className ? ` ${className}` : ''}`}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={COMPONENTS} skipHtml>
        {content}
      </ReactMarkdown>
    </div>
  );
}

/** Memoized so streaming re-renders of an unchanged prior message stay cheap. */
const SafeMarkdown = memo(SafeMarkdownImpl);
export default SafeMarkdown;
