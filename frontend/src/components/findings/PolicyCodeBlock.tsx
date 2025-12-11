import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { cn } from '@/lib/utils'

// Custom dark theme matching our design
const aideTheme: { [key: string]: React.CSSProperties } = {
  'code[class*="language-"]': {
    color: '#e5e5e5',
    background: 'none',
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fontSize: '0.8125rem',
    textAlign: 'left',
    whiteSpace: 'pre',
    wordSpacing: 'normal',
    wordBreak: 'normal',
    wordWrap: 'normal',
    lineHeight: '1.6',
    tabSize: 2,
    hyphens: 'none',
  },
  'pre[class*="language-"]': {
    color: '#e5e5e5',
    background: '#0a0a0a',
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fontSize: '0.8125rem',
    textAlign: 'left',
    whiteSpace: 'pre',
    wordSpacing: 'normal',
    wordBreak: 'normal',
    wordWrap: 'normal',
    lineHeight: '1.6',
    tabSize: 2,
    hyphens: 'none',
    padding: '1rem',
    margin: '0',
    overflow: 'auto',
    borderRadius: '0.375rem',
  },
  comment: { color: '#6b7280' },
  prolog: { color: '#6b7280' },
  doctype: { color: '#6b7280' },
  cdata: { color: '#6b7280' },
  punctuation: { color: '#a3a3a3' },
  property: { color: '#93c5fd' },
  tag: { color: '#93c5fd' },
  boolean: { color: '#c4b5fd' },
  number: { color: '#c4b5fd' },
  constant: { color: '#c4b5fd' },
  symbol: { color: '#c4b5fd' },
  deleted: { color: '#fca5a5' },
  selector: { color: '#86efac' },
  'attr-name': { color: '#fcd34d' },
  string: { color: '#86efac' },
  char: { color: '#86efac' },
  builtin: { color: '#86efac' },
  inserted: { color: '#86efac' },
  operator: { color: '#e5e5e5' },
  entity: { color: '#e5e5e5', cursor: 'help' },
  url: { color: '#e5e5e5' },
  'attr-value': { color: '#86efac' },
  keyword: { color: '#f9a8d4' },
  function: { color: '#93c5fd' },
  'class-name': { color: '#fcd34d' },
  regex: { color: '#fcd34d' },
  important: { color: '#fcd34d', fontWeight: 'bold' },
  variable: { color: '#e5e5e5' },
  bold: { fontWeight: 'bold' },
  italic: { fontStyle: 'italic' },
}

interface PolicyCodeBlockProps {
  code: string
  language?: string
  highlightLines?: string[]
  className?: string
}

export function PolicyCodeBlock({ 
  code, 
  language = 'json',
  highlightLines,
  className 
}: PolicyCodeBlockProps) {
  // Find lines that contain offending patterns
  const linesToHighlight: number[] = []
  
  if (highlightLines && language === 'json') {
    const lines = code.split('\n')
    lines.forEach((line, index) => {
      // Highlight lines with wildcards or dangerous patterns
      if (
        line.includes('"*"') ||
        line.includes(': "*"') ||
        line.includes("'*'") ||
        highlightLines.some(h => line.includes(h.split(':')[0]))
      ) {
        linesToHighlight.push(index + 1)
      }
    })
  }

  return (
    <div className={cn('relative rounded-aide overflow-hidden', className)}>
      <SyntaxHighlighter
        language={language}
        style={aideTheme}
        showLineNumbers
        wrapLines
        lineNumberStyle={{
          color: '#525252',
          paddingRight: '1rem',
          minWidth: '2.5rem',
          userSelect: 'none',
        }}
        lineProps={(lineNumber) => {
          const style: React.CSSProperties = { 
            display: 'block',
            padding: '0 0.5rem',
          }
          if (linesToHighlight.includes(lineNumber)) {
            style.backgroundColor = 'rgba(127, 29, 29, 0.3)'
            style.borderLeft = '3px solid #ef4444'
            style.marginLeft = '-3px'
          }
          return { style }
        }}
        customStyle={{
          margin: 0,
          padding: '1rem',
          background: '#0a0a0a',
          border: '1px solid #262626',
          borderRadius: '0.375rem',
          fontSize: '0.8125rem',
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  )
}
