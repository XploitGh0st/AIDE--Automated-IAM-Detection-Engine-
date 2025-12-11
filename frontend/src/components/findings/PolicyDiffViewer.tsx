import ReactDiffViewer, { DiffMethod } from 'react-diff-viewer-continued'

interface PolicyDiffViewerProps {
  oldValue: string
  newValue: string
  splitView?: boolean
}

// Custom styles matching our professional monochrome theme
const diffStyles = {
  variables: {
    dark: {
      diffViewerBackground: '#0a0a0a',
      diffViewerColor: '#e5e5e5',
      addedBackground: 'rgba(20, 83, 45, 0.3)',
      addedColor: '#86efac',
      removedBackground: 'rgba(127, 29, 29, 0.3)',
      removedColor: '#fca5a5',
      wordAddedBackground: 'rgba(34, 197, 94, 0.4)',
      wordRemovedBackground: 'rgba(239, 68, 68, 0.4)',
      addedGutterBackground: 'rgba(20, 83, 45, 0.4)',
      removedGutterBackground: 'rgba(127, 29, 29, 0.4)',
      gutterBackground: '#171717',
      gutterBackgroundDark: '#0a0a0a',
      highlightBackground: 'rgba(255, 255, 255, 0.05)',
      highlightGutterBackground: 'rgba(255, 255, 255, 0.05)',
      codeFoldGutterBackground: '#1a1a1a',
      codeFoldBackground: '#1a1a1a',
      emptyLineBackground: '#0a0a0a',
      gutterColor: '#525252',
      addedGutterColor: '#86efac',
      removedGutterColor: '#fca5a5',
      codeFoldContentColor: '#737373',
      diffViewerTitleBackground: '#171717',
      diffViewerTitleColor: '#e5e5e5',
      diffViewerTitleBorderColor: '#262626',
    },
  },
  line: {
    padding: '4px 10px',
    fontSize: '13px',
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
  },
  gutter: {
    minWidth: '40px',
    padding: '0 10px',
    fontSize: '12px',
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
  },
  contentText: {
    fontSize: '13px',
    lineHeight: '1.6',
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
  },
  marker: {
    padding: '0 6px',
  },
  diffContainer: {
    borderRadius: '0.375rem',
    border: '1px solid #262626',
    overflow: 'hidden',
  },
  diffRemoved: {
    borderLeft: '3px solid #ef4444',
  },
  diffAdded: {
    borderLeft: '3px solid #22c55e',
  },
}

export function PolicyDiffViewer({ 
  oldValue, 
  newValue, 
  splitView = true 
}: PolicyDiffViewerProps) {
  // Format JSON for better display
  const formatJSON = (json: string): string => {
    try {
      return JSON.stringify(JSON.parse(json), null, 2)
    } catch {
      return json
    }
  }

  return (
    <div className="rounded-aide overflow-hidden border border-aide-border-DEFAULT">
      <div className="flex border-b border-aide-border-DEFAULT bg-aide-bg-primary">
        <div className="flex-1 px-4 py-2 text-xs font-medium text-red-400 border-r border-aide-border-DEFAULT">
          Original Policy
        </div>
        <div className="flex-1 px-4 py-2 text-xs font-medium text-green-400">
          Suggested Secure Policy
        </div>
      </div>
      <ReactDiffViewer
        oldValue={formatJSON(oldValue)}
        newValue={formatJSON(newValue)}
        splitView={splitView}
        useDarkTheme={true}
        compareMethod={DiffMethod.WORDS}
        styles={diffStyles}
        leftTitle=""
        rightTitle=""
        hideLineNumbers={false}
        showDiffOnly={false}
      />
    </div>
  )
}
