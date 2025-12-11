import { AlertCircle, RefreshCw, WifiOff } from 'lucide-react'
import { cn } from '@/lib/utils'

interface LoadingStateProps {
  message?: string
  className?: string
}

export function LoadingState({ message = 'Loading...', className }: LoadingStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12', className)}>
      <div className="relative">
        <div className="w-12 h-12 rounded-full border-2 border-aide-bg-tertiary" />
        <div className="absolute top-0 left-0 w-12 h-12 rounded-full border-2 border-transparent border-t-neutral-400 animate-spin" />
      </div>
      <p className="mt-4 text-sm text-aide-text-muted">{message}</p>
    </div>
  )
}

interface ErrorStateProps {
  title?: string
  message?: string
  onRetry?: () => void
  className?: string
}

export function ErrorState({ 
  title = 'Something went wrong',
  message = 'An error occurred while loading the data.',
  onRetry,
  className 
}: ErrorStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12', className)}>
      <div className="p-3 rounded-full bg-red-950/30 border border-red-900/50">
        <AlertCircle className="w-8 h-8 text-red-400" />
      </div>
      <h3 className="mt-4 text-lg font-medium text-aide-text-primary">{title}</h3>
      <p className="mt-1 text-sm text-aide-text-muted text-center max-w-md">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-4 aide-btn-secondary">
          <RefreshCw className="w-4 h-4" />
          Try again
        </button>
      )}
    </div>
  )
}

interface EmptyStateProps {
  icon?: React.ElementType
  title: string
  message?: string
  action?: {
    label: string
    onClick: () => void
  }
  className?: string
}

export function EmptyState({ 
  icon: Icon,
  title,
  message,
  action,
  className 
}: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12', className)}>
      {Icon && (
        <div className="p-3 rounded-full bg-aide-bg-tertiary border border-aide-border-DEFAULT">
          <Icon className="w-8 h-8 text-aide-text-muted" />
        </div>
      )}
      <h3 className="mt-4 text-lg font-medium text-aide-text-primary">{title}</h3>
      {message && (
        <p className="mt-1 text-sm text-aide-text-muted text-center max-w-md">{message}</p>
      )}
      {action && (
        <button onClick={action.onClick} className="mt-4 aide-btn-primary">
          {action.label}
        </button>
      )}
    </div>
  )
}

interface OfflineStateProps {
  className?: string
}

export function OfflineState({ className }: OfflineStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12', className)}>
      <div className="p-3 rounded-full bg-amber-950/30 border border-amber-900/50">
        <WifiOff className="w-8 h-8 text-amber-400" />
      </div>
      <h3 className="mt-4 text-lg font-medium text-aide-text-primary">You're offline</h3>
      <p className="mt-1 text-sm text-aide-text-muted text-center max-w-md">
        Please check your internet connection and try again.
      </p>
    </div>
  )
}
