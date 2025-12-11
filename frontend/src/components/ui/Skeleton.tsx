import { cn } from '@/lib/utils'

interface SkeletonProps {
  className?: string
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div className={cn('animate-pulse bg-aide-bg-tertiary rounded-aide', className)} />
  )
}

export function SkeletonCard() {
  return (
    <div className="aide-card p-5">
      <Skeleton className="h-4 w-24 mb-4" />
      <Skeleton className="h-8 w-16 mb-2" />
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="aide-card p-0 overflow-hidden">
      <div className="p-4 border-b border-aide-border-DEFAULT">
        <Skeleton className="h-6 w-48" />
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 p-4 border-b border-aide-border-subtle">
          <Skeleton className="h-6 w-20" />
          <Skeleton className="h-6 flex-1" />
          <Skeleton className="h-6 w-32" />
          <Skeleton className="h-6 w-24" />
        </div>
      ))}
    </div>
  )
}

export function SkeletonDrawer() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Skeleton className="h-8 w-24" />
        <Skeleton className="h-8 flex-1" />
      </div>
      
      {/* Risk explanation */}
      <div className="p-4 rounded-aide border border-aide-border-DEFAULT">
        <Skeleton className="h-4 w-32 mb-3" />
        <Skeleton className="h-4 w-full mb-2" />
        <Skeleton className="h-4 w-3/4" />
      </div>
      
      {/* Tabs */}
      <Skeleton className="h-10 w-48" />
      
      {/* Content */}
      <div className="grid grid-cols-2 gap-4">
        <div className="aide-card p-4">
          <Skeleton className="h-4 w-32 mb-4" />
          <div className="space-y-3">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-5/6" />
          </div>
        </div>
        <div className="aide-card p-4">
          <Skeleton className="h-4 w-32 mb-4" />
          <Skeleton className="h-40 w-full" />
        </div>
      </div>
    </div>
  )
}

export function SkeletonDiff() {
  return (
    <div className="aide-card p-4">
      <div className="flex border-b border-aide-border-DEFAULT pb-3 mb-4">
        <Skeleton className="h-4 w-32 mr-4" />
        <Skeleton className="h-4 w-40" />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-4 w-full" />
          ))}
        </div>
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-4 w-full" />
          ))}
        </div>
      </div>
    </div>
  )
}
