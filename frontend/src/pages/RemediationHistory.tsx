import { Check, RotateCcw, AlertCircle, Clock } from 'lucide-react'
import { Card, Badge } from '@/components/ui'
import { LoadingState, ErrorState } from '@/components/ui/States'
import { useRemediationHistory } from '@/hooks/useApi'
import { formatTimeAgo } from '@/lib/utils'

export function RemediationHistory() {
  const { data: history = [], isLoading, error, refetch } = useRemediationHistory()

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'applied':
        return <Check className="w-4 h-4 text-green-400" />
      case 'pending':
        return <Clock className="w-4 h-4 text-amber-400" />
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-400" />
      case 'rolled-back':
        return <RotateCcw className="w-4 h-4 text-blue-400" />
      default:
        return null
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'applied':
        return <Badge variant="success">Applied</Badge>
      case 'pending':
        return <Badge variant="high">Pending</Badge>
      case 'failed':
        return <Badge variant="critical">Failed</Badge>
      case 'rolled-back':
        return <Badge variant="info">Rolled Back</Badge>
      default:
        return <Badge variant="default">{status}</Badge>
    }
  }

  if (isLoading) {
    return <LoadingState message="Loading remediation history..." />
  }

  if (error) {
    return <ErrorState message="Failed to load history" onRetry={() => refetch()} />
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-aide-text-primary">Remediation History</h1>
        <p className="text-sm text-aide-text-secondary mt-1">
          Track all policy changes and remediations applied to your AWS environment
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-green-400">
            {history.filter(h => h.status === 'applied').length}
          </p>
          <p className="text-xs text-aide-text-muted mt-1">Successfully Applied</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-amber-400">
            {history.filter(h => h.status === 'pending').length}
          </p>
          <p className="text-xs text-aide-text-muted mt-1">Pending Review</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-red-400">
            {history.filter(h => h.status === 'failed').length}
          </p>
          <p className="text-xs text-aide-text-muted mt-1">Failed</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-blue-400">
            {history.filter(h => h.status === 'rolled-back').length}
          </p>
          <p className="text-xs text-aide-text-muted mt-1">Rolled Back</p>
        </Card>
      </div>

      {/* History Timeline */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-aide-text-primary mb-6">Recent Activity</h2>
        
        <div className="space-y-6">
          {history.map((record, index) => (
            <div key={record.id} className="relative">
              {/* Timeline line */}
              {index < history.length - 1 && (
                <div className="absolute left-[11px] top-8 bottom-0 w-px bg-aide-border-DEFAULT" />
              )}
              
              {/* Timeline item */}
              <div className="flex gap-4">
                {/* Icon */}
                <div className="flex-shrink-0 w-6 h-6 rounded-full bg-aide-bg-tertiary border border-aide-border-DEFAULT flex items-center justify-center">
                  {getStatusIcon(record.status)}
                </div>
                
                {/* Content */}
                <div className="flex-1 pb-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-3">
                        <p className="text-sm font-medium text-aide-text-primary">
                          {record.findingType}
                        </p>
                        {getStatusBadge(record.status)}
                      </div>
                      <p className="text-xs text-aide-text-muted mt-1">
                        <code className="bg-aide-bg-primary px-1.5 py-0.5 rounded">
                          {record.resourceArn.split(':').pop()}
                        </code>
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-aide-text-muted">
                        {formatTimeAgo(record.appliedAt)}
                      </p>
                      <p className="text-xs text-aide-text-muted mt-0.5">
                        by {record.appliedBy}
                      </p>
                    </div>
                  </div>
                  
                  {/* Policy diff summary */}
                  <div className="mt-3 grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-aide bg-red-950/20 border border-red-900/30">
                      <p className="text-xs text-red-400 font-medium mb-1">Original</p>
                      <code className="text-xs text-aide-text-secondary">
                        {record.originalPolicy}
                      </code>
                    </div>
                    <div className="p-3 rounded-aide bg-green-950/20 border border-green-900/30">
                      <p className="text-xs text-green-400 font-medium mb-1">Remediated</p>
                      <code className="text-xs text-aide-text-secondary">
                        {record.remediatedPolicy}
                      </code>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {history.length === 0 && (
          <div className="py-12 text-center">
            <p className="text-aide-text-muted">No remediation history yet</p>
          </div>
        )}
      </Card>
    </div>
  )
}
