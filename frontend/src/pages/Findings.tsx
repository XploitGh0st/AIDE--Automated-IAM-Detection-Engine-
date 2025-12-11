import { useState, useMemo } from 'react'
import { Search, Filter, ChevronDown, Copy, Check } from 'lucide-react'
import { Badge, Card } from '@/components/ui'
import { LoadingState, ErrorState, EmptyState } from '@/components/ui/States'
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from '@/components/ui/Select'
import { FindingDetailDrawer } from '@/components/findings/FindingDetailDrawer'
import { useAppStore } from '@/store/appStore'
import { useFindings } from '@/hooks/useApi'
import { formatTimeAgo, truncateMiddle, copyToClipboard, cn } from '@/lib/utils'
import { Finding, Severity, AWSService } from '@/types'

export function Findings() {
  const { filters, setFilters, openDrawer, isDrawerOpen, selectedFinding, closeDrawer } = useAppStore()
  const [copiedArn, setCopiedArn] = useState<string | null>(null)
  
  const { data: findings = [], isLoading, error, refetch } = useFindings()

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      if (filters.severity !== 'all' && finding.severity !== filters.severity) return false
      if (filters.service !== 'all' && finding.service !== filters.service) return false
      if (filters.status !== 'all' && finding.status !== filters.status) return false
      if (filters.search) {
        const searchLower = filters.search.toLowerCase()
        return (
          finding.findingType.toLowerCase().includes(searchLower) ||
          finding.resourceArn.toLowerCase().includes(searchLower) ||
          finding.description.toLowerCase().includes(searchLower)
        )
      }
      return true
    })
  }, [findings, filters])

  const handleCopyArn = async (arn: string, e: React.MouseEvent) => {
    e.stopPropagation()
    await copyToClipboard(arn)
    setCopiedArn(arn)
    setTimeout(() => setCopiedArn(null), 2000)
  }

  const getSeverityOrder = (severity: Severity): number => {
    const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
    return order[severity]
  }

  const sortedFindings = useMemo(() => {
    return [...filteredFindings].sort((a, b) => 
      getSeverityOrder(a.severity) - getSeverityOrder(b.severity)
    )
  }, [filteredFindings])

  const severityCounts = useMemo(() => ({
    all: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  }), [findings])

  if (isLoading) {
    return <LoadingState message="Loading security findings..." />
  }

  if (error) {
    return <ErrorState message="Failed to load findings" onRetry={() => refetch()} />
  }

  if (findings.length === 0) {
    return <EmptyState 
      title="No findings yet"
      description="Run a scan to discover security vulnerabilities in your AWS IAM configuration."
    />
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Filters Toolbar */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* Search */}
          <div className="relative flex-1 min-w-[250px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aide-text-muted" />
            <input
              type="text"
              placeholder="Search findings, resources, or ARNs..."
              value={filters.search}
              onChange={(e) => setFilters({ search: e.target.value })}
              className="aide-input pl-10"
            />
          </div>

          {/* Severity Filter */}
          <Select 
            value={filters.severity} 
            onValueChange={(value) => setFilters({ severity: value as Severity | 'all' })}
          >
            <SelectTrigger className="w-[160px]">
              <Filter className="w-4 h-4 mr-2 text-aide-text-muted" />
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities ({severityCounts.all})</SelectItem>
              <SelectItem value="critical">Critical ({severityCounts.critical})</SelectItem>
              <SelectItem value="high">High ({severityCounts.high})</SelectItem>
              <SelectItem value="medium">Medium ({severityCounts.medium})</SelectItem>
              <SelectItem value="low">Low ({severityCounts.low})</SelectItem>
            </SelectContent>
          </Select>

          {/* Service Filter */}
          <Select 
            value={filters.service} 
            onValueChange={(value) => setFilters({ service: value as AWSService | 'all' })}
          >
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Service" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Services</SelectItem>
              <SelectItem value="IAM">IAM</SelectItem>
              <SelectItem value="S3">S3</SelectItem>
              <SelectItem value="EC2">EC2</SelectItem>
              <SelectItem value="Lambda">Lambda</SelectItem>
              <SelectItem value="KMS">KMS</SelectItem>
            </SelectContent>
          </Select>

          {/* Status Filter */}
          <Select 
            value={filters.status} 
            onValueChange={(value) => setFilters({ status: value as any })}
          >
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="in-progress">In Progress</SelectItem>
              <SelectItem value="remediated">Remediated</SelectItem>
              <SelectItem value="suppressed">Suppressed</SelectItem>
            </SelectContent>
          </Select>

          {/* Results count */}
          <div className="text-sm text-aide-text-muted">
            Showing <span className="font-medium text-aide-text-secondary">{sortedFindings.length}</span> findings
          </div>
        </div>
      </Card>

      {/* Findings Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="aide-table">
            <thead>
              <tr>
                <th className="w-[100px]">Severity</th>
                <th className="min-w-[280px]">Finding Type</th>
                <th className="min-w-[300px]">Resource ARN</th>
                <th className="w-[100px]">Service</th>
                <th className="w-[120px]">Account ID</th>
                <th className="w-[120px]">Detected</th>
              </tr>
            </thead>
            <tbody>
              {sortedFindings.map((finding) => (
                <tr 
                  key={finding.id}
                  onClick={() => openDrawer(finding)}
                  className="group"
                >
                  <td>
                    <Badge variant={finding.severity}>
                      {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                    </Badge>
                  </td>
                  <td>
                    <div>
                      <p className="text-aide-text-primary font-medium">
                        {finding.findingType}
                      </p>
                      <p className="text-xs text-aide-text-muted mt-0.5 line-clamp-1">
                        {finding.description}
                      </p>
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center gap-2 group/arn">
                      <code className="text-xs font-mono text-aide-text-secondary bg-aide-bg-primary px-2 py-1 rounded">
                        {truncateMiddle(finding.resourceArn, 50)}
                      </code>
                      <button
                        onClick={(e) => handleCopyArn(finding.resourceArn, e)}
                        className="opacity-0 group-hover/arn:opacity-100 p-1 hover:bg-aide-bg-tertiary rounded transition-all"
                      >
                        {copiedArn === finding.resourceArn ? (
                          <Check className="w-3.5 h-3.5 text-green-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5 text-aide-text-muted" />
                        )}
                      </button>
                    </div>
                  </td>
                  <td>
                    <span className="text-aide-text-secondary">{finding.service}</span>
                  </td>
                  <td>
                    <span className="text-aide-text-muted font-mono text-xs">
                      {finding.accountId}
                    </span>
                  </td>
                  <td>
                    <span className="text-aide-text-muted text-xs">
                      {formatTimeAgo(finding.detectedAt)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {sortedFindings.length === 0 && (
            <div className="py-12 text-center">
              <p className="text-aide-text-muted">No findings match your filters</p>
              <button 
                onClick={() => setFilters({ severity: 'all', service: 'all', status: 'all', search: '' })}
                className="mt-2 text-sm text-aide-text-secondary hover:text-aide-text-primary"
              >
                Clear all filters
              </button>
            </div>
          )}
        </div>
      </Card>

      {/* Finding Detail Drawer */}
      <FindingDetailDrawer 
        finding={selectedFinding}
        isOpen={isDrawerOpen}
        onClose={closeDrawer}
      />
    </div>
  )
}
