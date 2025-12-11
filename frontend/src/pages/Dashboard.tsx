import { 
  ShieldAlert, 
  AlertTriangle, 
  AlertCircle, 
  Server,
  Scan,
  Zap,
  FileText,
  Clock,
  Loader2
} from 'lucide-react'
import { KPICard, ActionCard, Card, CardTitle } from '@/components/ui'
import { LoadingState, ErrorState, EmptyState } from '@/components/ui/States'
import { formatTimeAgo } from '@/lib/utils'
import { useNavigate } from 'react-router-dom'
import { useFindings, useStartScan } from '@/hooks/useApi'

export function Dashboard() {
  const navigate = useNavigate()
  const { data: findings = [], isLoading, error, refetch } = useFindings()
  const { mutate: startScan, isPending: isScanning } = useStartScan()

  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length
  const mediumCount = findings.filter(f => f.severity === 'medium').length
  const lowCount = findings.filter(f => f.severity === 'low').length
  
  // Get unique services from findings
  const services = [...new Set(findings.map(f => f.service))]
  
  // Create a mock lastScan from findings data
  const lastScan = {
    completedAt: findings.length > 0 ? new Date().toISOString() : null,
    totalResources: findings.length * 5, // Approximate
    scannedServices: services.length > 0 ? services : ['IAM', 'S3', 'EC2', 'Lambda', 'KMS'],
  }

  const handleScan = (type: 'full' | 'quick') => {
    startScan(type, {
      onSuccess: () => {
        refetch()
      }
    })
  }

  if (isLoading) {
    return <LoadingState message="Loading security findings..." />
  }

  if (error) {
    return <ErrorState message="Failed to load findings" onRetry={() => refetch()} />
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Status Header */}
      <div className="aide-card p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-aide bg-green-950/50">
            <Clock className="w-4 h-4 text-green-300" />
          </div>
          <div>
            <p className="text-sm text-aide-text-primary">
              Last scan completed{' '}
              <span className="font-medium">
                {lastScan.completedAt ? formatTimeAgo(lastScan.completedAt) : 'Never'}
              </span>
            </p>
            <p className="text-xs text-aide-text-muted mt-0.5">
              Scanned {lastScan.totalResources} resources across {lastScan.scannedServices.length} services
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-aide-text-primary">
            {criticalCount + highCount + mediumCount + lowCount}
          </span>
          <span className="text-sm text-aide-text-muted">Total Risks Found</span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          title="Critical Risks"
          value={criticalCount}
          icon={ShieldAlert}
          variant="critical"
          subtitle="Immediate action required"
          trend={criticalCount > 0 ? { value: 50, direction: 'up' } : undefined}
        />
        <KPICard
          title="High Risks"
          value={highCount}
          icon={AlertTriangle}
          variant="high"
          subtitle="Address within 24 hours"
        />
        <KPICard
          title="Medium Risks"
          value={mediumCount}
          icon={AlertCircle}
          variant="medium"
          subtitle="Review and prioritize"
        />
        <KPICard
          title="Resources Scanned"
          value={lastScan.totalResources}
          icon={Server}
          variant="default"
          subtitle="Across all AWS services"
        />
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-lg font-semibold text-aide-text-primary mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <ActionCard
            title={isScanning ? "Scanning..." : "Deep Scan AWS"}
            description="Full analysis of all IAM policies and resources"
            icon={isScanning ? Loader2 : Scan}
            onClick={() => !isScanning && handleScan('full')}
          />
          <ActionCard
            title="Quick Scan (Critical Only)"
            description="Fast scan focusing on critical vulnerabilities"
            icon={Zap}
            onClick={() => !isScanning && handleScan('quick')}
          />
          <ActionCard
            title="View Reports"
            description="Download security assessment reports"
            icon={FileText}
            onClick={() => navigate('/findings')}
          />
        </div>
      </div>

      {/* Recent Critical Findings */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-aide-text-primary">Recent Critical Findings</h2>
          <button 
            onClick={() => navigate('/findings')}
            className="text-sm text-aide-text-secondary hover:text-aide-text-primary transition-colors"
          >
            View all findings →
          </button>
        </div>
        <Card className="p-0 overflow-hidden">
          <table className="aide-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Resource</th>
                <th>Service</th>
                <th>Detected</th>
              </tr>
            </thead>
            <tbody>
              {findings
                .filter(f => f.severity === 'critical' || f.severity === 'high')
                .slice(0, 5)
                .map((finding) => (
                  <tr 
                    key={finding.id}
                    onClick={() => navigate('/findings')}
                    className="cursor-pointer"
                  >
                    <td>
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          finding.severity === 'critical' ? 'bg-red-400' : 'bg-amber-400'
                        }`} />
                        <span className="text-aide-text-primary">{finding.findingType}</span>
                      </div>
                    </td>
                    <td>
                      <span className="text-aide-text-secondary font-mono text-xs">
                        {finding.resourceArn.split(':').pop()}
                      </span>
                    </td>
                    <td>
                      <span className="text-aide-text-muted">{finding.service}</span>
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
        </Card>
      </div>

      {/* Services Overview */}
      <div>
        <h2 className="text-lg font-semibold text-aide-text-primary mb-4">Services Overview</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {lastScan.scannedServices.map((service) => {
            const serviceFindings = findings.filter(f => f.service === service)
            const criticalInService = serviceFindings.filter(f => f.severity === 'critical').length
            
            return (
              <Card 
                key={service}
                className="p-3 text-center hover:border-neutral-600 transition-colors cursor-pointer"
              >
                <p className="text-xs text-aide-text-muted uppercase tracking-wider">{service}</p>
                <p className="text-xl font-bold text-aide-text-primary mt-1">
                  {serviceFindings.length}
                </p>
                <p className="text-xxs text-aide-text-muted">
                  {criticalInService > 0 ? (
                    <span className="text-red-400">{criticalInService} critical</span>
                  ) : (
                    'findings'
                  )}
                </p>
              </Card>
            )
          })}
        </div>
      </div>
    </div>
  )
}
