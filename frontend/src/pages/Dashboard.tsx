import { useState } from 'react'
import { 
  ShieldAlert, 
  AlertTriangle, 
  AlertCircle, 
  Server,
  Scan,
  Zap,
  FileText,
  Clock,
  Loader2,
  CloudOff,
  CheckCircle
} from 'lucide-react'
import { KPICard, ActionCard, Card } from '@/components/ui'
import { LoadingState, ErrorState } from '@/components/ui/States'
import { formatTimeAgo } from '@/lib/utils'
import { useNavigate } from 'react-router-dom'
import { useFindings, useStartScan } from '@/hooks/useApi'

export function Dashboard() {
  const navigate = useNavigate()
  const { data: findings = [], isLoading, error, refetch } = useFindings()
  const { mutate: startScan, isPending: isScanning } = useStartScan()
  const [lastScanResult, setLastScanResult] = useState<{status: string; error?: string} | null>(null)

  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length
  const mediumCount = findings.filter(f => f.severity === 'medium').length
  const lowCount = findings.filter(f => f.severity === 'low').length
  
  // Get unique services from findings
  const services = [...new Set(findings.map(f => f.service))]
  
  // Derive last scan info from findings data
  const lastScan = {
    completedAt: findings.length > 0 ? new Date().toISOString() : null,
    totalResources: findings.length * 5, // Approximate
    scannedServices: services.length > 0 ? services : ['IAM', 'S3', 'EC2', 'Lambda', 'KMS'],
  }

  const handleScan = (type: 'full' | 'quick') => {
    setLastScanResult(null)
    startScan(type, {
      onSuccess: (result) => {
        setLastScanResult({ status: result.status, error: result.error })
        refetch()
      },
      onError: (err) => {
        setLastScanResult({ status: 'failed', error: err.message })
      }
    })
  }

  if (isLoading) {
    return <LoadingState message="Loading security findings..." />
  }

  if (error) {
    return <ErrorState message="Failed to load findings" onRetry={() => refetch()} />
  }

  // Show empty state with prominent scan button if no findings
  if (findings.length === 0 && !isScanning) {
    return (
      <div className="space-y-6 animate-fade-in">
        {/* Scan Error Alert */}
        {lastScanResult?.status === 'failed' && (
          <div className="aide-card p-4 border-red-900/50 bg-red-950/20">
            <div className="flex items-start gap-3">
              <CloudOff className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-medium text-red-300">AWS Connection Failed</h4>
                <p className="text-xs text-aide-text-secondary mt-1">
                  {lastScanResult.error || 'Could not connect to AWS. Please check your credentials.'}
                </p>
                <p className="text-xs text-aide-text-muted mt-2">
                  Make sure your AWS credentials are configured correctly. You can use:
                </p>
                <ul className="text-xs text-aide-text-muted mt-1 list-disc list-inside">
                  <li>AWS CLI profile (configure in Settings)</li>
                  <li>Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)</li>
                  <li>IAM role (if running on AWS)</li>
                </ul>
              </div>
            </div>
          </div>
        )}
        
        {/* Welcome Message */}
        <div className="aide-card p-8 text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-cyan-950/50 flex items-center justify-center">
            <ShieldAlert className="w-8 h-8 text-cyan-400" />
          </div>
          <h2 className="text-xl font-bold text-aide-text-primary mb-2">
            Welcome to AIDE
          </h2>
          <p className="text-sm text-aide-text-secondary max-w-md mx-auto mb-6">
            Automated IAM Detection Engine - AI-powered security scanner for AWS IAM policies.
            Run your first scan to discover security vulnerabilities.
          </p>
          <button
            onClick={() => handleScan('full')}
            disabled={isScanning}
            className="aide-btn-primary text-lg px-6 py-3"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Scanning AWS...
              </>
            ) : (
              <>
                <Scan className="w-5 h-5" />
                Scan Your AWS Account
              </>
            )}
          </button>
        </div>
        
        {/* Features Info */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="p-4">
            <ShieldAlert className="w-6 h-6 text-red-400 mb-3" />
            <h3 className="text-sm font-medium text-aide-text-primary mb-1">9 Vulnerability Types</h3>
            <p className="text-xs text-aide-text-muted">
              Detects privilege escalation, wildcard admin, missing MFA, and more
            </p>
          </Card>
          <Card className="p-4">
            <Zap className="w-6 h-6 text-amber-400 mb-3" />
            <h3 className="text-sm font-medium text-aide-text-primary mb-1">AI-Powered Remediation</h3>
            <p className="text-xs text-aide-text-muted">
              Get smart policy recommendations using Gemini AI
            </p>
          </Card>
          <Card className="p-4">
            <FileText className="w-6 h-6 text-cyan-400 mb-3" />
            <h3 className="text-sm font-medium text-aide-text-primary mb-1">One-Click Fixes</h3>
            <p className="text-xs text-aide-text-muted">
              Apply remediations with Terraform or AWS CLI commands
            </p>
          </Card>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Scan Status Alert */}
      {isScanning && (
        <div className="aide-card p-4 border-cyan-900/50 bg-cyan-950/20">
          <div className="flex items-center gap-3">
            <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
            <div>
              <p className="text-sm text-aide-text-primary">Scanning AWS account...</p>
              <p className="text-xs text-aide-text-muted">Analyzing IAM policies, roles, users, and resources</p>
            </div>
          </div>
        </div>
      )}
      
      {lastScanResult?.status === 'completed' && (
        <div className="aide-card p-4 border-green-900/50 bg-green-950/20">
          <div className="flex items-center gap-3">
            <CheckCircle className="w-5 h-5 text-green-400" />
            <div>
              <p className="text-sm text-aide-text-primary">Scan completed successfully</p>
              <p className="text-xs text-aide-text-muted">Found {findings.length} security findings</p>
            </div>
          </div>
        </div>
      )}
      
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
