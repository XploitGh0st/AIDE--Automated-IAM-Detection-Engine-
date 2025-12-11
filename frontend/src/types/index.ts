export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type FindingStatus = 'open' | 'remediated' | 'suppressed' | 'in-progress'

export type AWSService = 'IAM' | 'S3' | 'EC2' | 'Lambda' | 'RDS' | 'KMS' | 'CloudTrail'

export interface Finding {
  id: string
  severity: Severity
  findingType: string
  description: string
  resourceArn: string
  resourceType: string
  accountId: string
  region: string
  detectedAt: string
  status: FindingStatus
  service: AWSService
  
  // Evidence
  policyDocument?: string
  offendingStatements?: string[]
  affectedResources?: AffectedResource[]
  
  // AI Remediation
  aiAnalysis?: AIAnalysis
  
  // Tags
  tags?: Record<string, string>
}

export interface AffectedResource {
  arn: string
  type: string
  name: string
  lastUsed?: string
  tags?: Record<string, string>
}

export interface AIAnalysis {
  riskExplanation: string
  suggestedPolicy: string
  explanation: string
  confidenceScore: number
  terraformCode?: string
  awsCliCommand?: string
  generatedAt: string
}

export interface ScanResult {
  id: string
  startedAt: string
  completedAt?: string
  status: 'running' | 'completed' | 'failed'
  error?: string
  totalResources: number
  findings: {
    critical: number
    high: number
    medium: number
    low: number
  }
  scannedServices: AWSService[]
}

export interface RemediationRecord {
  id: string
  findingId: string
  findingType: string
  resourceArn: string
  severity: Severity
  originalPolicy: string
  remediatedPolicy: string
  appliedAt: string
  appliedBy: string
  status: 'applied' | 'pending' | 'failed' | 'rolled-back'
}

export interface FilterState {
  severity: Severity | 'all'
  service: AWSService | 'all'
  status: FindingStatus | 'all'
  search: string
}
