import { useState, useEffect } from 'react'
import { 
  AlertTriangle, 
  FileCode, 
  Sparkles, 
  Tag, 
  Clock,
  Copy,
  Check,
  Terminal,
  FileText
} from 'lucide-react'
import { 
  Drawer, 
  DrawerContent, 
  DrawerHeader, 
  DrawerBody, 
  DrawerFooter,
  DrawerTitle,
  Badge
} from '@/components/ui'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { PolicyCodeBlock } from './PolicyCodeBlock'
import { PolicyDiffViewer } from './PolicyDiffViewer'
import { Finding, AIAnalysis } from '@/types'
import { formatTimeAgo, copyToClipboard } from '@/lib/utils'
import { useGenerateRemediation, useApplyRemediation } from '@/hooks/useApi'

interface FindingDetailDrawerProps {
  finding: Finding | null
  isOpen: boolean
  onClose: () => void
}

export function FindingDetailDrawer({ finding, isOpen, onClose }: FindingDetailDrawerProps) {
  const [activeTab, setActiveTab] = useState('evidence')
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const [localAiAnalysis, setLocalAiAnalysis] = useState<AIAnalysis | null>(null)
  
  const { mutate: generateRemediation, isPending: isGeneratingFix } = useGenerateRemediation()
  const { mutate: applyRemediation, isPending: isApplying } = useApplyRemediation()

  // Reset local state when finding changes
  useEffect(() => {
    if (finding?.aiAnalysis) {
      setLocalAiAnalysis(finding.aiAnalysis)
    } else {
      setLocalAiAnalysis(null)
    }
  }, [finding?.id])

  if (!finding) return null

  const handleCopy = async (text: string, field: string) => {
    await copyToClipboard(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const handleGenerateFix = () => {
    generateRemediation(finding.id, {
      onSuccess: (data) => {
        if (data) {
          setLocalAiAnalysis(data)
        }
      }
    })
  }

  const handleApplyFix = () => {
    applyRemediation(finding.id, {
      onSuccess: () => {
        onClose()
      }
    })
  }

  const aiAnalysis = localAiAnalysis || finding.aiAnalysis
  const hasAIAnalysis = !!aiAnalysis

  return (
    <Drawer open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DrawerContent width="half">
        <DrawerHeader>
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <Badge variant={finding.severity} size="lg">
                {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
              </Badge>
              <DrawerTitle>{finding.findingType}</DrawerTitle>
            </div>
            <p className="text-sm text-aide-text-secondary">{finding.description}</p>
          </div>
        </DrawerHeader>

        <DrawerBody>
          {/* Risk Explanation */}
          <div className="mb-6 p-4 rounded-aide bg-red-950/20 border border-red-900/50">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-medium text-red-300 mb-1">Why this is a risk</h4>
                <p className="text-sm text-aide-text-secondary leading-relaxed">
                  {aiAnalysis?.riskExplanation || 
                    'This configuration may expose your AWS environment to unauthorized access or privilege escalation attacks.'}
                </p>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="evidence">
                <FileCode className="w-4 h-4" />
                Evidence
              </TabsTrigger>
              <TabsTrigger value="remediation">
                <Sparkles className="w-4 h-4" />
                AI Remediation
              </TabsTrigger>
            </TabsList>

            {/* Evidence Tab */}
            <TabsContent value="evidence">
              <div className="space-y-6">
                {/* Affected Resource Details */}
                <div className="grid grid-cols-2 gap-4">
                  {/* Left Panel - Resource Details */}
                  <div className="aide-card p-4">
                    <h4 className="text-sm font-medium text-aide-text-primary mb-4 flex items-center gap-2">
                      <Tag className="w-4 h-4 text-aide-text-muted" />
                      Affected Resource Details
                    </h4>
                    <dl className="space-y-3 text-sm">
                      <div>
                        <dt className="text-aide-text-muted text-xs uppercase tracking-wider">Resource ARN</dt>
                        <dd className="mt-1 flex items-center gap-2">
                          <code className="text-xs font-mono text-aide-text-secondary bg-aide-bg-primary px-2 py-1 rounded break-all">
                            {finding.resourceArn}
                          </code>
                          <button
                            onClick={() => handleCopy(finding.resourceArn, 'arn')}
                            className="p-1 hover:bg-aide-bg-tertiary rounded flex-shrink-0"
                          >
                            {copiedField === 'arn' ? (
                              <Check className="w-3.5 h-3.5 text-green-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5 text-aide-text-muted" />
                            )}
                          </button>
                        </dd>
                      </div>
                      <div>
                        <dt className="text-aide-text-muted text-xs uppercase tracking-wider">Resource Type</dt>
                        <dd className="mt-1 text-aide-text-secondary">{finding.resourceType}</dd>
                      </div>
                      <div>
                        <dt className="text-aide-text-muted text-xs uppercase tracking-wider">Account ID</dt>
                        <dd className="mt-1 text-aide-text-secondary font-mono">{finding.accountId}</dd>
                      </div>
                      <div>
                        <dt className="text-aide-text-muted text-xs uppercase tracking-wider">Region</dt>
                        <dd className="mt-1 text-aide-text-secondary">{finding.region}</dd>
                      </div>
                      <div>
                        <dt className="text-aide-text-muted text-xs uppercase tracking-wider">Detected At</dt>
                        <dd className="mt-1 text-aide-text-secondary flex items-center gap-1">
                          <Clock className="w-3.5 h-3.5" />
                          {formatTimeAgo(finding.detectedAt)}
                        </dd>
                      </div>
                      {finding.tags && Object.keys(finding.tags).length > 0 && (
                        <div>
                          <dt className="text-aide-text-muted text-xs uppercase tracking-wider mb-2">Tags</dt>
                          <dd className="flex flex-wrap gap-1">
                            {Object.entries(finding.tags).map(([key, value]) => (
                              <span 
                                key={key}
                                className="text-xs px-2 py-0.5 bg-aide-bg-tertiary rounded text-aide-text-secondary"
                              >
                                {key}: {value}
                              </span>
                            ))}
                          </dd>
                        </div>
                      )}
                    </dl>
                  </div>

                  {/* Right Panel - Offending Policy */}
                  <div className="aide-card p-4">
                    <h4 className="text-sm font-medium text-aide-text-primary mb-4 flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-aide-text-muted" />
                      Offending Policy Snippet
                    </h4>
                    {finding.policyDocument ? (
                      <PolicyCodeBlock 
                        code={finding.policyDocument}
                        highlightLines={finding.offendingStatements}
                      />
                    ) : (
                      <div className="text-sm text-aide-text-muted py-8 text-center">
                        No policy document available
                      </div>
                    )}
                  </div>
                </div>

                {/* Offending Statements */}
                {finding.offendingStatements && finding.offendingStatements.length > 0 && (
                  <div className="aide-card p-4">
                    <h4 className="text-sm font-medium text-aide-text-primary mb-3">Specific Issues Found</h4>
                    <ul className="space-y-2">
                      {finding.offendingStatements.map((statement, idx) => (
                        <li 
                          key={idx}
                          className="flex items-start gap-2 text-sm text-aide-text-secondary"
                        >
                          <span className="w-5 h-5 rounded-full bg-red-950/50 border border-red-900 flex items-center justify-center text-xs text-red-300 flex-shrink-0">
                            {idx + 1}
                          </span>
                          <span>{statement}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </TabsContent>

            {/* AI Remediation Tab */}
            <TabsContent value="remediation">
              {hasAIAnalysis ? (
                <div className="space-y-6">
                  {/* Diff Viewer */}
                  <div className="aide-card p-4">
                    <h4 className="text-sm font-medium text-aide-text-primary mb-4 flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-amber-400" />
                      Suggested Policy Changes
                    </h4>
                    <PolicyDiffViewer
                      oldValue={finding.policyDocument || '{}'}
                      newValue={aiAnalysis?.suggestedPolicy || '{}'}
                    />
                  </div>

                  {/* AI Explanation */}
                  <div className="aide-card p-4">
                    <h4 className="text-sm font-medium text-aide-text-primary mb-3">Why This Fix Works</h4>
                    <div className="prose prose-invert prose-sm max-w-none text-aide-text-secondary">
                      <div 
                        className="whitespace-pre-wrap leading-relaxed"
                        dangerouslySetInnerHTML={{ 
                          __html: aiAnalysis?.explanation?.replace(/\*\*(.*?)\*\*/g, '<strong class="text-aide-text-primary">$1</strong>') || '' 
                        }}
                      />
                    </div>
                    <div className="mt-4 pt-4 border-t border-aide-border-DEFAULT flex items-center justify-between">
                      <span className="text-xs text-aide-text-muted">
                        Confidence Score: {Math.round((aiAnalysis?.confidenceScore || 0) * 100)}%
                      </span>
                      <span className="text-xs text-aide-text-muted">
                        Generated {aiAnalysis?.generatedAt ? formatTimeAgo(aiAnalysis.generatedAt) : 'just now'}
                      </span>
                    </div>
                  </div>

                  {/* Terraform Code */}
                  {aiAnalysis?.terraformCode && (
                    <div className="aide-card p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="text-sm font-medium text-aide-text-primary flex items-center gap-2">
                          <FileText className="w-4 h-4 text-aide-text-muted" />
                          Terraform Code
                        </h4>
                        <button
                          onClick={() => handleCopy(aiAnalysis?.terraformCode || '', 'terraform')}
                          className="aide-btn-ghost text-xs"
                        >
                          {copiedField === 'terraform' ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-green-400" />
                              Copied!
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              Copy
                            </>
                          )}
                        </button>
                      </div>
                      <PolicyCodeBlock 
                        code={aiAnalysis.terraformCode}
                        language="hcl"
                      />
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-12 text-center">
                  <Sparkles className="w-12 h-12 text-aide-text-muted mx-auto mb-4" />
                  <h4 className="text-lg font-medium text-aide-text-primary mb-2">
                    Generate AI Remediation
                  </h4>
                  <p className="text-sm text-aide-text-secondary mb-6 max-w-md mx-auto">
                    Let our AI analyze this finding and generate a secure, least-privilege policy recommendation.
                  </p>
                  <button 
                    onClick={handleGenerateFix}
                    className="aide-btn-primary"
                    disabled={isGeneratingFix}
                  >
                    {isGeneratingFix ? (
                      <>
                        <div className="w-4 h-4 border-2 border-neutral-600 border-t-white rounded-full animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-4 h-4" />
                        Generate Fix with AI
                      </>
                    )}
                  </button>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </DrawerBody>

        <DrawerFooter>
          {hasAIAnalysis && (
            <button 
              className="aide-btn-primary"
              onClick={handleApplyFix}
              disabled={isApplying}
            >
              {isApplying ? (
                <>
                  <div className="w-4 h-4 border-2 border-neutral-600 border-t-white rounded-full animate-spin" />
                  Applying...
                </>
              ) : (
                <>
                  <Check className="w-4 h-4" />
                  Apply Fix
                </>
              )}
            </button>
          )}
          {aiAnalysis?.awsCliCommand && (
            <button 
              className="aide-btn-secondary"
              onClick={() => handleCopy(aiAnalysis.awsCliCommand || '', 'cli')}
            >
              {copiedField === 'cli' ? (
                <>
                  <Check className="w-4 h-4 text-green-400" />
                  Copied!
                </>
              ) : (
                <>
                  <Terminal className="w-4 h-4" />
                  Copy AWS CLI
                </>
              )}
            </button>
          )}
          {aiAnalysis?.terraformCode && (
            <button 
              className="aide-btn-secondary"
              onClick={() => handleCopy(aiAnalysis.terraformCode || '', 'terraform-footer')}
            >
              {copiedField === 'terraform-footer' ? (
                <>
                  <Check className="w-4 h-4 text-green-400" />
                  Copied!
                </>
              ) : (
                <>
                  <FileText className="w-4 h-4" />
                  Copy Terraform
                </>
              )}
            </button>
          )}
          <button className="aide-btn-ghost ml-auto" onClick={onClose}>
            Close
          </button>
        </DrawerFooter>
      </DrawerContent>
    </Drawer>
  )
}
