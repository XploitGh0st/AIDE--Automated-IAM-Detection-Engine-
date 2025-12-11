import { useState } from 'react'
import { 
  Key, 
  Cloud, 
  Bell, 
  Shield, 
  Database,
  Save,
  RefreshCw,
  Check
} from 'lucide-react'
import { Card, CardTitle } from '@/components/ui'
import { cn } from '@/lib/utils'

interface SettingSection {
  id: string
  title: string
  icon: React.ElementType
  description: string
}

const sections: SettingSection[] = [
  { id: 'aws', title: 'AWS Configuration', icon: Cloud, description: 'Manage AWS credentials and regions' },
  { id: 'notifications', title: 'Notifications', icon: Bell, description: 'Configure alerts and notifications' },
  { id: 'security', title: 'Security', icon: Shield, description: 'Security and authentication settings' },
  { id: 'database', title: 'Database', icon: Database, description: 'Database connection settings' },
]

export function Settings() {
  const [activeSection, setActiveSection] = useState('aws')
  const [isSaving, setIsSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const handleSave = async () => {
    setIsSaving(true)
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000))
    setIsSaving(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-aide-text-primary">Settings</h1>
          <p className="text-sm text-aide-text-secondary mt-1">
            Configure AIDE to match your security requirements
          </p>
        </div>
        <button 
          onClick={handleSave}
          disabled={isSaving}
          className="aide-btn-primary"
        >
          {isSaving ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : saved ? (
            <>
              <Check className="w-4 h-4" />
              Saved!
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              Save Changes
            </>
          )}
        </button>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Sidebar */}
        <div className="col-span-3">
          <Card className="p-2">
            <nav className="space-y-1">
              {sections.map((section) => (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={cn(
                    'w-full flex items-center gap-3 px-3 py-2.5 rounded-aide text-left transition-all',
                    activeSection === section.id
                      ? 'bg-aide-bg-tertiary text-aide-text-primary'
                      : 'text-aide-text-secondary hover:bg-aide-bg-tertiary/50 hover:text-aide-text-primary'
                  )}
                >
                  <section.icon className="w-4 h-4" />
                  <span className="text-sm font-medium">{section.title}</span>
                </button>
              ))}
            </nav>
          </Card>
        </div>

        {/* Content */}
        <div className="col-span-9">
          {activeSection === 'aws' && (
            <Card className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 rounded-aide bg-aide-bg-tertiary">
                  <Cloud className="w-5 h-5 text-aide-text-secondary" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-aide-text-primary">AWS Configuration</h2>
                  <p className="text-sm text-aide-text-muted">Connect and manage your AWS accounts</p>
                </div>
              </div>

              <div className="space-y-6">
                {/* AWS Profile */}
                <div>
                  <label className="block text-sm font-medium text-aide-text-primary mb-2">
                    AWS Profile Name
                  </label>
                  <input
                    type="text"
                    defaultValue="default"
                    className="aide-input max-w-md"
                    placeholder="default"
                  />
                  <p className="mt-1.5 text-xs text-aide-text-muted">
                    The AWS CLI profile to use for authentication
                  </p>
                </div>

                {/* Region */}
                <div>
                  <label className="block text-sm font-medium text-aide-text-primary mb-2">
                    Default Region
                  </label>
                  <select className="aide-input max-w-md">
                    <option value="us-east-1">US East (N. Virginia) - us-east-1</option>
                    <option value="us-west-2">US West (Oregon) - us-west-2</option>
                    <option value="eu-west-1">EU (Ireland) - eu-west-1</option>
                    <option value="ap-southeast-1">Asia Pacific (Singapore) - ap-southeast-1</option>
                  </select>
                </div>

                {/* Multi-region scanning */}
                <div className="flex items-center justify-between p-4 rounded-aide bg-aide-bg-primary border border-aide-border-DEFAULT">
                  <div>
                    <p className="text-sm font-medium text-aide-text-primary">Multi-Region Scanning</p>
                    <p className="text-xs text-aide-text-muted mt-0.5">
                      Scan resources across all enabled AWS regions
                    </p>
                  </div>
                  <button className="relative inline-flex h-6 w-11 items-center rounded-full bg-green-600 transition-colors">
                    <span className="inline-block h-4 w-4 transform rounded-full bg-white transition-transform translate-x-6" />
                  </button>
                </div>

                {/* Assumed Role */}
                <div>
                  <label className="block text-sm font-medium text-aide-text-primary mb-2">
                    Assume Role ARN (Optional)
                  </label>
                  <input
                    type="text"
                    className="aide-input"
                    placeholder="arn:aws:iam::123456789012:role/AIDESecurityAudit"
                  />
                  <p className="mt-1.5 text-xs text-aide-text-muted">
                    For cross-account scanning, enter the ARN of the role to assume
                  </p>
                </div>
              </div>
            </Card>
          )}

          {activeSection === 'notifications' && (
            <Card className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 rounded-aide bg-aide-bg-tertiary">
                  <Bell className="w-5 h-5 text-aide-text-secondary" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-aide-text-primary">Notifications</h2>
                  <p className="text-sm text-aide-text-muted">Configure how you receive alerts</p>
                </div>
              </div>

              <div className="space-y-4">
                {[
                  { label: 'Critical Findings', description: 'Immediate alerts for critical security issues', enabled: true },
                  { label: 'High Severity Findings', description: 'Alerts for high severity vulnerabilities', enabled: true },
                  { label: 'Scan Completion', description: 'Notify when security scans complete', enabled: false },
                  { label: 'Weekly Summary', description: 'Weekly digest of security posture', enabled: true },
                ].map((item, index) => (
                  <div 
                    key={index}
                    className="flex items-center justify-between p-4 rounded-aide bg-aide-bg-primary border border-aide-border-DEFAULT"
                  >
                    <div>
                      <p className="text-sm font-medium text-aide-text-primary">{item.label}</p>
                      <p className="text-xs text-aide-text-muted mt-0.5">{item.description}</p>
                    </div>
                    <button 
                      className={cn(
                        'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
                        item.enabled ? 'bg-green-600' : 'bg-aide-bg-tertiary'
                      )}
                    >
                      <span 
                        className={cn(
                          'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                          item.enabled ? 'translate-x-6' : 'translate-x-1'
                        )}
                      />
                    </button>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {activeSection === 'security' && (
            <Card className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 rounded-aide bg-aide-bg-tertiary">
                  <Shield className="w-5 h-5 text-aide-text-secondary" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-aide-text-primary">Security Settings</h2>
                  <p className="text-sm text-aide-text-muted">Authentication and access controls</p>
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-aide-text-primary mb-2">
                    <div className="flex items-center gap-2">
                      <Key className="w-4 h-4" />
                      Gemini API Key
                    </div>
                  </label>
                  <input
                    type="password"
                    defaultValue="••••••••••••••••••••"
                    className="aide-input max-w-md"
                    placeholder="Enter your Gemini API key"
                  />
                  <p className="mt-1.5 text-xs text-aide-text-muted">
                    Required for AI-powered remediation suggestions
                  </p>
                </div>

                <div className="p-4 rounded-aide bg-amber-950/20 border border-amber-900/50">
                  <p className="text-sm text-amber-300 font-medium">API Key Security</p>
                  <p className="text-xs text-aide-text-secondary mt-1">
                    Your API keys are encrypted at rest and never exposed in logs. 
                    We recommend rotating keys every 90 days.
                  </p>
                </div>
              </div>
            </Card>
          )}

          {activeSection === 'database' && (
            <Card className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 rounded-aide bg-aide-bg-tertiary">
                  <Database className="w-5 h-5 text-aide-text-secondary" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-aide-text-primary">Database Settings</h2>
                  <p className="text-sm text-aide-text-muted">Local database configuration</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="p-4 rounded-aide bg-aide-bg-primary border border-aide-border-DEFAULT">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <p className="text-sm font-medium text-aide-text-primary">SQLite Database</p>
                      <p className="text-xs text-aide-text-muted mt-0.5">Local file-based storage</p>
                    </div>
                    <span className="flex items-center gap-1.5 text-xs text-green-400">
                      <span className="w-2 h-2 bg-green-500 rounded-full" />
                      Connected
                    </span>
                  </div>
                  <div className="text-xs text-aide-text-muted font-mono bg-aide-bg-tertiary p-2 rounded">
                    ./data/aide.db
                  </div>
                </div>

                <button className="aide-btn-secondary">
                  <RefreshCw className="w-4 h-4" />
                  Reset Database
                </button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
