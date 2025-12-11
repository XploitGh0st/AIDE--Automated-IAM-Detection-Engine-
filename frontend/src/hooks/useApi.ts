import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Finding, ScanResult, RemediationRecord } from '@/types'

const API_BASE = '/api'

// Settings type
export interface Settings {
  awsProfile: string
  awsRegion: string
  multiRegionScanning: boolean
  assumeRoleArn: string | null
  geminiApiConfigured: boolean
}

// API Functions
async function fetchFindings(): Promise<Finding[]> {
  const response = await fetch(`${API_BASE}/findings`)
  if (!response.ok) throw new Error('Failed to fetch findings')
  return response.json()
}

async function fetchFinding(id: string): Promise<Finding> {
  const response = await fetch(`${API_BASE}/findings/${id}`)
  if (!response.ok) throw new Error('Failed to fetch finding')
  return response.json()
}

async function startScan(type: 'full' | 'quick' = 'full'): Promise<ScanResult> {
  const response = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type }),
  })
  if (!response.ok) throw new Error('Failed to start scan')
  return response.json()
}

async function getScanStatus(scanId: string): Promise<ScanResult> {
  const response = await fetch(`${API_BASE}/scan/${scanId}`)
  if (!response.ok) throw new Error('Failed to fetch scan status')
  return response.json()
}

async function generateRemediation(findingId: string): Promise<Finding['aiAnalysis']> {
  const response = await fetch(`${API_BASE}/findings/${findingId}/remediate`, {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to generate remediation')
  return response.json()
}

async function applyRemediation(findingId: string): Promise<RemediationRecord> {
  const response = await fetch(`${API_BASE}/findings/${findingId}/apply`, {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to apply remediation')
  return response.json()
}

async function fetchRemediationHistory(): Promise<RemediationRecord[]> {
  const response = await fetch(`${API_BASE}/remediation-history`)
  if (!response.ok) throw new Error('Failed to fetch remediation history')
  return response.json()
}

async function fetchSettings(): Promise<Settings> {
  const response = await fetch(`${API_BASE}/settings`)
  if (!response.ok) throw new Error('Failed to fetch settings')
  return response.json()
}

async function updateSettings(settings: Partial<Settings>): Promise<{ success: boolean; message: string }> {
  const response = await fetch(`${API_BASE}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  })
  if (!response.ok) throw new Error('Failed to update settings')
  return response.json()
}

async function fetchHealthCheck(): Promise<{ status: string; version: string; geminiConfigured: boolean }> {
  const response = await fetch(`${API_BASE}/health`)
  if (!response.ok) throw new Error('Failed to check health')
  return response.json()
}

// Hooks
export function useFindings() {
  return useQuery({
    queryKey: ['findings'],
    queryFn: fetchFindings,
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ['finding', id],
    queryFn: () => fetchFinding(id),
    enabled: !!id,
  })
}

export function useStartScan() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: startScan,
    onSuccess: () => {
      // Invalidate findings query to refetch after scan
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })
}

export function useScanStatus(scanId: string) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScanStatus(scanId),
    enabled: !!scanId,
    refetchInterval: (query) => {
      // Poll every 2 seconds while scan is running
      const data = query.state.data
      if (data?.status === 'running') return 2000
      return false
    },
  })
}

export function useGenerateRemediation() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: generateRemediation,
    onSuccess: (data, findingId) => {
      // Update the finding with the new AI analysis
      queryClient.setQueryData(['finding', findingId], (old: Finding | undefined) => {
        if (!old) return old
        return { ...old, aiAnalysis: data }
      })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })
}

export function useApplyRemediation() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: applyRemediation,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['remediation-history'] })
    },
  })
}

export function useRemediationHistory() {
  return useQuery({
    queryKey: ['remediation-history'],
    queryFn: fetchRemediationHistory,
  })
}

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: fetchSettings,
  })
}

export function useUpdateSettings() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: updateSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })
}

export function useHealthCheck() {
  return useQuery({
    queryKey: ['health'],
    queryFn: fetchHealthCheck,
  })
}

// Account info type
export interface AccountInfo {
  accountId: string | null
  region: string | null
  profile: string | null
  connected: boolean
  error?: string
}

async function fetchAccountInfo(): Promise<AccountInfo> {
  const response = await fetch(`${API_BASE}/account`)
  if (!response.ok) throw new Error('Failed to fetch account info')
  return response.json()
}

export function useAccountInfo() {
  return useQuery({
    queryKey: ['account'],
    queryFn: fetchAccountInfo,
    retry: false, // Don't retry if AWS connection fails
  })
}
