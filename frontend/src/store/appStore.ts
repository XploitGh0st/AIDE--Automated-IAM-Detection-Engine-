import { create } from 'zustand'
import { Finding, FilterState, ScanResult } from '@/types'

interface AppState {
  // Findings
  findings: Finding[]
  setFindings: (findings: Finding[]) => void
  
  // Selected finding for drawer
  selectedFinding: Finding | null
  setSelectedFinding: (finding: Finding | null) => void
  isDrawerOpen: boolean
  openDrawer: (finding: Finding) => void
  closeDrawer: () => void
  
  // Filters
  filters: FilterState
  setFilters: (filters: Partial<FilterState>) => void
  resetFilters: () => void
  
  // Scan state
  currentScan: ScanResult | null
  setCurrentScan: (scan: ScanResult | null) => void
  lastScan: ScanResult | null
  setLastScan: (scan: ScanResult | null) => void
  isScanning: boolean
  setIsScanning: (scanning: boolean) => void
  
  // UI State
  isSidebarCollapsed: boolean
  toggleSidebar: () => void
}

const initialFilters: FilterState = {
  severity: 'all',
  service: 'all',
  status: 'all',
  search: '',
}

export const useAppStore = create<AppState>((set) => ({
  // Findings
  findings: [],
  setFindings: (findings) => set({ findings }),
  
  // Selected finding
  selectedFinding: null,
  setSelectedFinding: (finding) => set({ selectedFinding: finding }),
  isDrawerOpen: false,
  openDrawer: (finding) => set({ selectedFinding: finding, isDrawerOpen: true }),
  closeDrawer: () => set({ isDrawerOpen: false, selectedFinding: null }),
  
  // Filters
  filters: initialFilters,
  setFilters: (filters) => set((state) => ({ 
    filters: { ...state.filters, ...filters } 
  })),
  resetFilters: () => set({ filters: initialFilters }),
  
  // Scan state
  currentScan: null,
  setCurrentScan: (scan) => set({ currentScan: scan }),
  lastScan: null,
  setLastScan: (scan) => set({ lastScan: scan }),
  isScanning: false,
  setIsScanning: (scanning) => set({ isScanning: scanning }),
  
  // UI State
  isSidebarCollapsed: false,
  toggleSidebar: () => set((state) => ({ 
    isSidebarCollapsed: !state.isSidebarCollapsed 
  })),
}))
