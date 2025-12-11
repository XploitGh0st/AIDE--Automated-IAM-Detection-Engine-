import { Routes, Route } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout'
import { Dashboard } from './pages/Dashboard'
import { Findings } from './pages/Findings'
import { RemediationHistory } from './pages/RemediationHistory'
import { Settings } from './pages/Settings'

function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/remediation-history" element={<RemediationHistory />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </AppLayout>
  )
}

export default App
