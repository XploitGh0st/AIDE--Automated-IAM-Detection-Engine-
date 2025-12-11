# AIDE Frontend - Enterprise Security Dashboard

A professional, ultra-modern React dashboard for the Automated IAM Detection Engine.

## Tech Stack

- **Framework**: React 18+ with TypeScript
- **Build Tool**: Vite 5
- **Styling**: Tailwind CSS with custom grayscale theme
- **UI Components**: Shadcn/Radix primitives (customized)
- **State Management**: Zustand
- **Data Fetching**: TanStack Query (React Query)
- **Syntax Highlighting**: react-syntax-highlighter
- **Diff Viewer**: react-diff-viewer-continued
- **Icons**: Lucide React

## Design Philosophy

### Professional Monochrome Theme

The UI follows a strict grayscale palette designed for enterprise security products:

- **Backgrounds**: Layered dark mode (`neutral-950`, `neutral-900`, `neutral-800`)
- **Text**: High contrast for readability (`neutral-100` primary, `neutral-400` secondary)
- **Status Indicators**: Muted metallic tones
  - Critical: Muted Rust/Crimson Gray
  - High: Muted Amber/Bronze Gray
  - Medium: Muted Slate Gray
  - Low: Cool Gray

## Project Structure

```
frontend/
├── public/
│   └── aide-logo.svg        # AIDE logo
├── src/
│   ├── components/
│   │   ├── layout/
│   │   │   └── AppLayout.tsx     # Main layout with sidebar
│   │   ├── findings/
│   │   │   ├── FindingDetailDrawer.tsx
│   │   │   ├── PolicyCodeBlock.tsx
│   │   │   └── PolicyDiffViewer.tsx
│   │   └── ui/
│   │       ├── Badge.tsx         # Severity badges
│   │       ├── Card.tsx          # Cards & KPI cards
│   │       ├── Drawer.tsx        # Slide-out panels
│   │       ├── Select.tsx        # Dropdown selects
│   │       └── Tabs.tsx          # Tab components
│   ├── data/
│   │   └── mockData.ts           # Mock data for development
│   ├── hooks/
│   │   └── useApi.ts             # API hooks with React Query
│   ├── lib/
│   │   └── utils.ts              # Utility functions
│   ├── pages/
│   │   ├── Dashboard.tsx         # Landing page
│   │   ├── Findings.tsx          # Findings data grid
│   │   ├── RemediationHistory.tsx
│   │   └── Settings.tsx
│   ├── store/
│   │   └── appStore.ts           # Zustand store
│   ├── types/
│   │   └── index.ts              # TypeScript types
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css                 # Tailwind + custom styles
├── index.html
├── package.json
├── tailwind.config.ts
├── tsconfig.json
└── vite.config.ts
```

## Setup Instructions

### Prerequisites

- Node.js 18+ 
- npm or yarn
- AIDE backend running on port 5000

### Installation

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The development server will start at `http://localhost:3000`.

### Building for Production

```bash
npm run build
```

The built files will be in the `dist/` directory.

## Key Features

### 1. Dashboard
- Executive summary with last scan status
- KPI cards for Critical, High, Medium risks and scanned resources
- Quick action buttons for scans and reports
- Recent critical findings table
- Services overview grid

### 2. Findings Data Grid
- Advanced filtering by severity, service, and status
- Full-text search across findings
- Sortable columns
- Copy-to-clipboard for resource ARNs
- Click-to-open detail drawer

### 3. Finding Detail Drawer
- Risk explanation panel
- Evidence tab with resource details and policy viewer
- AI Remediation tab with:
  - Side-by-side policy diff viewer
  - AI-generated explanation
  - Terraform code generation
  - AWS CLI command preview

### 4. Policy Viewers
- Syntax-highlighted JSON with custom dark theme
- Line highlighting for problematic statements
- Professional diff viewer for before/after comparison

## API Integration

The frontend expects a REST API at `/api` with these endpoints:

```
GET  /api/findings           - List all findings
GET  /api/findings/:id       - Get single finding
POST /api/scan               - Start new scan
GET  /api/scan/:id           - Get scan status
POST /api/findings/:id/remediate - Generate AI remediation
POST /api/findings/:id/apply     - Apply remediation
GET  /api/remediation-history    - List remediation history
```

## Customization

### Adding New Severity Variants

Edit `tailwind.config.ts` under `theme.extend.colors.aide.status`:

```typescript
status: {
  newLevel: {
    text: '#...', 
    bg: 'rgba(...)',
    border: '#...',
  }
}
```

### Modifying Theme

The theme is centralized in:
- `tailwind.config.ts` - Color palette and design tokens
- `src/index.css` - Component-level styles with `@apply`

## Development Notes

- All lint errors before `npm install` are expected (missing type declarations)
- The frontend uses path aliases (`@/` → `./src/`)
- Mock data is provided for development without backend
- Zustand store persists filter state across navigation
