import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Professional Monochrome Palette
        aide: {
          // Backgrounds - Layered dark mode
          bg: {
            primary: '#0a0a0a',    // neutral-950 - main background
            secondary: '#171717',  // neutral-900 - cards/panels
            tertiary: '#262626',   // neutral-800 - hover states/inputs
            elevated: '#1a1a1a',   // slightly elevated surfaces
          },
          // Text - High contrast
          text: {
            primary: '#f5f5f5',    // neutral-100 - primary headings
            secondary: '#a3a3a3',  // neutral-400 - secondary metadata/labels
            muted: '#737373',      // neutral-500 - disabled/muted text
            inverse: '#0a0a0a',    // for light backgrounds
          },
          // Borders/Dividers - Subtle
          border: {
            DEFAULT: '#262626',    // neutral-800
            subtle: '#1f1f1f',     // even more subtle
            focus: '#404040',      // neutral-700 for focus states
          },
          // Status Indicators - Muted metallic tones
          status: {
            // Critical - Muted Rust/Crimson Gray
            critical: {
              text: '#fca5a5',      // red-300
              bg: 'rgba(127, 29, 29, 0.5)', // red-950/50
              border: '#7f1d1d',   // red-900
            },
            // High - Muted Amber/Bronze Gray
            high: {
              text: '#fcd34d',      // amber-300
              bg: 'rgba(120, 53, 15, 0.5)', // amber-950/50
              border: '#78350f',   // amber-900
            },
            // Medium - Muted Slate Gray
            medium: {
              text: '#cbd5e1',      // slate-300
              bg: 'rgba(30, 41, 59, 0.5)', // slate-800/50
              border: '#334155',   // slate-700
            },
            // Low - Muted cool gray
            low: {
              text: '#9ca3af',      // gray-400
              bg: 'rgba(31, 41, 55, 0.5)', // gray-800/50
              border: '#374151',   // gray-700
            },
            // Info - Muted steel blue
            info: {
              text: '#93c5fd',      // blue-300
              bg: 'rgba(30, 58, 138, 0.5)', // blue-950/50
              border: '#1e3a8a',   // blue-900
            },
            // Success - Muted sage green
            success: {
              text: '#86efac',      // green-300
              bg: 'rgba(20, 83, 45, 0.5)', // green-950/50
              border: '#14532d',   // green-900
            },
          },
          // Accent - Subtle highlights
          accent: {
            primary: '#525252',    // neutral-600 for primary actions
            hover: '#404040',      // neutral-700 for hover
            active: '#3f3f3f',     // slightly lighter for active
            glow: 'rgba(255, 255, 255, 0.05)', // subtle glow effect
          },
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      fontSize: {
        'xxs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      boxShadow: {
        'aide-sm': '0 1px 2px 0 rgba(0, 0, 0, 0.3)',
        'aide-md': '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
        'aide-lg': '0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -4px rgba(0, 0, 0, 0.4)',
        'aide-glow': '0 0 20px rgba(255, 255, 255, 0.03)',
        'aide-inset': 'inset 0 1px 0 rgba(255, 255, 255, 0.03)',
      },
      backgroundImage: {
        'aide-gradient': 'linear-gradient(180deg, rgba(255, 255, 255, 0.02) 0%, transparent 100%)',
        'aide-gradient-radial': 'radial-gradient(ellipse at top, rgba(255, 255, 255, 0.03) 0%, transparent 50%)',
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-in-right': 'slideInRight 0.3s ease-out',
        'slide-in-up': 'slideInUp 0.2s ease-out',
        'pulse-subtle': 'pulseSubtle 2s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideInRight: {
          '0%': { transform: 'translateX(100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        slideInUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.7' },
        },
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
      },
      borderRadius: {
        'aide': '0.375rem',
      },
    },
  },
  plugins: [],
}

export default config
