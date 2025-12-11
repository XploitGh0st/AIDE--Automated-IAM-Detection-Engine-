import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'
import { 
  AlertTriangle, 
  AlertCircle, 
  Info, 
  ShieldAlert,
  type LucideIcon 
} from 'lucide-react'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full border backdrop-blur-sm transition-colors',
  {
    variants: {
      variant: {
        critical: 'text-red-300 bg-red-950/50 border-red-900',
        high: 'text-amber-300 bg-amber-950/50 border-amber-900',
        medium: 'text-slate-300 bg-slate-800/50 border-slate-700',
        low: 'text-gray-400 bg-gray-800/50 border-gray-700',
        info: 'text-blue-300 bg-blue-950/50 border-blue-900',
        success: 'text-green-300 bg-green-950/50 border-green-900',
        default: 'text-aide-text-secondary bg-aide-bg-tertiary border-aide-border-DEFAULT',
      },
      size: {
        default: 'px-2.5 py-1 text-xs',
        sm: 'px-2 py-0.5 text-xxs',
        lg: 'px-3 py-1.5 text-sm',
      }
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

const severityIcons: Record<string, LucideIcon> = {
  critical: ShieldAlert,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
}

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  showIcon?: boolean
}

export function Badge({ 
  className, 
  variant, 
  size,
  showIcon = true,
  children, 
  ...props 
}: BadgeProps) {
  const Icon = variant ? severityIcons[variant] : null

  return (
    <span className={cn(badgeVariants({ variant, size }), className)} {...props}>
      {showIcon && Icon && <Icon className="w-3 h-3" />}
      {children}
    </span>
  )
}

// Convenience components for severity badges
export function CriticalBadge({ children = 'Critical', ...props }: Omit<BadgeProps, 'variant'>) {
  return <Badge variant="critical" {...props}>{children}</Badge>
}

export function HighBadge({ children = 'High', ...props }: Omit<BadgeProps, 'variant'>) {
  return <Badge variant="high" {...props}>{children}</Badge>
}

export function MediumBadge({ children = 'Medium', ...props }: Omit<BadgeProps, 'variant'>) {
  return <Badge variant="medium" {...props}>{children}</Badge>
}

export function LowBadge({ children = 'Low', ...props }: Omit<BadgeProps, 'variant'>) {
  return <Badge variant="low" {...props}>{children}</Badge>
}
