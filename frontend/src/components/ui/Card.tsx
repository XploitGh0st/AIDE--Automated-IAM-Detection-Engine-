import { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { LucideIcon } from 'lucide-react'

interface CardProps {
  children: ReactNode
  className?: string
}

export function Card({ children, className }: CardProps) {
  return (
    <div className={cn('aide-card p-4', className)}>
      {children}
    </div>
  )
}

interface CardHeaderProps {
  children: ReactNode
  className?: string
}

export function CardHeader({ children, className }: CardHeaderProps) {
  return (
    <div className={cn('flex items-center justify-between mb-3', className)}>
      {children}
    </div>
  )
}

interface CardTitleProps {
  children: ReactNode
  className?: string
}

export function CardTitle({ children, className }: CardTitleProps) {
  return (
    <h3 className={cn('text-sm font-medium text-aide-text-secondary', className)}>
      {children}
    </h3>
  )
}

interface CardContentProps {
  children: ReactNode
  className?: string
}

export function CardContent({ children, className }: CardContentProps) {
  return (
    <div className={cn('', className)}>
      {children}
    </div>
  )
}

// KPI Card Component
interface KPICardProps {
  title: string
  value: number | string
  subtitle?: string
  icon?: LucideIcon
  trend?: {
    value: number
    direction: 'up' | 'down' | 'neutral'
  }
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'success'
  className?: string
}

const variantStyles = {
  default: 'border-aide-border-DEFAULT',
  critical: 'border-red-900/50 bg-red-950/20',
  high: 'border-amber-900/50 bg-amber-950/20',
  medium: 'border-slate-700/50 bg-slate-800/20',
  low: 'border-gray-700/50 bg-gray-800/20',
  success: 'border-green-900/50 bg-green-950/20',
}

const iconVariantStyles = {
  default: 'bg-aide-bg-tertiary text-aide-text-secondary',
  critical: 'bg-red-950/50 text-red-300',
  high: 'bg-amber-950/50 text-amber-300',
  medium: 'bg-slate-800/50 text-slate-300',
  low: 'bg-gray-800/50 text-gray-400',
  success: 'bg-green-950/50 text-green-300',
}

const valueVariantStyles = {
  default: 'text-aide-text-primary',
  critical: 'text-red-300',
  high: 'text-amber-300',
  medium: 'text-slate-300',
  low: 'text-gray-400',
  success: 'text-green-300',
}

export function KPICard({ 
  title, 
  value, 
  subtitle,
  icon: Icon, 
  trend,
  variant = 'default',
  className 
}: KPICardProps) {
  return (
    <div className={cn(
      'aide-card p-5 flex items-start justify-between',
      variantStyles[variant],
      className
    )}>
      <div className="flex-1">
        <p className="text-xs font-medium text-aide-text-muted uppercase tracking-wider mb-2">
          {title}
        </p>
        <p className={cn(
          'text-3xl font-bold tracking-tight',
          valueVariantStyles[variant]
        )}>
          {value}
        </p>
        {subtitle && (
          <p className="text-xs text-aide-text-muted mt-1">
            {subtitle}
          </p>
        )}
        {trend && (
          <div className={cn(
            'flex items-center gap-1 mt-2 text-xs',
            trend.direction === 'up' && 'text-red-400',
            trend.direction === 'down' && 'text-green-400',
            trend.direction === 'neutral' && 'text-aide-text-muted'
          )}>
            <span>
              {trend.direction === 'up' && '↑'}
              {trend.direction === 'down' && '↓'}
              {trend.direction === 'neutral' && '→'}
            </span>
            <span>{trend.value}% from last scan</span>
          </div>
        )}
      </div>
      {Icon && (
        <div className={cn(
          'p-2.5 rounded-aide',
          iconVariantStyles[variant]
        )}>
          <Icon className="w-5 h-5" />
        </div>
      )}
    </div>
  )
}

// Action Card Component
interface ActionCardProps {
  title: string
  description?: string
  icon?: LucideIcon
  onClick?: () => void
  className?: string
}

export function ActionCard({ 
  title, 
  description, 
  icon: Icon,
  onClick,
  className 
}: ActionCardProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'aide-card p-4 text-left w-full transition-all duration-150',
        'hover:bg-aide-bg-tertiary hover:border-neutral-600',
        'focus:outline-none focus:ring-2 focus:ring-neutral-500 focus:ring-offset-2 focus:ring-offset-aide-bg-primary',
        className
      )}
    >
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="p-2 rounded-aide bg-aide-bg-tertiary">
            <Icon className="w-4 h-4 text-aide-text-secondary" />
          </div>
        )}
        <div>
          <p className="text-sm font-medium text-aide-text-primary">{title}</p>
          {description && (
            <p className="text-xs text-aide-text-muted mt-0.5">{description}</p>
          )}
        </div>
      </div>
    </button>
  )
}
