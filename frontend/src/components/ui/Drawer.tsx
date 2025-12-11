import * as React from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

const Drawer = DialogPrimitive.Root

const DrawerTrigger = DialogPrimitive.Trigger

const DrawerClose = DialogPrimitive.Close

const DrawerPortal = DialogPrimitive.Portal

const DrawerOverlay = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Overlay>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Overlay
    ref={ref}
    className={cn(
      'fixed inset-0 z-50 bg-black/60 backdrop-blur-sm',
      'data-[state=open]:animate-in data-[state=closed]:animate-out',
      'data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0',
      className
    )}
    {...props}
  />
))
DrawerOverlay.displayName = DialogPrimitive.Overlay.displayName

interface DrawerContentProps
  extends React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> {
  side?: 'left' | 'right'
  width?: 'sm' | 'md' | 'lg' | 'xl' | 'half'
}

const widthClasses = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-xl',
  half: 'w-1/2 max-w-none',
}

const DrawerContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  DrawerContentProps
>(({ className, side = 'right', width = 'half', children, ...props }, ref) => (
  <DrawerPortal>
    <DrawerOverlay />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        'fixed z-50 h-full bg-aide-bg-secondary border-l border-aide-border-DEFAULT',
        'shadow-aide-lg outline-none',
        'data-[state=open]:animate-slide-in-right',
        'data-[state=closed]:animate-out data-[state=closed]:slide-out-to-right',
        side === 'right' && 'inset-y-0 right-0',
        side === 'left' && 'inset-y-0 left-0 border-r border-l-0',
        widthClasses[width],
        className
      )}
      {...props}
    >
      <div className="flex flex-col h-full overflow-hidden">
        {children}
      </div>
    </DialogPrimitive.Content>
  </DrawerPortal>
))
DrawerContent.displayName = DialogPrimitive.Content.displayName

const DrawerHeader = ({
  className,
  children,
  onClose,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { onClose?: () => void }) => (
  <div
    className={cn(
      'flex items-center justify-between px-6 py-4 border-b border-aide-border-DEFAULT',
      'bg-aide-bg-secondary/80 backdrop-blur-sm',
      className
    )}
    {...props}
  >
    <div className="flex-1">{children}</div>
    <DialogPrimitive.Close className="aide-btn-ghost p-2 -mr-2">
      <X className="w-4 h-4" />
      <span className="sr-only">Close</span>
    </DialogPrimitive.Close>
  </div>
)
DrawerHeader.displayName = 'DrawerHeader'

const DrawerBody = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn('flex-1 overflow-y-auto p-6', className)}
    {...props}
  />
)
DrawerBody.displayName = 'DrawerBody'

const DrawerFooter = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      'flex items-center gap-3 px-6 py-4 border-t border-aide-border-DEFAULT',
      'bg-aide-bg-secondary/80 backdrop-blur-sm',
      className
    )}
    {...props}
  />
)
DrawerFooter.displayName = 'DrawerFooter'

const DrawerTitle = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Title>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Title
    ref={ref}
    className={cn('text-lg font-semibold text-aide-text-primary', className)}
    {...props}
  />
))
DrawerTitle.displayName = DialogPrimitive.Title.displayName

const DrawerDescription = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Description>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Description
    ref={ref}
    className={cn('text-sm text-aide-text-secondary', className)}
    {...props}
  />
))
DrawerDescription.displayName = DialogPrimitive.Description.displayName

export {
  Drawer,
  DrawerPortal,
  DrawerOverlay,
  DrawerTrigger,
  DrawerClose,
  DrawerContent,
  DrawerHeader,
  DrawerBody,
  DrawerFooter,
  DrawerTitle,
  DrawerDescription,
}
