import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { canManageAccounts } from '../api/client'
import { useAuth } from '../contexts/useAuth'

type ProtectedRouteProps = {
  children: ReactNode
  requireManager?: boolean
}

export default function ProtectedRoute({ children, requireManager = false }: ProtectedRouteProps) {
  const { isLoading, user } = useAuth()

  if (isLoading) {
    return <div className="page-status">Loading…</div>
  }

  if (!user) {
    return <Navigate to="/login" replace />
  }

  if (requireManager && !canManageAccounts(user)) {
    return <Navigate to="/account" replace />
  }

  return <>{children}</>
}
