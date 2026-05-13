import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../contexts/useAuth'

type ProtectedRouteProps = {
  children: ReactNode
  requireAdmin?: boolean
}

export default function ProtectedRoute({ children, requireAdmin = false }: ProtectedRouteProps) {
  const { isLoading, user } = useAuth()

  if (isLoading) {
    return <div className="page-status">Loading…</div>
  }

  if (!user) {
    return <Navigate to="/login" replace />
  }

  if (requireAdmin && !user.isAdmin) {
    return <Navigate to="/account" replace />
  }

  return <>{children}</>
}
