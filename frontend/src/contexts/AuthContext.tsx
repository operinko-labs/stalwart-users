import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, loginUrl, type AuthUser } from '../api/client'
import { AuthContext } from './auth-context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    let isMounted = true

    const loadUser = async () => {
      try {
        const currentUser = await api.auth.me()
        if (isMounted) {
          setUser(currentUser)
        }
      } catch {
        if (isMounted) {
          setUser(null)
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    void loadUser()

    return () => {
      isMounted = false
    }
  }, [])

  const startLogin = useCallback(() => {
    window.location.assign(loginUrl)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.auth.logout()
    } finally {
      setUser(null)
    }
  }, [])

  const value = useMemo(
    () => ({ user, isLoading, startLogin, logout }),
    [isLoading, startLogin, logout, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
