import { createContext } from 'react'
import type { AuthUser } from '../api/client'

export type AuthContextValue = {
  user: AuthUser | null
  isLoading: boolean
  startLogin: () => void
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)
