import { Navigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../contexts/useAuth'

const ERROR_MESSAGES: Record<string, string> = {
  denied: 'Sign-in was cancelled.',
  state: 'Sign-in expired, please try again.',
  signin: 'Sign-in failed, please try again.',
  no_mailbox: 'This account has no mailbox here.',
}

export default function LoginPage() {
  const { isLoading, user, startLogin } = useAuth()
  const [searchParams] = useSearchParams()
  const errorCode = searchParams.get('error')
  // An unknown code gets the generic message.
  const error = errorCode ? (ERROR_MESSAGES[errorCode] ?? ERROR_MESSAGES.signin) : ''

  if (isLoading) {
    return <div className="page-status">Loading…</div>
  }

  if (user) {
    return <Navigate to="/" replace />
  }

  return (
    <main className="page-card standalone-page">
      <div className="login-header">
        <h1>Stalwart User Management</h1>
        <p>Sign in to your account</p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <button type="button" className="btn-primary" onClick={startLogin}>
        Sign in
      </button>
    </main>
  )
}
