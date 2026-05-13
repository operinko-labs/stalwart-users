import { useEffect, useState } from 'react'
import { api, type Account } from '../api/client'
import { useAuth } from '../contexts/useAuth'

export default function MyAccountPage() {
  const { user } = useAuth()
  const [account, setAccount] = useState<Account | null>(null)
  const [aliases, setAliases] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Password form state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isChangingPassword, setIsChangingPassword] = useState(false)
  const [passwordError, setPasswordError] = useState('')
  const [passwordSuccess, setPasswordSuccess] = useState('')

  // Alias form state
  const [newAlias, setNewAlias] = useState('')
  const [isAddingAlias, setIsAddingAlias] = useState(false)
  const [aliasError, setAliasError] = useState('')
  const [removingAlias, setRemovingAlias] = useState<string | null>(null)

  // Description edit state
  const [isEditingDesc, setIsEditingDesc] = useState(false)
  const [editDescValue, setEditDescValue] = useState('')
  const [isSavingDesc, setIsSavingDesc] = useState(false)

  useEffect(() => {
    if (!user?.username) return

    let isMounted = true

    const loadData = async () => {
      try {
        const [accountData, aliasesData] = await Promise.all([
          api.accounts.get(user.username),
          api.emails.list(user.username),
        ])
        if (isMounted) {
          setAccount(accountData)
          setAliases(aliasesData)
          setEditDescValue(accountData.description)
        }
      } catch (err: unknown) {
        if (isMounted) {
          setError((err as Error).message || 'Failed to load account details')
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    void loadData()

    return () => {
      isMounted = false
    }
  }, [user?.username])

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user?.username) return

    setPasswordError('')
    setPasswordSuccess('')

    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match')
      return
    }

    if (!currentPassword) {
      setPasswordError('Current password is required')
      return
    }

    setIsChangingPassword(true)
    try {
      await api.accounts.changePassword(user.username, newPassword, currentPassword)
      setPasswordSuccess('Password changed successfully')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err: unknown) {
      setPasswordError((err as Error).message || 'Failed to change password')
    } finally {
      setIsChangingPassword(false)
    }
  }

  const handleAddAlias = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user?.username || !newAlias.trim()) return

    setAliasError('')
    setIsAddingAlias(true)
    try {
      await api.emails.add(user.username, newAlias.trim())
      const updatedAliases = await api.emails.list(user.username)
      setAliases(updatedAliases)
      setNewAlias('')
    } catch (err: unknown) {
      setAliasError((err as Error).message || 'Failed to add alias')
    } finally {
      setIsAddingAlias(false)
    }
  }

  const handleRemoveAlias = async (address: string) => {
    if (!user?.username) return

    setAliasError('')
    setRemovingAlias(address)
    try {
      await api.emails.remove(user.username, address)
      const updatedAliases = await api.emails.list(user.username)
      setAliases(updatedAliases)
    } catch (err: unknown) {
      setAliasError((err as Error).message || 'Failed to remove alias')
    } finally {
      setRemovingAlias(null)
    }
  }

  const handleSaveDescription = async () => {
    if (!user?.username || !account) return

    setIsSavingDesc(true)
    try {
      await api.accounts.update(user.username, { description: editDescValue })
      setAccount({ ...account, description: editDescValue })
      setIsEditingDesc(false)
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to update description')
    } finally {
      setIsSavingDesc(false)
    }
  }

  if (isLoading) {
    return <div className="page-status">Loading account details...</div>
  }

  if (error && !account) {
    return <div className="page-status error-banner">{error}</div>
  }

  if (!account) {
    return <div className="page-status">Account not found</div>
  }

  return (
    <div className="my-account-page">
      {error && <div className="error-banner">{error}</div>}

      <section className="page-card page-section">
        <h2>Account Details</h2>
        <div className="detail-grid" style={{ marginTop: '1.5rem' }}>
          <div className="detail-item">
            <span className="detail-label">Name</span>
            <span className="detail-value">{account.name}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Type</span>
            <span className="detail-value">{account.type}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Status</span>
            <span className="detail-value">
              {account.active ? 'Active' : 'Inactive'}
            </span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Quota</span>
            <span className="detail-value">
              {account.quota === 0 ? 'Unlimited' : `${(account.quota / 1024 / 1024).toFixed(2)} MB`}
            </span>
          </div>
        </div>

        <div className="detail-item" style={{ marginTop: '1rem' }}>
          <span className="detail-label">Description</span>
          {isEditingDesc ? (
            <div className="flex-row" style={{ marginTop: '0.5rem' }}>
              <div className="form-group">
                <input
                  type="text"
                  className="form-input"
                  value={editDescValue}
                  onChange={(e) => setEditDescValue(e.target.value)}
                  disabled={isSavingDesc}
                />
              </div>
              <button
                className="btn-primary"
                onClick={handleSaveDescription}
                disabled={isSavingDesc}
              >
                {isSavingDesc ? 'Saving...' : 'Save'}
              </button>
              <button
                className="btn-danger"
                onClick={() => {
                  setIsEditingDesc(false)
                  setEditDescValue(account.description)
                }}
                disabled={isSavingDesc}
              >
                Cancel
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.25rem' }}>
              <span className="detail-value">{account.description || <em style={{ color: '#64748b' }}>No description</em>}</span>
              <button
                className="btn-primary"
                style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem', width: 'auto' }}
                onClick={() => setIsEditingDesc(true)}
              >
                Edit
              </button>
            </div>
          )}
        </div>
      </section>

      <section className="page-card page-section">
        <h2>Change Password</h2>
        <p style={{ marginBottom: '1.5rem' }}>Update your account password.</p>

        {passwordError && <div className="error-banner">{passwordError}</div>}
        {passwordSuccess && <div className="success-banner">{passwordSuccess}</div>}

        <form onSubmit={handlePasswordChange}>
          <div className="form-group">
            <label className="form-label" htmlFor="currentPassword">Current Password</label>
            <input
              id="currentPassword"
              type="password"
              className="form-input"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              disabled={isChangingPassword}
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="newPassword">New Password</label>
            <input
              id="newPassword"
              type="password"
              className="form-input"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              disabled={isChangingPassword}
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="confirmPassword">Confirm New Password</label>
            <input
              id="confirmPassword"
              type="password"
              className="form-input"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              disabled={isChangingPassword}
            />
          </div>
          <button
            type="submit"
            className="btn-primary"
            disabled={isChangingPassword || !currentPassword || !newPassword || !confirmPassword}
            style={{ marginTop: '1rem' }}
          >
            {isChangingPassword ? 'Changing Password...' : 'Change Password'}
          </button>
        </form>
      </section>

      <section className="page-card page-section">
        <h2>Email Aliases</h2>
        <p style={{ marginBottom: '1.5rem' }}>Manage email addresses associated with your account.</p>

        {aliasError && <div className="error-banner">{aliasError}</div>}

        {aliases.length > 0 ? (
          <ul className="alias-list">
            {aliases.map((alias) => {
              const isPrimary = alias === account.name
              return (
                <li key={alias} className={`alias-item ${isPrimary ? 'primary' : ''}`}>
                  <div>
                    <span>{alias}</span>
                    {isPrimary && <span className="alias-badge">Primary</span>}
                  </div>
                  {!isPrimary && (
                    <button
                      className="btn-danger"
                      onClick={() => handleRemoveAlias(alias)}
                      disabled={removingAlias === alias}
                      title="Remove alias"
                    >
                      {removingAlias === alias ? 'Removing...' : 'Remove'}
                    </button>
                  )}
                </li>
              )
            })}
          </ul>
        ) : (
          <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>No aliases found.</p>
        )}

        <form onSubmit={handleAddAlias} className="flex-row">
          <div className="form-group">
            <label className="form-label" htmlFor="newAlias">Add New Alias</label>
            <input
              id="newAlias"
              type="email"
              className="form-input"
              placeholder="alias@example.com"
              value={newAlias}
              onChange={(e) => setNewAlias(e.target.value)}
              required
              disabled={isAddingAlias}
            />
          </div>
          <button
            type="submit"
            className="btn-primary"
            disabled={isAddingAlias || !newAlias.trim()}
          >
            {isAddingAlias ? 'Adding...' : 'Add Alias'}
          </button>
        </form>
      </section>
    </div>
  )
}
