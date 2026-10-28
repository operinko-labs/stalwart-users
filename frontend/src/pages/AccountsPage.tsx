import { useState, useEffect, useRef } from 'react'
import { api, type Account } from '../api/client'
import { useAuth } from '../contexts/useAuth'

export default function AccountsPage() {
  const { user } = useAuth()
  // Domain admins only see their domains' accounts and can't set quota.
  const isAdmin = !!user?.isAdmin
  const [accounts, setAccounts] = useState<Account[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Create form state
  const [showCreate, setShowCreate] = useState(false)
  const [createData, setCreateData] = useState({
    name: '',
    password: '',
    description: '',
    type: 'individual',
    quota: '',
  })
  const [createError, setCreateError] = useState<string | null>(null)
  const [createLoading, setCreateLoading] = useState(false)

  // Edit state
  const [editingAccount, setEditingAccount] = useState<string | null>(null)
  const editingRef = useRef<string | null>(null)
  const [editData, setEditData] = useState<{
    description: string
    quota: string
    // Comma-separated; null until loaded, so an early save can't clear them.
    adminDomains: string | null
  }>({
    description: '',
    quota: '',
    adminDomains: null,
  })
  const [editError, setEditError] = useState<string | null>(null)
  const [editLoading, setEditLoading] = useState(false)

  // Password reset state
  const [resetAccount, setResetAccount] = useState<string | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [resetError, setResetError] = useState<string | null>(null)
  const [resetLoading, setResetLoading] = useState(false)

  // Alias state
  const [aliasAccount, setAliasAccount] = useState<string | null>(null)
  const [accountAliases, setAccountAliases] = useState<string[]>([])
  const [aliasLoading, setAliasLoading] = useState(false)
  const [aliasError, setAliasError] = useState<string | null>(null)
  const [newAliasValue, setNewAliasValue] = useState('')
  const [addingAlias, setAddingAlias] = useState(false)

  // Group management state
  const [groupAccount, setGroupAccount] = useState<string | null>(null)
  const [accountGroups, setAccountGroups] = useState<string[]>([])
  const [groupLoading, setGroupLoading] = useState(false)
  const [groupError, setGroupError] = useState<string | null>(null)
  const [newGroupValue, setNewGroupValue] = useState('')
  const [addingGroup, setAddingGroup] = useState(false)

  const fetchAccounts = async () => {
    try {
      const data = await api.accounts.list()
      setAccounts(data)
      setError(null)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  useEffect(() => {
    api.accounts.list()
      .then(data => {
        setAccounts(data)
        setError(null)
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreateError(null)
    setCreateLoading(true)
    try {
      await api.accounts.create({
        name: createData.name,
        password: createData.password,
        description: createData.description,
        type: createData.type,
        ...(isAdmin ? { quota: createData.quota ? parseInt(createData.quota, 10) : 0 } : {}),
      })
      setShowCreate(false)
      setCreateData({ name: '', password: '', description: '', type: 'individual', quota: '' })
      await fetchAccounts()
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : String(err))
    } finally {
      setCreateLoading(false)
    }
  }

  const startEdit = (account: Account) => {
    setEditingAccount(account.name)
    setEditData({
      description: account.description,
      quota: account.quota ? account.quota.toString() : '',
      adminDomains: null,
    })
    setEditError(null)
    editingRef.current = account.name
    if (isAdmin) {
      api.accounts.adminDomains(account.name)
        .then(domains => {
          // Ignore a late answer for an account whose dialog was since replaced.
          if (editingRef.current === account.name) {
            setEditData(data => ({ ...data, adminDomains: domains.join(', ') }))
          }
        })
        .catch((err: unknown) => setEditError(err instanceof Error ? err.message : String(err)))
    }
  }

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingAccount) return
    setEditError(null)
    setEditLoading(true)
    try {
      await api.accounts.update(editingAccount, {
        description: editData.description,
        ...(isAdmin ? { quota: editData.quota ? parseInt(editData.quota, 10) : 0 } : {}),
      })
      if (isAdmin && editData.adminDomains !== null) {
        await api.accounts.setAdminDomains(
          editingAccount,
          editData.adminDomains.split(/[\s,]+/).filter(Boolean),
        )
      }
      setEditingAccount(null)
      await fetchAccounts()
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : String(err))
    } finally {
      setEditLoading(false)
    }
  }

  const handleDelete = async (name: string) => {
    if (!window.confirm(`Are you sure you want to delete account ${name}?`)) return
    try {
      await api.accounts.delete(name)
      await fetchAccounts()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : String(err))
    }
  }

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!resetAccount) return
    setResetError(null)
    setResetLoading(true)
    try {
      await api.accounts.changePassword(resetAccount, newPassword)
      setResetAccount(null)
      setNewPassword('')
      alert('Password reset successfully')
    } catch (err: unknown) {
      setResetError(err instanceof Error ? err.message : String(err))
    } finally {
      setResetLoading(false)
    }
  }

  const fetchAliases = async (accountName: string) => {
    setAliasLoading(true)
    setAliasError(null)
    try {
      const data = await api.emails.list(accountName)
      setAccountAliases(data)
    } catch (err: unknown) {
      setAliasError(err instanceof Error ? err.message : String(err))
    } finally {
      setAliasLoading(false)
    }
  }

  const handleOpenAliases = (accountName: string) => {
    setAliasAccount(accountName)
    fetchAliases(accountName)
  }

  const handleAddAlias = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!aliasAccount || !newAliasValue.trim()) return
    setAddingAlias(true)
    setAliasError(null)
    try {
      await api.emails.add(aliasAccount, newAliasValue.trim())
      setNewAliasValue('')
      await fetchAliases(aliasAccount)
    } catch (err: unknown) {
      setAliasError(err instanceof Error ? err.message : String(err))
    } finally {
      setAddingAlias(false)
    }
  }

  const handleRemoveAlias = async (address: string) => {
    if (!aliasAccount) return
    if (!window.confirm(`Are you sure you want to remove alias ${address}?`)) return
    setAliasError(null)
    try {
      await api.emails.remove(aliasAccount, address)
      await fetchAliases(aliasAccount)
    } catch (err: unknown) {
      setAliasError(err instanceof Error ? err.message : String(err))
    }
  }

  const fetchGroups = async (accountName: string) => {
    setGroupLoading(true)
    setGroupError(null)
    try {
      const groups = await api.groups.list(accountName)
      setAccountGroups(groups || [])
    } catch (err: unknown) {
      setGroupError(err instanceof Error ? err.message : String(err))
    } finally {
      setGroupLoading(false)
    }
  }

  const handleOpenGroups = (accountName: string) => {
    setGroupAccount(accountName)
    fetchGroups(accountName)
  }

  const handleAddGroup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!groupAccount || !newGroupValue.trim()) return
    setAddingGroup(true)
    setGroupError(null)
    try {
      await api.groups.add(groupAccount, newGroupValue.trim())
      setNewGroupValue('')
      await fetchGroups(groupAccount)
    } catch (err: unknown) {
      setGroupError(err instanceof Error ? err.message : String(err))
    } finally {
      setAddingGroup(false)
    }
  }

  const handleRemoveGroup = async (groupName: string) => {
    if (!groupAccount) return
    setGroupError(null)
    try {
      await api.groups.remove(groupAccount, groupName)
      await fetchGroups(groupAccount)
    } catch (err: unknown) {
      setGroupError(err instanceof Error ? err.message : String(err))
    }
  }

  const formatQuota = (quota: number) => {
    if (!quota) return 'Unlimited'
    if (quota >= 1024 * 1024 * 1024) return `${(quota / (1024 * 1024 * 1024)).toFixed(2)} GB`
    if (quota >= 1024 * 1024) return `${(quota / (1024 * 1024)).toFixed(2)} MB`
    if (quota >= 1024) return `${(quota / 1024).toFixed(2)} KB`
    return `${quota} B`
  }

  return (
    <div className="accounts-page">
      <div className="page-header">
        <h2>Accounts</h2>
        <button className="btn-primary btn-sm" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? 'Cancel' : 'Create Account'}
        </button>
      </div>

      {!isAdmin && user && (
        <p>Domains you manage: {user.adminDomains.join(', ')}</p>
      )}

      {error && <div className="error-banner">{error}</div>}

      {showCreate && (
        <div className="page-card create-section">
          <h3>Create New Account</h3>
          {createError && <div className="error-banner">{createError}</div>}
          <form onSubmit={handleCreate} className="create-form">
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Name (Email)</label>
                <input
                  type="email"
                  className="form-input"
                  required
                  value={createData.name}
                  onChange={(e) => setCreateData({ ...createData, name: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Password</label>
                <input
                  type="password"
                  className="form-input"
                  required
                  value={createData.password}
                  onChange={(e) => setCreateData({ ...createData, password: e.target.value })}
                />
              </div>
            </div>
            <div className="form-row">
               <div className="form-group">
                 <label className="form-label">Full Name</label>
                 <input
                   type="text"
                   className="form-input"
                   value={createData.description}
                   onChange={(e) => setCreateData({ ...createData, description: e.target.value })}
                 />
               </div>
              <div className="form-group">
                <label className="form-label">Type</label>
                <select
                  className="form-input"
                  value={createData.type}
                  onChange={(e) => setCreateData({ ...createData, type: e.target.value })}
                >
                  <option value="individual">Individual</option>
                  {isAdmin ? (
                    <option value="domain">Domain</option>
                  ) : (
                    <option value="group">Group</option>
                  )}
                </select>
              </div>
              {isAdmin && (
                <div className="form-group">
                  <label className="form-label">Quota (Bytes)</label>
                  <input
                    type="number"
                    className="form-input"
                    placeholder="Leave empty for unlimited"
                    value={createData.quota}
                    onChange={(e) => setCreateData({ ...createData, quota: e.target.value })}
                  />
                </div>
              )}
            </div>
            <button type="submit" className="btn-primary" disabled={createLoading}>
              {createLoading ? 'Creating...' : 'Create Account'}
            </button>
          </form>
        </div>
      )}

      <div className="page-card table-container">
        {loading ? (
          <p>Loading accounts...</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                 <th>Name</th>
                 <th>Full Name</th>
                 <th>Type</th>
                 <th>Quota</th>
                 <th>Actions</th>
               </tr>
            </thead>
            <tbody>
              {accounts.map((account) => (
                <tr key={account.name}>
                  <td>{account.name}</td>
                  <td>{account.description}</td>
                  <td><span className="badge badge-neutral">{account.type}</span></td>
                  <td>{formatQuota(account.quota)}</td>
                  <td>
                    <div className="action-buttons">
                      <button className="btn-icon" onClick={() => handleOpenGroups(account.name)} title="Manage Groups">
                        👥
                      </button>
                      <button className="btn-icon" onClick={() => handleOpenAliases(account.name)} title="Manage Aliases">
                        📧
                      </button>
                      <button className="btn-icon" onClick={() => startEdit(account)} title="Edit">
                        ✏️
                      </button>
                      <button className="btn-icon" onClick={() => setResetAccount(account.name)} title="Reset Password">
                        🔑
                      </button>
                      <button className="btn-icon btn-danger" onClick={() => handleDelete(account.name)} title="Delete">
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {accounts.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-center">No accounts found.</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Edit Modal */}
      {editingAccount && (
        <div className="modal-overlay">
          <div className="modal-content page-card">
            <h3>Edit Account: {editingAccount}</h3>
            {editError && <div className="error-banner">{editError}</div>}
             <form onSubmit={handleEdit}>
               <div className="form-group">
                 <label className="form-label">Full Name</label>
                 <input
                   type="text"
                   className="form-input"
                   value={editData.description}
                   onChange={(e) => setEditData({ ...editData, description: e.target.value })}
                 />
               </div>
              {isAdmin && (
                <div className="form-group">
                  <label className="form-label">Quota (Bytes)</label>
                  <input
                    type="number"
                    className="form-input"
                    placeholder="Leave empty for unlimited"
                    value={editData.quota}
                    onChange={(e) => setEditData({ ...editData, quota: e.target.value })}
                  />
                </div>
              )}
              {isAdmin && (
                <div className="form-group">
                  <label className="form-label">Manages domains</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder={editData.adminDomains === null ? 'Loading…' : 'e.g. client.fi, client2.fi'}
                    disabled={editData.adminDomains === null}
                    value={editData.adminDomains ?? ''}
                    onChange={(e) => setEditData({ ...editData, adminDomains: e.target.value })}
                  />
                </div>
              )}
              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setEditingAccount(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={editLoading}>
                  {editLoading ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {resetAccount && (
        <div className="modal-overlay">
          <div className="modal-content page-card">
            <h3>Reset Password: {resetAccount}</h3>
            {resetError && <div className="error-banner">{resetError}</div>}
            <form onSubmit={handleResetPassword}>
              <div className="form-group">
                <label className="form-label">New Password</label>
                <input
                  type="password"
                  className="form-input"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setResetAccount(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={resetLoading}>
                  {resetLoading ? 'Resetting...' : 'Reset Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Alias Modal */}
      {aliasAccount && (
        <div className="modal-overlay">
          <div className="modal-content page-card">
            <h3>Aliases: {aliasAccount}</h3>
            {aliasError && <div className="error-banner">{aliasError}</div>}
            
            <div className="alias-list" style={{ marginBottom: '1.5rem' }}>
              {aliasLoading ? (
                <p>Loading aliases...</p>
              ) : accountAliases.length > 0 ? (
                accountAliases.map((alias) => (
                  <div key={alias} className="alias-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
                    <span>{alias}</span>
                    <button 
                      className="btn-icon btn-danger" 
                      onClick={() => handleRemoveAlias(alias)}
                      title="Remove Alias"
                    >
                      🗑️
                    </button>
                  </div>
                ))
              ) : (
                <p>No aliases found.</p>
              )}
            </div>

            <form onSubmit={handleAddAlias} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <input
                type="email"
                className="form-input"
                placeholder="New alias email"
                required
                value={newAliasValue}
                onChange={(e) => setNewAliasValue(e.target.value)}
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn-primary" disabled={addingAlias}>
                {addingAlias ? 'Adding...' : 'Add'}
              </button>
            </form>

            <div className="modal-actions">
              <button type="button" className="btn-secondary" onClick={() => setAliasAccount(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Group Management Modal */}
      {groupAccount && (
        <div className="modal-overlay">
          <div className="modal-content page-card">
            <h3>Groups: {groupAccount}</h3>
            {groupError && <div className="error-banner">{groupError}</div>}
            
            <div className="alias-list" style={{ marginBottom: '1rem' }}>
              {groupLoading ? (
                <p>Loading groups...</p>
              ) : accountGroups.length === 0 ? (
                <p>No group memberships</p>
              ) : (
                accountGroups.map(group => (
                  <div key={group} className="alias-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', border: '1px solid #eee', marginBottom: '0.5rem', borderRadius: '4px' }}>
                    <span>• {group}</span>
                    <button 
                      className="btn-icon btn-danger" 
                      onClick={() => handleRemoveGroup(group)}
                      title="Remove from group"
                    >
                      Remove
                    </button>
                  </div>
                ))
              )}
            </div>

            <form onSubmit={handleAddGroup} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
              <input
                type="text"
                className="form-input"
                placeholder="group name"
                value={newGroupValue}
                onChange={(e) => setNewGroupValue(e.target.value)}
                required
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn-primary" disabled={addingGroup}>
                {addingGroup ? 'Adding...' : 'Add'}
              </button>
            </form>

            <div className="modal-actions">
              <button type="button" className="btn-secondary" onClick={() => setGroupAccount(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
