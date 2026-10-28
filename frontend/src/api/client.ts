const API_BASE = import.meta.env.VITE_API_BASE || '/api'

// An API error that keeps the HTTP status and the server's error string, so callers
// can tell e.g. 401 reauth_required from 401 invalid current password.
export class ApiError extends Error {
  status: number
  code: string

  constructor(status: number, code: string) {
    super(code)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

// Sign-in is a full-page navigation to the backend, which redirects to Stalwart's login page.
export const loginUrl = `${API_BASE}/auth/login`

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText }))
    throw new ApiError(response.status, error.error || response.statusText)
  }

  if (response.status === 204) {
    return undefined as T
  }

  const contentType = response.headers.get('content-type')
  if (!contentType?.includes('application/json')) {
    return undefined as T
  }

  return response.json() as Promise<T>
}

export type AuthUser = {
  username: string
  isAdmin: boolean
  adminDomains: string[]
}

export function domainOf(name: string): string {
  const at = name.lastIndexOf('@')
  return at < 0 ? '' : name.slice(at + 1).toLowerCase()
}

// Full admins and domain admins can both use the Accounts page.
export function canManageAccounts(user: AuthUser | null): boolean {
  return !!user && (user.isAdmin || user.adminDomains.length > 0)
}

export function managesDomain(user: AuthUser | null, name: string): boolean {
  return !!user && (user.isAdmin || user.adminDomains.includes(domainOf(name)))
}

export type Account = {
  name: string
  description: string
  type: string
  quota: number
  active: boolean
}

export const api = {
  auth: {
    me: () => request<AuthUser>('/auth/me'),
    logout: () => request<void>('/auth/logout', { method: 'POST' }),
  },
  accounts: {
    list: () => request<Account[]>('/accounts'),
    get: (name: string) => request<Account>(`/accounts/${encodeURIComponent(name)}`),
    create: (data: Partial<Account> & { password?: string }) =>
      request<Account>('/accounts', { method: 'POST', body: JSON.stringify(data) }),
    update: (name: string, data: Partial<Account>) =>
      request<Account>(`/accounts/${encodeURIComponent(name)}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    delete: (name: string) => request<void>(`/accounts/${encodeURIComponent(name)}`, { method: 'DELETE' }),
    changePassword: (name: string, newPassword: string, currentPassword?: string, otpCode?: string) =>
      request<{ message: string }>(`/accounts/${encodeURIComponent(name)}/password`, {
        method: 'PUT',
        body: JSON.stringify({
          ...(currentPassword ? { current_password: currentPassword } : {}),
          new_password: newPassword,
          ...(otpCode ? { otp_code: otpCode } : {}),
        }),
      }),
    adminDomains: async (name: string) => {
      const data = await request<{ domains: string[] }>(`/accounts/${encodeURIComponent(name)}/admin-domains`)
      return data.domains
    },
    setAdminDomains: async (name: string, domains: string[]) => {
      const data = await request<{ domains: string[] }>(`/accounts/${encodeURIComponent(name)}/admin-domains`, {
        method: 'PUT',
        body: JSON.stringify({ domains }),
      })
      return data.domains
    },
  },
  emails: {
    list: async (name: string) => {
      const data = await request<{ name: string; address: string; type: string }[]>(
        `/accounts/${encodeURIComponent(name)}/emails`
      )
      return data.map((e) => e.address)
    },
    add: (name: string, address: string) =>
      request<unknown>(`/accounts/${encodeURIComponent(name)}/emails`, {
        method: 'POST',
        body: JSON.stringify({ address }),
      }),
    remove: (name: string, address: string) =>
      request<void>(`/accounts/${encodeURIComponent(name)}/emails/${encodeURIComponent(address)}`, { method: 'DELETE' }),
  },
  groups: {
    list: (name: string) => request<string[]>(`/accounts/${encodeURIComponent(name)}/groups`),
    add: (name: string, group: string) =>
      request<unknown>(`/accounts/${encodeURIComponent(name)}/groups`, {
        method: 'POST',
        body: JSON.stringify({ member_of: group }),
      }),
    remove: (name: string, group: string) =>
      request<void>(`/accounts/${encodeURIComponent(name)}/groups/${encodeURIComponent(group)}`, { method: 'DELETE' }),
  },
}
