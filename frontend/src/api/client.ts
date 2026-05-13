const API_BASE = import.meta.env.VITE_API_BASE || '/api'

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
    throw new Error(error.error || response.statusText)
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
    login: (email: string, password: string) =>
      request<AuthUser>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }),
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
    changePassword: (name: string, newPassword: string, currentPassword?: string) =>
      request<{ message: string }>(`/accounts/${encodeURIComponent(name)}/password`, {
        method: 'PUT',
        body: JSON.stringify({
          ...(currentPassword ? { current_password: currentPassword } : {}),
          new_password: newPassword,
        }),
      }),
  },
  emails: {
    list: (name: string) => request<string[]>(`/accounts/${encodeURIComponent(name)}/emails`),
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
