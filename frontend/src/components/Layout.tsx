import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../contexts/useAuth'

export default function Layout() {
  const { logout, user } = useAuth()

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Stalwart users</p>
          <h1 className="app-title">Mail account management</h1>
        </div>
        <div className="user-meta">
          <span>{user?.username}</span>
          <button type="button" onClick={() => void logout()}>
            Log out
          </button>
        </div>
      </header>

      <nav className="app-nav" aria-label="Primary">
        {user?.isAdmin ? <NavLink to="/accounts">Accounts</NavLink> : null}
        <NavLink to="/account">My account</NavLink>
      </nav>

      <main className="app-main">
        <Outlet />
      </main>
    </div>
  )
}
