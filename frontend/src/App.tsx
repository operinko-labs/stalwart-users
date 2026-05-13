import { Navigate, Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import Layout from './components/Layout'
import { useAuth } from './contexts/useAuth'
import AccountsPage from './pages/AccountsPage'
import LoginPage from './pages/LoginPage'
import MyAccountPage from './pages/MyAccountPage'
import NotFoundPage from './pages/NotFoundPage'

function HomeRedirect() {
  const { isLoading, user } = useAuth()

  if (isLoading) {
    return <div className="page-status">Loading…</div>
  }

  if (!user) {
    return <Navigate to="/login" replace />
  }

  return <Navigate to={user.isAdmin ? '/accounts' : '/account'} replace />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<HomeRedirect />} />
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route
          path="/accounts"
          element={
            <ProtectedRoute requireAdmin>
              <AccountsPage />
            </ProtectedRoute>
          }
        />
        <Route path="/account" element={<MyAccountPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
