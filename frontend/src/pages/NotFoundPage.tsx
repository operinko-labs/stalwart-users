import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <main className="page-card standalone-page">
      <h1>Page not found</h1>
      <p>
        The page you requested does not exist. <Link to="/">Return home</Link>.
      </p>
    </main>
  )
}
