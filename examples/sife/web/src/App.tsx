import { Link, Route, Routes, useNavigate } from 'react-router-dom';
import { getToken, logout } from './api';
import { Landing } from './pages/Landing';
import { StatusPage } from './pages/StatusPage';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Search } from './pages/Search';
import { Knowledge } from './pages/Knowledge';
import { Dashboard } from './pages/Dashboard';
import { TicketDetail } from './pages/TicketDetail';

const Header = () => {
  const navigate = useNavigate();
  const signedIn = Boolean(getToken());

  const signOut = async () => {
    await logout();
    navigate('/');
  };

  return (
    <header className="site-header">
      <Link to="/" className="brand">
        <span className="brand-mark" />
        Sife
      </Link>
      <nav>
        <Link to="/status">Status</Link>
        <Link to="/kb">Knowledge base</Link>
        <Link to="/search">Search</Link>
        {signedIn ? (
          <>
            <Link to="/app">Dashboard</Link>
            <button type="button" className="btn btn-ghost" onClick={signOut}>
              Sign out
            </button>
          </>
        ) : (
          <Link to="/login" className="btn btn-ghost">
            Sign in
          </Link>
        )}
      </nav>
    </header>
  );
};

const Footer = () => (
  <footer className="site-footer">
    <span>© {new Date().getFullYear()} Sife Ltd — Registered in England &amp; Wales.</span>
    <span>
      <Link to="/status">Status</Link> · <Link to="/kb">Docs</Link> · <a href="/privacy">Privacy</a>
    </span>
  </footer>
);

export const App = () => (
  <div className="app-shell">
    <Header />
    <main>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/status" element={<StatusPage />} />
        <Route path="/kb" element={<Knowledge />} />
        <Route path="/search" element={<Search />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/app" element={<Dashboard />} />
        <Route path="/app/tickets/:id" element={<TicketDetail />} />
      </Routes>
    </main>
    <Footer />
  </div>
);
