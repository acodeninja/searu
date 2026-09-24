import { Link, Route, Routes, useNavigate } from 'react-router-dom';
import { getRole, getToken, logout } from './api';
import { Landing } from './pages/Landing';
import { StatusPage } from './pages/StatusPage';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Reset } from './pages/Reset';
import { Billing } from './pages/Billing';
import { Search } from './pages/Search';
import { Knowledge } from './pages/Knowledge';
import { Dashboard } from './pages/Dashboard';
import { TicketDetail } from './pages/TicketDetail';
import { Admin } from './pages/Admin';

const Header = () => {
  const navigate = useNavigate();
  const signedIn = Boolean(getToken());
  const isAdmin = getRole() === 'admin';

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
            {isAdmin && <Link to="/admin">Admin</Link>}
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
        <Route path="/reset" element={<Reset />} />
        <Route path="/app" element={<Dashboard />} />
        <Route path="/billing" element={<Billing />} />
        <Route path="/app/tickets/:id" element={<TicketDetail />} />
        <Route path="/admin" element={<Admin />} />
      </Routes>
    </main>
    <Footer />
  </div>
);
