import { Link, Route, Routes } from 'react-router-dom';
import { Landing } from './pages/Landing';
import { StatusPage } from './pages/StatusPage';

const Header = () => (
  <header className="site-header">
    <Link to="/" className="brand">
      <span className="brand-mark" />
      Sife
    </Link>
    <nav>
      <Link to="/status">Status</Link>
      <a href="/docs">Docs</a>
      <Link to="/login" className="btn btn-ghost">
        Sign in
      </Link>
    </nav>
  </header>
);

const Footer = () => (
  <footer className="site-footer">
    <span>© {new Date().getFullYear()} Sife Ltd — Registered in England &amp; Wales.</span>
    <span>
      <a href="/status">Status</a> · <a href="/docs">Docs</a> · <a href="/privacy">Privacy</a>
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
      </Routes>
    </main>
    <Footer />
  </div>
);
