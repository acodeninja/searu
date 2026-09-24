import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { login } from '../api';

export const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    try {
      await login(email, password);
      navigate('/app');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign in failed');
    }
  };

  return (
    <div className="auth-card">
      <h1>Sign in to Sife</h1>
      <p className="notice">Use your Sife account to manage tickets and your status page.</p>
      <form onSubmit={submit}>
        <label>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <p className="notice error">{error}</p>}
        <button className="btn btn-primary" type="submit">
          Sign in
        </button>
      </form>
      <p className="notice">
        New to Sife? <Link to="/register">Create an account</Link>. Forgotten your password?{' '}
        <Link to="/reset">Reset it</Link>.
      </p>
    </div>
  );
};
