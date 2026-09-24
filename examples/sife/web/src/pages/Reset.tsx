import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { performReset, requestReset } from '../api';

export const Reset = () => {
  const [params] = useSearchParams();
  const token = params.get('token');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const request = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    try {
      await requestReset(email);
      setMessage('If that email is registered, a reset link is on its way.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed');
    }
  };

  const reset = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    try {
      await performReset(token ?? '', password);
      setMessage('Your password has been reset. You can now sign in.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset failed');
    }
  };

  return (
    <div className="auth-card">
      <h1>Reset your password</h1>
      {message && <p className="notice">{message}</p>}
      {error && <p className="notice error">{error}</p>}
      {token ? (
        <form onSubmit={reset}>
          <label>
            New password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </label>
          <button className="btn btn-primary" type="submit">
            Set new password
          </button>
        </form>
      ) : (
        <form onSubmit={request}>
          <label>
            Email
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </label>
          <button className="btn btn-primary" type="submit">
            Send reset link
          </button>
        </form>
      )}
    </div>
  );
};
