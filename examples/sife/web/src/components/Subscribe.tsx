import { useState } from 'react';
import { subscribeStatus } from '../api';

export const Subscribe = () => {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      await subscribeStatus(email, []);
      setMessage('You are subscribed to status updates.');
      setEmail('');
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Could not subscribe');
    }
  };

  return (
    <form className="subscribe-box" onSubmit={submit}>
      <label>
        Get status updates by email
        <div className="subscribe-row">
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@example.com"
            required
          />
          <button className="btn btn-primary" type="submit">
            Subscribe
          </button>
        </div>
      </label>
      {message && <p className="notice">{message}</p>}
    </form>
  );
};
