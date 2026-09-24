import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { register } from '../api';

export const Register = () => {
  const navigate = useNavigate();
  const [fields, setFields] = useState({
    email: '',
    password: '',
    full_name: '',
    organisation: '',
  });
  const [error, setError] = useState<string | null>(null);

  const update = (key: keyof typeof fields) => (event: React.ChangeEvent<HTMLInputElement>) =>
    setFields({ ...fields, [key]: event.target.value });

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    try {
      await register(fields);
      navigate('/app');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    }
  };

  return (
    <div className="auth-card">
      <h1>Create your Sife account</h1>
      <form onSubmit={submit}>
        <label>
          Full name
          <input value={fields.full_name} onChange={update('full_name')} required />
        </label>
        <label>
          Organisation
          <input value={fields.organisation} onChange={update('organisation')} />
        </label>
        <label>
          Email
          <input type="email" value={fields.email} onChange={update('email')} required />
        </label>
        <label>
          Password
          <input type="password" value={fields.password} onChange={update('password')} required />
        </label>
        {error && <p className="notice error">{error}</p>}
        <button className="btn btn-primary" type="submit">
          Create account
        </button>
      </form>
    </div>
  );
};
