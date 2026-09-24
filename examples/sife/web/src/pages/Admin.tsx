import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAdminSettings, getToken } from '../api';

export const Admin = () => {
  const navigate = useNavigate();
  const [settings, setSettings] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!getToken()) {
      navigate('/login');
      return;
    }
    getAdminSettings().then(setSettings).catch((err) => setError(err.message));
  }, [navigate]);

  return (
    <div className="admin-page">
      <h1>Admin settings</h1>
      <p className="notice">Operational configuration and integration credentials.</p>
      {error && <p className="notice error">{error}</p>}
      {settings && (
        <pre className="settings-dump">{JSON.stringify(settings, null, 2)}</pre>
      )}
    </div>
  );
};
