import { useEffect, useState } from 'react';
import { getStatus, type StatusPage as StatusPageData } from '../api';

const statusLabel: Record<string, string> = {
  operational: 'All systems operational',
  degraded_performance: 'Degraded performance',
  partial_outage: 'Partial outage',
  major_outage: 'Major outage',
};

const componentLabel: Record<string, string> = {
  operational: 'Operational',
  degraded_performance: 'Degraded',
  partial_outage: 'Partial outage',
  major_outage: 'Major outage',
};

export const StatusPage = () => {
  const [data, setData] = useState<StatusPageData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStatus().then(setData).catch((err) => setError(err.message));
  }, []);

  if (error) {
    return <p className="notice error">Could not load status: {error}</p>;
  }
  if (!data) {
    return <p className="notice">Loading status…</p>;
  }

  return (
    <div className="status-page">
      <div className={`status-banner ${data.status}`}>
        {statusLabel[data.status] ?? data.status}
      </div>

      <section>
        <h2>Components</h2>
        <ul className="component-list">
          {data.components.map((component) => (
            <li key={component.id}>
              <span>{component.name}</span>
              <span className={`pill ${component.status}`}>
                {componentLabel[component.status] ?? component.status}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Recent incidents</h2>
        {data.incidents.length === 0 && <p className="notice">No incidents reported.</p>}
        {data.incidents.map((incident) => (
          <article key={incident.id} className="incident-card">
            <header>
              <h3>{incident.title}</h3>
              <span className={`pill severity-${incident.severity}`}>{incident.severity}</span>
            </header>
            <p>{incident.body}</p>
            <ol className="timeline">
              {incident.updates.map((update, index) => (
                <li key={index}>
                  <strong>{update.status}</strong> — {update.body}
                </li>
              ))}
            </ol>
          </article>
        ))}
      </section>
    </div>
  );
};
