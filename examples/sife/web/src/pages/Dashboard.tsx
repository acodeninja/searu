import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { getTickets, getToken, whoami, type CurrentUser, type Ticket } from '../api';

export const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<CurrentUser>(null);
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (!getToken()) {
      navigate('/login');
      return;
    }
    whoami().then((result) => setUser(result.user));
  }, [navigate]);

  const load = (term?: string) => {
    getTickets(term).then(setTickets).catch(() => setTickets([]));
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="dashboard">
      <header className="dashboard-head">
        <h1>Your tickets</h1>
        <div className="dashboard-actions">
          <a className="btn btn-ghost" href="/api/tickets/export.csv">
            Export CSV
          </a>
          <Link className="btn btn-ghost" to="/billing">
            Billing
          </Link>
        </div>
      </header>
      {user && (
        <p className="notice">
          Signed in as {user.email} ({user.role})
        </p>
      )}
      <form
        className="ticket-search"
        onSubmit={(event) => {
          event.preventDefault();
          load(search);
        }}
      >
        <input
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search tickets…"
        />
        <button className="btn btn-ghost" type="submit">
          Search
        </button>
      </form>
      <table className="ticket-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Subject</th>
            <th>Requester</th>
            <th>Priority</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {tickets.map((ticket) => (
            <tr key={ticket.id}>
              <td>{ticket.id}</td>
              <td>
                <Link to={`/app/tickets/${ticket.id}`}>{ticket.subject}</Link>
              </td>
              <td>{ticket.requester}</td>
              <td>{ticket.priority}</td>
              <td>{ticket.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
