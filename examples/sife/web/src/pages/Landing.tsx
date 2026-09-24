import { Link } from 'react-router-dom';

const features = [
  {
    title: 'Public status pages',
    body: 'Keep customers informed with a branded status page, component health, and a clear incident timeline.',
  },
  {
    title: 'Private support desk',
    body: 'Tickets, threaded replies, and file attachments — with your agents and customers in one place.',
  },
  {
    title: 'Reactions, not noise',
    body: 'Let visitors acknowledge an incident with a reaction, so you can gauge impact without a flood of tickets.',
  },
];

export const Landing = () => (
  <>
    <section className="hero">
      <h1>Status pages and support, together.</h1>
      <p>
        Sife pairs a public status page with a private support desk, so your customers always know
        what is happening — and can reach you when it matters.
      </p>
      <div className="hero-actions">
        <Link to="/status" className="btn btn-primary">
          View our status
        </Link>
        <Link to="/login" className="btn btn-ghost">
          Sign in
        </Link>
      </div>
    </section>
    <section className="features">
      {features.map((feature) => (
        <article key={feature.title} className="feature-card">
          <h3>{feature.title}</h3>
          <p>{feature.body}</p>
        </article>
      ))}
    </section>
  </>
);
