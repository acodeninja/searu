CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_md5 TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  organisation TEXT,
  phone TEXT,
  api_token TEXT,
  plan TEXT NOT NULL DEFAULT 'free',
  seats INTEGER NOT NULL DEFAULT 3,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free';
ALTER TABLE users ADD COLUMN IF NOT EXISTS seats INTEGER NOT NULL DEFAULT 3;

CREATE TABLE IF NOT EXISTS components (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'operational',
  position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incidents (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'minor',
  status TEXT NOT NULL DEFAULT 'investigating',
  component TEXT,
  is_public BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incident_updates (
  id SERIAL PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  status TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reactions (
  id SERIAL PRIMARY KEY,
  incident_id INTEGER NOT NULL,
  emoji TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tickets (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'normal',
  is_public BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ticket_comments (
  id SERIAL PRIMARY KEY,
  ticket_id INTEGER NOT NULL REFERENCES tickets(id),
  author_id INTEGER REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attachments (
  id SERIAL PRIMARY KEY,
  ticket_id INTEGER NOT NULL REFERENCES tickets(id),
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  content_type TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO users (id, email, password_md5, full_name, role, organisation, phone, api_token) VALUES
  (1, 'admin@sife.io', '7c6a180b36896a0a8c02787eeafb0e4c', 'Priya Sharma', 'admin', 'Sife', '+44 20 7946 0100', 'sife_live_9f2a4c7e1b6d'),
  (2, 'ops@sife.io', '0d107d09f5bbe40cade3de5c71e9e9b7', 'Marcus Doyle', 'agent', 'Sife', '+44 20 7946 0142', NULL),
  (3, 'tara@sife.io', '0571749e2ac330a7455809c6b0e7af90', 'Tara Nwosu', 'agent', 'Sife', '+44 20 7946 0188', NULL),
  (4, 'alice@northwind.example', 'e10adc3949ba59abbe56e057f20f883e', 'Alice Bianchi', 'customer', 'Northwind Traders', '+44 161 496 0210', NULL),
  (5, 'bob@globex.example', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'Bob Okonkwo', 'customer', 'Globex', '+44 113 496 0044', NULL),
  (6, 'carol@initech.example', '2ab96390c7dbe3439de74d0c9b0b1767', 'Carol Meunier', 'customer', 'Initech', '+44 121 496 0077', NULL),
  (7, 'dave@umbrella.example', '8621ffdbc5698829397d97767ac13db3', 'Dave Lindqvist', 'customer', 'Umbrella Health', '+44 141 496 0512', NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO components (id, name, status, position) VALUES
  (1, 'Dashboard', 'operational', 1),
  (2, 'REST API', 'operational', 2),
  (3, 'Ticketing', 'operational', 3),
  (4, 'Email notifications', 'degraded_performance', 4),
  (5, 'File attachments', 'operational', 5)
ON CONFLICT (id) DO NOTHING;

INSERT INTO incidents (id, title, body, severity, status, component, is_public, created_at) VALUES
  (1, 'Elevated API latency in EU-West', 'We are investigating raised response times on the REST API for customers in the EU-West region. Mitigation is under way.', 'major', 'monitoring', 'REST API', true, now() - interval '3 hours'),
  (2, 'Delayed email notifications', 'Outbound notification email is queued behind a backlog with our delivery provider. Tickets and dashboards are unaffected.', 'minor', 'investigating', 'Email notifications', true, now() - interval '1 day'),
  (3, 'Scheduled maintenance: storage migration', 'We will migrate attachment storage on Sunday 02:00–04:00 UTC. Uploads may be briefly unavailable.', 'maintenance', 'scheduled', 'File attachments', true, now() - interval '2 days'),
  (4, 'Internal: pilot tenant data reconciliation', 'Reconciling billing counters for the pilot tenant. Tracking internally, not shown on the public page.', 'minor', 'investigating', 'Dashboard', false, now() - interval '5 hours')
ON CONFLICT (id) DO NOTHING;

INSERT INTO incident_updates (incident_id, status, body, created_at) VALUES
  (1, 'investigating', 'We have identified raised latency and are investigating a slow database replica.', now() - interval '3 hours'),
  (1, 'monitoring', 'A replica has been rotated out. Latency is returning to normal; we are monitoring.', now() - interval '1 hour'),
  (2, 'investigating', 'Our email provider reports a delivery backlog. We are monitoring the queue.', now() - interval '1 day')
ON CONFLICT DO NOTHING;

INSERT INTO tickets (id, user_id, subject, body, status, priority, is_public, created_at) VALUES
  (1, 4, 'Cannot reset my password', 'The password reset email never arrives for alice@northwind.example.', 'open', 'normal', false, now() - interval '2 days'),
  (2, 5, 'Invoice INV-20418 shows the wrong VAT', 'Our latest invoice charges 20% VAT but Globex is zero-rated. Please correct.', 'open', 'high', false, now() - interval '1 day'),
  (3, 6, 'API returns 500 on /rest/user/whoami', 'Since this morning the whoami endpoint 500s for our service account.', 'pending', 'high', false, now() - interval '6 hours'),
  (4, 7, 'Request: SSO with Azure AD', 'Umbrella Health would like SAML SSO against Azure AD for all staff.', 'open', 'low', true, now() - interval '4 days'),
  (5, 4, 'How do I export ticket history?', 'Is there a CSV export of closed tickets for audit purposes?', 'closed', 'low', true, now() - interval '9 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO ticket_comments (ticket_id, author_id, body, created_at) VALUES
  (2, 2, 'Thanks Bob — I have escalated this to billing. Reference for the finance team: BILL-8841.', now() - interval '20 hours'),
  (3, 6, 'Here is the failing call using our key so you can reproduce: `curl -H "Authorization: Bearer sife_live_c1a9d40f7e28" https://api.sife.io/rest/user/whoami`', now() - interval '5 hours'),
  (4, 3, 'Noted — SAML is on the roadmap for next quarter. I will keep this ticket updated.', now() - interval '3 days')
ON CONFLICT DO NOTHING;

INSERT INTO reactions (incident_id, emoji) VALUES
  (1, '👍'), (1, '👀'), (1, '🙏'), (2, '👍'), (2, '😤')
ON CONFLICT DO NOTHING;

SELECT setval('users_id_seq', (SELECT max(id) FROM users));
SELECT setval('components_id_seq', (SELECT max(id) FROM components));
SELECT setval('incidents_id_seq', (SELECT max(id) FROM incidents));
SELECT setval('tickets_id_seq', (SELECT max(id) FROM tickets));
