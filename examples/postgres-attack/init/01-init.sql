CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO users (email) VALUES
  ('alice@dimaggi.ai'),
  ('bob@dimaggi.ai'),
  ('carol@dimaggi.ai');

CREATE TABLE payments (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id),
  amount_cents INT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO payments (user_id, amount_cents) VALUES
  (1, 4999),
  (2, 12500),
  (3, 250);

CREATE TABLE audit_log (
  id SERIAL PRIMARY KEY,
  event TEXT NOT NULL,
  at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO audit_log (event) VALUES
  ('user signup: alice'),
  ('payment received: $49.99'),
  ('login: bob');
