-- =============================================================================
-- SecureFlow — initial database schema (VULNERABLE baseline)
-- Used by docker-compose volume mount and K8s postgres-init ConfigMap
--
-- Deliberate issues:
--   [VULN-01] Passwords stored as MD5 hashes (broken — rainbow tables exist)
--   [VULN-02] internal_cost column exposed through product-service API (IDOR)
--   [VULN-03] No row-level security policies
--   [VULN-04] Seed admin password is 'admin' — trivially guessable
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
  id         SERIAL       PRIMARY KEY,
  username   VARCHAR(100) UNIQUE NOT NULL,
  password   VARCHAR(255) NOT NULL,      -- [VULN-01] stored as MD5
  email      VARCHAR(255),
  role       VARCHAR(50)  DEFAULT 'user',
  created_at TIMESTAMP    DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
  id            SERIAL       PRIMARY KEY,
  name          VARCHAR(255) NOT NULL,
  description   TEXT,
  price         DECIMAL(10,2),
  category      VARCHAR(100),
  stock         INTEGER       DEFAULT 0,
  internal_cost DECIMAL(10,2),           -- [VULN-02] margin data, never for API
  created_at    TIMESTAMP     DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
  id         SERIAL      PRIMARY KEY,
  user_id    INTEGER,
  product_id INTEGER,
  quantity   INTEGER,
  notes      TEXT,
  status     VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP   DEFAULT NOW()
);

-- ---- Seed data ---------------------------------------------------------------
-- admin : admin     MD5 → 21232f297a57a5a743894a0e4a801fc3   [VULN-04]
-- alice : password1 MD5 → 6384e2b2184bcbf58eccf10ca7a6563c
INSERT INTO users (username, password, email, role) VALUES
  ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin@secureflow.local', 'admin'),
  ('alice', '6384e2b2184bcbf58eccf10ca7a6563c', 'alice@example.com',       'user');

INSERT INTO products (name, description, price, category, stock, internal_cost) VALUES
  ('Laptop Pro',         'High-performance laptop',    999.99, 'electronics', 50,  600.00),
  ('Wireless Mouse',     'Ergonomic wireless mouse',    29.99, 'accessories', 200,   8.00),
  ('USB-C Hub',          '7-port USB-C hub',            49.99, 'accessories', 100,  12.00),
  ('Mechanical Keyboard','RGB mechanical keyboard',     79.99, 'accessories',  75,  22.00);
