// =============================================================================
// product-service — INTENTIONALLY VULNERABLE
// Role: Product catalogue — list, search, create, update, delete
//
// Vulnerabilities present (for DevSecOps demo):
//   [VULN-01] SQL injection in GET /products?search= (string concatenation)
//   [VULN-02] SQL injection in GET/DELETE /products/:id
//   [VULN-03] Hardcoded DB credentials in source code
//   [VULN-04] Full DB error stack traces returned to HTTP clients
//   [VULN-05] Mass assignment — user can set internal_cost (sensitive field)
//   [VULN-06] IDOR — no ownership check on PUT/DELETE (any user edits any product)
//   [VULN-07] No authentication on any endpoint
//   [VULN-08] DB password logged to stdout on startup
// =============================================================================

const express = require('express')
const { Pool }  = require('pg')

const app = express()
app.use(express.json())

// [VULN-03] Hardcoded credentials — shared password, never rotated
const pool = new Pool({
  host:     process.env.DB_HOST || 'postgres',
  database: 'shopdb',
  user:     'admin',
  password: 'admin123',   // [VULN-03]
  port:     5432,
})

// [VULN-01] SQL injection via ?search= parameter
// Payload: ?search=%' UNION SELECT 1,username,email,password,role,6,7 FROM users --
app.get('/products', async (req, res) => {
  const search = req.query.search || ''
  try {
    const result = await pool.query(
      `SELECT * FROM products WHERE name ILIKE '%${search}%' OR description ILIKE '%${search}%'`
    )
    res.json(result.rows)
  } catch (err) {
    // [VULN-04] Full stack trace + DB error message returned to client
    res.status(500).json({ error: err.message, stack: err.stack })
  }
})

// [VULN-02] SQL injection via :id path param
app.get('/products/:id', async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM products WHERE id=${req.params.id}`)
    if (!result.rows[0]) return res.status(404).json({ error: 'not found' })
    res.json(result.rows[0])
  } catch (err) {
    // [VULN-04]
    res.status(500).json({ error: err.message, stack: err.stack })
  }
})

// [VULN-05] Mass assignment — internal_cost is a sensitive margin field, not user-settable
// [VULN-07] No auth — anyone can create products
app.post('/products', async (req, res) => {
  const { name, description, price, category, stock, internal_cost } = req.body
  try {
    const result = await pool.query(
      `INSERT INTO products (name, description, price, category, stock, internal_cost)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name, description, price, category, stock || 0, internal_cost || 0]
    )
    res.status(201).json(result.rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// [VULN-06] IDOR — no check that the requesting user owns this product
// [VULN-07] No authentication
app.put('/products/:id', async (req, res) => {
  const { name, description, price, stock } = req.body
  try {
    const result = await pool.query(
      `UPDATE products SET name=$1, description=$2, price=$3, stock=$4 WHERE id=$5 RETURNING *`,
      [name, description, price, stock, req.params.id]
    )
    res.json(result.rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// [VULN-02] SQL injection via :id in DELETE
// [VULN-06] IDOR — any user can delete any product
app.delete('/products/:id', async (req, res) => {
  try {
    await pool.query(`DELETE FROM products WHERE id=${req.params.id}`)
    res.json({ message: 'deleted' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.listen(3001, '0.0.0.0', () => {
  console.log('[product-service] Listening on :3001')
  // [VULN-08] DB password written to stdout — visible in container logs
  console.log('[product-service] DB password: admin123')
})
