// =============================================================================
// api-gateway — INTENTIONALLY VULNERABLE
// Role: HTTP reverse proxy routing traffic to downstream microservices
//
// Vulnerabilities present (for DevSecOps demo):
//   [VULN-01] Hardcoded gateway signing secret in source code
//   [VULN-02] CORS wildcard — accepts requests from any origin
//   [VULN-03] /debug/env endpoint leaks all environment variables (incl. secrets)
//   [VULN-04] /debug/routes exposes internal service topology + secret
//   [VULN-05] No authentication or authorisation on any route
//   [VULN-06] Gateway secret logged to stdout on startup
//   [VULN-07] No TLS — all traffic is plaintext HTTP
//   [VULN-08] No rate limiting — open to brute-force and DoS
// =============================================================================

const express = require('express')
const { createProxyMiddleware } = require('http-proxy-middleware')

const app = express()
app.use(express.json())

// [VULN-01] Hardcoded secret — should be injected via K8s Secret / Vault
const GATEWAY_SECRET = 'gateway-secret-key-12345'

// [VULN-02] CORS wildcard — any website can call this API
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', '*')
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  if (req.method === 'OPTIONS') return res.sendStatus(200)
  next()
})

// [VULN-03] Exposes ALL environment variables — DB passwords, JWT secrets, AWS keys
app.get('/debug/env', (req, res) => {
  res.json(process.env)
})

// [VULN-04] Exposes internal network topology and the gateway signing secret
app.get('/debug/routes', (req, res) => {
  res.json({
    services: {
      users:    process.env.USER_SERVICE_URL    || 'http://user-service:5000',
      products: process.env.PRODUCT_SERVICE_URL || 'http://product-service:3001',
      orders:   process.env.ORDER_SERVICE_URL   || 'http://order-service:5001',
    },
    gateway_secret: GATEWAY_SECRET,
  })
})

// [VULN-05] No auth middleware — every downstream route is publicly accessible
app.use('/api/users', createProxyMiddleware({
  target: process.env.USER_SERVICE_URL || 'http://user-service:5000',
  changeOrigin: true,
  pathRewrite: { '^/api/users': '' },
}))

app.use('/api/products', createProxyMiddleware({
  target: process.env.PRODUCT_SERVICE_URL || 'http://product-service:3001',
  changeOrigin: true,
  pathRewrite: { '^/api/products': '' },
}))

app.use('/api/orders', createProxyMiddleware({
  target: process.env.ORDER_SERVICE_URL || 'http://order-service:5001',
  changeOrigin: true,
  pathRewrite: { '^/api/orders': '' },
}))

// [VULN-07] Plain HTTP, no TLS termination
app.listen(3000, '0.0.0.0', () => {
  // [VULN-06] Secret written to stdout — visible in kubectl logs / CloudWatch
  console.log('[api-gateway] Listening on :3000')
  console.log('[api-gateway] Gateway secret:', GATEWAY_SECRET)
})
