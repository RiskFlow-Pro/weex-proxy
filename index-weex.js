const express = require('express');
const { createHmac } = require('crypto');
const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-weex-key, x-weex-secret, x-weex-passphrase');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const BASE_URL = 'https://api-contract.weex.com';

app.all('/', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint || !endpoint.startsWith('/capi/')) {
    return res.json({ code: -1, msg: 'Endpoint non valido — deve iniziare con /capi/' });
  }

  const method = req.method === 'POST' ? 'POST' : 'GET';

  const apiKey    = req.headers['x-weex-key']        || '';
  const secret    = req.headers['x-weex-secret']     || '';
  const passphrase = req.headers['x-weex-passphrase'] || '';

  // Build query string e body
  let queryStr = '';
  let bodyStr  = '';

  if (method === 'GET') {
    const params = { ...req.query };
    delete params.endpoint;
    queryStr = Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : '';
  } else {
    bodyStr = (req.body && Object.keys(req.body).length) ? JSON.stringify(req.body) : '';
  }

  const fullUrl = `${BASE_URL}${endpoint}${method === 'GET' ? queryStr : ''}`;

  // ── Chiamate pubbliche (no auth) ──
  if (!apiKey || !secret) {
    try {
      const response = await fetch(fullUrl, {
        method,
        headers: { 'Content-Type': 'application/json' },
        ...(method === 'POST' ? { body: bodyStr || '{}' } : {}),
      });
      const data = await response.json();
      return res.json(data);
    } catch(e) {
      return res.json({ code: -1, msg: e.message });
    }
  }

  // ── Chiamate autenticate: firma WEEX ──
  // Signature: HMAC-SHA256( timestamp + METHOD + path + queryString + body ) → Base64
  const ts = String(Date.now());
  const signPayload = ts + method.toUpperCase() + endpoint + (method === 'GET' ? queryStr : bodyStr);
  const signature = createHmac('sha256', secret).update(signPayload).digest('base64');

  try {
    const response = await fetch(fullUrl, {
      method,
      headers: {
        'ACCESS-KEY':        apiKey,
        'ACCESS-SIGN':       signature,
        'ACCESS-PASSPHRASE': passphrase,
        'ACCESS-TIMESTAMP':  ts,
        'Content-Type':      'application/json',
      },
      ...(method === 'POST' ? { body: bodyStr || '{}' } : {}),
    });
    const data = await response.json();
    res.json(data);
  } catch(e) {
    res.json({ code: -1, msg: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('WEEX proxy running'));
