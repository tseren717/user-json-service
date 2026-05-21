require('dotenv').config();
const https = require('https');
const http  = require('http');

const SOAP_URL = process.env.SOAP_WSDL_URL
  ? process.env.SOAP_WSDL_URL.replace('?wsdl', '')
  : 'https://user-soap-service-h8m4e.ondigitalocean.app/soap';

async function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token шаардлагатай' });
  }

  const token = header.substring(7);
  const soap = `<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:auth="http://auth.service/">
  <soapenv:Body>
    <auth:ValidateToken>
      <token>${token}</token>
    </auth:ValidateToken>
  </soapenv:Body>
</soapenv:Envelope>`;

  try {
    const result = await soapRequest(SOAP_URL, 'ValidateToken', soap);
    const valid  = result.match(/<valid>(.*?)<\/valid>/)?.[1];
    const userId = result.match(/<userId>(.*?)<\/userId>/)?.[1];

    if (valid === 'true') {
      req.userId = parseInt(userId);
      next();
    } else {
      res.status(401).json({ error: 'Token хүчингүй' });
    }
  } catch (err) {
    console.error('SOAP алдаа:', err.message);
    res.status(500).json({ error: 'Auth service холбогдсонгүй' });
  }
}

function soapRequest(url, action, body) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const data    = Buffer.from(body, 'utf8');
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'text/xml',
        'SOAPAction':     action,
        'Content-Length': data.length
      }
    };
    const req = lib.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

module.exports = authMiddleware;