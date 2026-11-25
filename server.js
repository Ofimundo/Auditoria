import express from 'express';
import cors from 'cors';
import tls from 'node:tls';
import net from 'node:net';

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Función para inspeccionar certificado SSL/TLS real
function getTlsCertificate(hostname) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect(443, hostname, { servername: hostname, timeout: 6000 }, () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const daysRemaining = validTo ? Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null;
        const issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Emisor no especificado') : 'Desconocido';
        socket.destroy();
        resolve({
          valid: true,
          authorized,
          daysRemaining,
          validTo: validTo ? validTo.toISOString() : null,
          issuer,
          protocol: protocol || 'TLS'
        });
      });
      socket.on('error', (err) => {
        resolve({ valid: false, authorized: false, error: err.message });
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ valid: false, authorized: false, error: 'Tiempo de espera agotado al conectar por SSL' });
      });
    } catch (e) {
      resolve({ valid: false, authorized: false, error: e.message });
    }
  });
}

// Función para consultar registros DNS y seguridad de correo (DoH)
async function checkDnsAndEmail(domain) {
  const result = {
    hasMx: false,
    mxRecords: [],
    hasSpf: false,
    spfRecord: '',
    hasDmarc: false,
    dmarcRecord: ''
  };

  const fetchDns = async (name, type) => {
    try {
      const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) return [];
      const data = await res.json();
      return (data.Answer || []).map(a => a.data ? a.data.replace(/^"|"$/g, '').replace(/\\"/g, '"') : '');
    } catch {
      return [];
    }
  };

  try {
    const [txtRoot, txtDmarc, mxList] = await Promise.all([
      fetchDns(domain, 'TXT'),
      fetchDns(`_dmarc.${domain}`, 'TXT'),
      fetchDns(domain, 'MX')
    ]);

    // SPF
    const spf = txtRoot.find(r => r.toLowerCase().startsWith('v=spf1'));
    if (spf) {
      result.hasSpf = true;
      result.spfRecord = spf;
    }

    // DMARC
    const dmarc = txtDmarc.find(r => r.toLowerCase().startsWith('v=dmarc1'));
    if (dmarc) {
      result.hasDmarc = true;
      result.dmarcRecord = dmarc;
    }

    // MX
    if (mxList.length > 0) {
      result.hasMx = true;
      result.mxRecords = mxList.slice(0, 3);
    }
  } catch (err) {
    console.error('Error resolviendo DNS:', err.message);
  }

  return result;
}

// Función auxiliar para probar conexión a un puerto específico
function checkPort(host, port, timeout = 1200) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });

    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });

    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });

    try {
      socket.connect(port, host);
    } catch {
      resolve(false);
    }
  });
}

// Análisis de Infraestructura, Servidor Web y Servicios / Puertos Clave
async function getInfrastructureInfo(hostname, headers) {
  // 1. IP pública del host
  let ip = 'No resuelta';
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      const data = await res.json();
      const aRec = data.Answer?.find(a => a.type === 1);
      if (aRec?.data) ip = aRec.data;
    }
  } catch {}

  // 2. Detección de CDN / WAF
  let cdn = 'Servidor directo (Sin CDN detectada)';
  const srv = (headers['server'] || '').toLowerCase();
  const via = (headers['via'] || '').toLowerCase();

  if (headers['cf-ray'] || srv.includes('cloudflare')) {
    cdn = 'Cloudflare (Proxy inverso y WAF activo)';
  } else if (headers['x-amz-cf-id'] || via.includes('cloudfront')) {
    cdn = 'Amazon CloudFront (AWS CDN)';
  } else if (srv.includes('akamai')) {
    cdn = 'Akamai Technologies CDN';
  } else if (headers['x-github-request-id']) {
    cdn = 'GitHub Pages / Fastly';
  } else if (srv.includes('litespeed')) {
    cdn = 'LiteSpeed Web Server (Hosting local / cPanel)';
  }

  // 3. Servidor y tecnología
  const server = headers['server'] || 'Oculto / No revelado';
  const poweredBy = headers['x-powered-by'] || 'No revelado';

  // 4. Puertos críticos a evaluar
  const portsToCheck = [
    { port: 21, service: 'FTP', risk: 'Alto', desc: 'Transferencia de archivos sin cifrar' },
    { port: 22, service: 'SSH', risk: 'Medio', desc: 'Terminal remota del servidor' },
    { port: 3306, service: 'MySQL / MariaDB', risk: 'Crítico', desc: 'Base de datos relacional' },
    { port: 5432, service: 'PostgreSQL', risk: 'Crítico', desc: 'Base de datos relacional' },
    { port: 6379, service: 'Redis', risk: 'Crítico', desc: 'Base de datos en memoria' },
    { port: 27017, service: 'MongoDB', risk: 'Crítico', desc: 'Base de datos NoSQL' },
    { port: 8080, service: 'HTTP Alternativo', risk: 'Medio', desc: 'Servicios de prueba / Tomcat' },
    { port: 2083, service: 'cPanel / WHM', risk: 'Bajo', desc: 'Panel de control de hosting' }
  ];

  const portResults = await Promise.all(
    portsToCheck.map(async (p) => {
      const open = await checkPort(hostname, p.port, 1200);
      return {
        ...p,
        open
      };
    })
  );

  return {
    ip,
    cdn,
    server,
    poweredBy,
    ports: portResults
  };
}

// Verificar páginas clave secundarias (Contacto / Nosotros)
async function checkKeyPages(origin, html) {
  const pages = {
    contact: { found: false, url: '', status: 0 },
    about: { found: false, url: '', status: 0 }
  };

  const contactMatch = html.match(/href=["']([^"']*(?:contacto|contact-us|contactenos)[^"']*)["']/i);
  const aboutMatch = html.match(/href=["']([^"']*(?:nosotros|about-us|quienes-somos)[^"']*)["']/i);

  const testPath = async (candidate, fallbackPath) => {
    let targetUrl = '';
    if (candidate) {
      targetUrl = candidate.startsWith('http') ? candidate : new URL(candidate, origin).href;
    } else {
      targetUrl = origin + fallbackPath;
    }

    try {
      const res = await fetch(targetUrl, {
        method: 'HEAD',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        signal: AbortSignal.timeout(4000)
      });
      return { found: res.ok, url: targetUrl, status: res.status };
    } catch {
      return { found: false, url: targetUrl, status: 0 };
    }
  };

  const [contactRes, aboutRes] = await Promise.all([
    testPath(contactMatch ? contactMatch[1] : null, '/contacto'),
    testPath(aboutMatch ? aboutMatch[1] : null, '/nosotros')
  ]);

  pages.contact = contactRes;
  pages.about = aboutRes;
  return pages;
}

// Chequear muestra de enlaces internos para detectar errores 404
async function checkSampleLinks(html, origin) {
  const linkMatches = [...html.matchAll(/href=["']([^"'#\s]+)["']/gi)];
  const candidateUrls = [];
  const seen = new Set();

  for (const m of linkMatches) {
    const raw = m[1];
    if (raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('tel:')) continue;
    try {
      const parsed = raw.startsWith('http') ? new URL(raw) : new URL(raw, origin);
      if (parsed.origin === origin && !seen.has(parsed.href) && parsed.href !== origin && parsed.href !== origin + '/') {
        seen.add(parsed.href);
        candidateUrls.push(parsed.href);
        if (candidateUrls.length >= 6) break;
      }
    } catch {}
  }

  const results = [];
  await Promise.all(
    candidateUrls.map(async (u) => {
      try {
        const res = await fetch(u, {
          method: 'HEAD',
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(4000)
        });
        results.push({ url: u, status: res.status, ok: res.ok });
      } catch (err) {
        results.push({ url: u, status: 0, ok: false, error: err.message });
      }
    })
  );

  return results;
}

app.post('/api/audit', async (req, res) => {
  try {
    let { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL requerida' });
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

    const target = new URL(url);
    const origin = target.origin;
    const hostname = target.hostname;

    const start = Date.now();
    const response = await fetch(target.href, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8'
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(12000)
    });
    const ttfb = Date.now() - start;
    const html = await response.text();
    const headers = Object.fromEntries(response.headers.entries());

    const fetchAux = async (path) => {
      try {
        const r = await fetch(origin + path, {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(4000)
        });
        return r.ok ? await r.text() : '';
      } catch {
        return '';
      }
    };

    // Consultas paralelas complementarias (incluyendo infraestructura y puertos)
    const [robots, sitemap, llms, ssl, dns, pages, sampleLinks, infrastructure] = await Promise.all([
      fetchAux('/robots.txt'),
      fetchAux('/sitemap.xml'),
      fetchAux('/llms.txt'),
      getTlsCertificate(hostname),
      checkDnsAndEmail(hostname),
      checkKeyPages(origin, html),
      checkSampleLinks(html, origin),
      getInfrastructureInfo(hostname, headers)
    ]);

    const brokenLinks = sampleLinks.filter(l => !l.ok);

    res.json({
      html,
      headers,
      ttfb,
      robots,
      sitemap,
      llms,
      ssl,
      dns,
      pages,
      sampleLinks,
      brokenLinks,
      infrastructure
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al analizar el dominio', details: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Auditor web avanzado activo en http://localhost:${PORT}`);
});
