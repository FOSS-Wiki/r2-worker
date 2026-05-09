const ALLOWED_ORIGINS = [
  'https://foss.wiki',
  'https://staging.foss.wiki',
  'https://images.foss.wiki',
];

const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, HEAD',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': 'ETag',
};

const ERROR_HTML = {
  403: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://images.foss.wiki/Logo.png">
  <title>Error | FOSS Wiki</title>
  <style>
    body { margin: 0; height: 100vh; display: flex; justify-content: center; align-items: center; background-color: #0d0d14; color: #ffffff; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; text-align: center; }
    .container { max-width: 600px; padding: 20px; width: 100%; margin: 0 auto; }
    h1 { font-size: 3rem; font-weight: 800; margin-bottom: 10px; }
    h2 { font-size: 1.75rem; font-weight: 700; margin-bottom: 15px; }
    p { font-size: 1rem; color: #9ca3af; margin-bottom: 30px; line-height: 1.6; }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    a.button { display: inline-block; padding: 12px 28px; background: #ffffff; color: #000000; text-decoration: none; font-weight: 600; border-radius: 999px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); transition: background 0.3s ease; }
    a.button:hover { background: #e5e7eb; }
    .subtext { margin-top: 25px; font-size: 0.9rem; color: #6b7280; }
  </style>
</head>
<body>
  <div class="container">
    <h1>403</h1>
    <h2>Access denied</h2>
    <p>You don't have permission to access this page.</p>
    <p>
      If you think this is a mistake, please email <a href="mailto:admin@foss.wiki">admin@foss.wiki</a>.<br>
      If you have security concerns, please <a href="https://foss.wiki/FW:Security">read here</a>.
    </p>
    <a href="https://foss.wiki" class="button">Visit the Wiki</a>
    <div class="subtext">FOSS Wiki</div>
  </div>
</body>
</html>`,
  404: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://images.foss.wiki/Logo.png">
  <title>Error | FOSS Wiki</title>
  <style>
    body { margin: 0; height: 100vh; display: flex; justify-content: center; align-items: center; background-color: #0d0d14; color: #ffffff; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; text-align: center; }
    .container { max-width: 600px; padding: 20px; width: 100%; margin: 0 auto; }
    h1 { font-size: 3rem; font-weight: 800; margin-bottom: 10px; }
    h2 { font-size: 1.75rem; font-weight: 700; margin-bottom: 15px; }
    p { font-size: 1rem; color: #9ca3af; margin-bottom: 30px; line-height: 1.6; }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    a.button { display: inline-block; padding: 12px 28px; background: #ffffff; color: #000000; text-decoration: none; font-weight: 600; border-radius: 999px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); transition: background 0.3s ease; }
    a.button:hover { background: #e5e7eb; }
    .subtext { margin-top: 25px; font-size: 0.9rem; color: #6b7280; }
  </style>
</head>
<body>
  <div class="container">
    <h1>404</h1>
    <h2>Oops! Page not found</h2>
    <p>The page you're looking for doesn't exist or has been moved.</p>
    <p>
      If you think this is a mistake, please email <a href="mailto:admin@foss.wiki">admin@foss.wiki</a>.<br>
      If you have security concerns, please <a href="https://foss.wiki/FW:Security">read here</a>.
    </p>
    <a href="https://foss.wiki" class="button">Visit the Wiki</a>
    <div class="subtext">FOSS Wiki</div>
  </div>
</body>
</html>`,
};

function corsHeaders(origin) {
  if (!ALLOWED_ORIGINS.includes(origin)) return {};
  return { ...CORS_HEADERS, 'Access-Control-Allow-Origin': origin };
}

function errorPage(status) {
  return new Response(ERROR_HTML[status], {
    status,
    headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'public, max-age=300' },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const key = url.pathname.slice(1);
    const origin = request.headers.get('Origin') ?? '';
    const method = request.method;

    // Preflight
    if (method === 'OPTIONS') {
      if (!ALLOWED_ORIGINS.includes(origin)) return new Response(null, { status: 403 });
      return new Response(null, {
        status: 204,
        headers: { ...corsHeaders(origin), 'Access-Control-Max-Age': '3600' },
      });
    }

    // Block restricted directories from outside allowed origins
    if (key.startsWith('temp/') || key.startsWith('deleted/')) {
      if (!ALLOWED_ORIGINS.includes(origin)) return errorPage(403);
    }

    // Write operations — allowed origins only
    if (method === 'PUT' || method === 'POST') {
      if (!ALLOWED_ORIGINS.includes(origin)) return new Response('Forbidden', { status: 403 });
      await env.FOSSWIKI_BUCKET.put(key, request.body, { httpMetadata: request.headers });
      return new Response(null, { status: 200, headers: corsHeaders(origin) });
    }

    // GET / HEAD only beyond this point
    if (method !== 'GET' && method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const object = await env.FOSSWIKI_BUCKET.get(key);
    if (!object) return errorPage(404);

    const headers = new Headers(corsHeaders(origin));
    object.writeHttpMetadata(headers);
    headers.set('ETag', object.httpEtag);
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');

    return new Response(method === 'HEAD' ? null : object.body, { headers });
  },
};
