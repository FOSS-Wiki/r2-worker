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

function corsHeaders(origin) {
  if (!ALLOWED_ORIGINS.includes(origin)) return {};
  return { ...CORS_HEADERS, 'Access-Control-Allow-Origin': origin };
}

async function errorPage(env, status) {
  const obj = await env.FOSSWIKI_BUCKET.get(`_errors/${status}.html`);
  if (obj) {
    return new Response(obj.body, {
      status,
      headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'public, max-age=300' },
    });
  }
  return new Response(`${status} Error`, { status, headers: { 'Content-Type': 'text/plain' } });
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
      if (!ALLOWED_ORIGINS.includes(origin)) return errorPage(env, 403);
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
    if (!object) return errorPage(env, 404);

    const headers = new Headers(corsHeaders(origin));
    object.writeHttpMetadata(headers);
    headers.set('ETag', object.httpEtag);
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');

    return new Response(method === 'HEAD' ? null : object.body, { headers });
  },
};
