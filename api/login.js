import { createState, FRONTEND_URL, REDIRECT_URI } from '../lib.js';

export default function handler(request) {
  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET' } });
  }

  const clientId = process.env.GITHUB_APP_CLIENT_ID;
  if (!clientId || !REDIRECT_URI) {
    return new Response('GitHub App is not configured on the server.', { status: 500 });
  }

  const state = createState();
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('state', state);

  // Keep the callback fixed to the configured GitHub Pages URL.
  // No user-controlled redirect URL is accepted here.
  void FRONTEND_URL;

  return Response.redirect(url.toString(), 302);
}
