import {
  FRONTEND_URL,
  ORG,
  REDIRECT_URI,
  createSession,
  githubFetch,
  readJson,
  verifyState,
} from '../lib.js';

function redirectWithError(message) {
  const url = new URL(FRONTEND_URL);
  url.searchParams.set('error', message);
  return Response.redirect(url.toString(), 302);
}

export default async function handler(request) {
  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET' } });
  }

  try {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const githubError = url.searchParams.get('error');

    if (githubError) return redirectWithError(`GitHub authorization was cancelled (${githubError}).`);
    if (!verifyState(state)) return redirectWithError('Authentication request expired or was invalid. Please sign in again.');
    if (!code) return redirectWithError('GitHub did not return an authorization code.');

    const clientId = process.env.GITHUB_APP_CLIENT_ID;
    const clientSecret = process.env.GITHUB_APP_CLIENT_SECRET;
    if (!clientId || !clientSecret || !REDIRECT_URI) {
      return new Response('GitHub App is not configured on the server.', { status: 500 });
    }

    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'Skylark-MSP-Knowledge-Hub',
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });

    const token = await readJson(tokenResponse);
    if (!tokenResponse.ok || !token?.access_token) {
      return redirectWithError('GitHub token exchange failed. Please try again.');
    }

    // Verify the authenticated GitHub identity.
    const meResponse = await githubFetch('/user', token.access_token);
    const me = await readJson(meResponse);
    if (!meResponse.ok || !me?.login) {
      return redirectWithError('Could not verify the GitHub account.');
    }

    // Require active membership in the Skylark-MSP organization.
    const membershipResponse = await githubFetch(`/user/memberships/orgs/${encodeURIComponent(ORG)}`, token.access_token);
    const membership = await readJson(membershipResponse);
    if (!membershipResponse.ok || membership?.state !== 'active') {
      return redirectWithError(`Your GitHub account is not an active member of ${ORG}.`);
    }

    const expiresIn = Number(token.expires_in || 8 * 60 * 60);
    const session = createSession({
      ghToken: token.access_token,
      exp: Date.now() + (expiresIn * 1000) - 30_000,
      user: {
        id: me.id,
        login: me.login,
        name: me.name || me.login,
        avatar_url: me.avatar_url || '',
        html_url: me.html_url || '',
      },
    });

    // Pass only our encrypted session token to the browser in the URL fragment.
    // The GitHub access token itself is never exposed to the page.
    const destination = new URL(FRONTEND_URL);
    destination.hash = `auth=${encodeURIComponent(session)}`;
    return Response.redirect(destination.toString(), 302);
  } catch (error) {
    console.error('OAuth callback error:', error);
    return redirectWithError('Authentication failed unexpectedly. Please try again.');
  }
}
