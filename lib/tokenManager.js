'use strict';

const https = require('node:https');
const crypto = require('node:crypto');
const { URLSearchParams, URL } = require('node:url');

const BRANDS = {
    hyundai: {
        idpHost: 'idpconnect-eu.hyundai.com',
        clientId: '6d477c38-3ca4-4cf3-9557-2a1929a94654',
        clientSecret: 'KUy49XxPzLpLuoK0xhBC77W6VXhmtQR9iQhmIFjjoY4IpxsV',
        redirectUri: 'https://prd.eu-ccapi.hyundai.com:8080/api/v1/user/oauth2/token',
    },
    kia: {
        idpHost: 'idpconnect-eu.kia.com',
        clientId: 'fdc85c00-0a2f-4c64-bcb4-2cfb1500730a',
        clientSecret: 'secret',
        redirectUri: 'https://prd.eu-ccapi.kia.com:8080/api/v1/user/oauth2/redirect',
    },
};

const USER_AGENT = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';

// Approximate Chrome 131 Android TLS fingerprint
const CHROME_CIPHERS = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-RSA-AES128-SHA',
    'ECDHE-RSA-AES256-SHA',
    'AES128-GCM-SHA256',
    'AES256-GCM-SHA384',
    'AES128-SHA',
    'AES256-SHA',
].join(':');

/** Simple cookie jar: parses Set-Cookie headers, returns Cookie header string */
class CookieJar {
    constructor() {
        this._cookies = {};
    }

    ingest(headers) {
        const setCookie = headers['set-cookie'];
        if (!setCookie) {
return;
}
        const list = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const entry of list) {
            const [pair] = entry.split(';');
            const eq = pair.indexOf('=');
            if (eq === -1) {
continue;
}
            const name = pair.slice(0, eq).trim();
            const value = pair.slice(eq + 1).trim();
            this._cookies[name] = value;
        }
    }

    header() {
        return Object.entries(this._cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    }
}

/**
 * Low-level HTTPS request returning { statusCode, headers, body }
 *
 * @param opts
 * @param {string} [body]
 */
function request(opts, body = undefined) {
    return new Promise((resolve, reject) => {
        const agent = new https.Agent({
            ciphers: CHROME_CIPHERS,
            honorCipherOrder: false,
            minVersion: 'TLSv1.2',
        });
        const req = https.request({ ...opts, agent }, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve({
                statusCode: res.statusCode,
                headers: res.headers,
                body: Buffer.concat(chunks).toString('utf-8'),
            }));
        });
        req.on('error', reject);
        req.setTimeout(15000, () => req.destroy(new Error('Request timed out')));
        if (body) {
req.write(body);
}
        req.end();
    });
}

/**
 * Encrypt password with RSA PKCS1v1.5 using JWK public key
 *
 * @param jwk
 * @param {string} password
 */
function encryptPassword(jwk, password) {
    const key = crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    return crypto.publicEncrypt(
        { key, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(password, 'utf-8'),
    ).toString('base64');
}

/**
 * Fetch a new refresh token using the Hyundai/Kia EU OAuth flow.
 *
 * Flow:
 *  (1) GET /authorize (CCAPI client) → IDP 302 → CCAPI SPA URL
 *       The IDP redirects to the CCAPI SPA, embedding the `connector_session_key`
 *       inside the `next_uri` query parameter.
 *  (2) Extract `next_uri` from CCAPI SPA URL and GET it directly.
 *       The CCAPI SPA JavaScript only does `window.location.replace(next_uri)`,
 *       so we replicate that manually. This tells the IDP that the connector
 *       session is pending and hands back the IDP session cookies + login form.
 *  (3) Follow any further IDP redirect to collect all session cookies (JSESSIONID,
 *       _hazkpw, hmg-auth-target …).
 *  (4) GET /certs → RSA JWK for password encryption.
 *  (5) POST /signin with connector_session_key and encrypted password.
 *       The IDP verifies credentials against the pending connector session and
 *       issues the authorization code → 302 → redirect_uri?code=XXX.
 *  (6) POST /token → access_token + refresh_token.
 *
 * @param {string} brand     'hyundai' | 'kia'
 * @param {string} username
 * @param {string} password  actual account password
 * @param {Function} [log]   optional logger (msg) => void
 * @returns {{ refreshToken: string, accessToken: string, expiresAt: string }}
 */
async function fetchToken(brand, username, password, log) {
    const info = log || (() => {});
    const cfg = BRANDS[brand];
    if (!cfg) {
throw new Error(`Unknown brand: ${brand}`);
}

    const host = cfg.idpHost;
    const jar = new CookieJar();

    const baseHeaders = (extra = {}) => ({
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?1',
        'Sec-Ch-Ua-Platform': '"Android"',
        Cookie: jar.header(),
        ...extra,
    });

    // Step 1: GET /authorize → IDP redirects to CCAPI SPA URL
    // The CCAPI SPA URL contains next_uri with the connector_session_key
    info(`[tokenManager] Step 1: GET https://${host}/auth/api/v2/user/oauth2/authorize`);
    const authorizeUrl = (
        `/auth/api/v2/user/oauth2/authorize?response_type=code` +
        `&client_id=${cfg.clientId}` +
        `&redirect_uri=${encodeURIComponent(cfg.redirectUri)}` +
        `&scope=openid+profile+email&lang=de&state=ccsp&country=DE`
    );
    const step1 = await request({ hostname: host, path: authorizeUrl, method: 'GET', headers: baseHeaders() });
    jar.ingest(step1.headers);
    info(`[tokenManager] Step 1: HTTP ${step1.statusCode}, cookies: ${Object.keys(jar._cookies).join(', ') || 'none'}`);

    const ccapiSpaLocation = step1.headers['location'] || '';
    if (!ccapiSpaLocation) {
        throw new Error(`Step 1: no redirect location (HTTP ${step1.statusCode}): ${step1.body.slice(0, 200)}`);
    }
    info(`[tokenManager] Step 1: CCAPI SPA URL: ${ccapiSpaLocation.slice(0, 80)}…`);

    // Extract connector_session_key from next_uri embedded in the CCAPI SPA URL
    let connectorSessionKey = '';
    let nextUri = '';
    try {
        const ccapiUrl = new URL(ccapiSpaLocation);
        nextUri = decodeURIComponent(ccapiUrl.searchParams.get('next_uri') || '');
        if (nextUri) {
            const nextUriParsed = new URL(nextUri);
            connectorSessionKey = nextUriParsed.searchParams.get('connector_session_key') || '';
        }
    } catch (_) { /* URL parse failed */ }
    info(`[tokenManager] Step 1: connector_session_key=${connectorSessionKey ? `${connectorSessionKey.slice(0, 8)}…` : 'not found'}`);
    info(`[tokenManager] Step 1: next_uri=${nextUri ? `${nextUri.slice(0, 80)}…` : 'not found'}`);

    if (!connectorSessionKey) {
        throw new Error(`connector_session_key not found in CCAPI SPA URL: ${ccapiSpaLocation.slice(0, 300)}`);
    }

    // Step 2: GET next_uri — mimics what the CCAPI SPA JavaScript does:
    //   window.location.replace(next_uri)
    // This call registers the connector session as "pending" on the IDP side
    // and returns the IDP login page (with session cookies).
    info(`[tokenManager] Step 2: GET next_uri (IDP callback to activate connector session)`);
    const nextUriParsed = new URL(nextUri);
    const step2 = await request({
        hostname: nextUriParsed.hostname,
        path: nextUriParsed.pathname + nextUriParsed.search,
        method: 'GET',
        headers: baseHeaders(),
    });
    jar.ingest(step2.headers);
    info(`[tokenManager] Step 2: HTTP ${step2.statusCode}, cookies: ${Object.keys(jar._cookies).join(', ') || 'none'}`);

    // Step 2b: if IDP redirected to login UI page, follow it to collect remaining cookies
    const step2Location = step2.headers['location'] || '';
    if (step2.statusCode === 302 && step2Location) {
        try {
            const loginUrl = new URL(step2Location, `https://${host}`);
            if (loginUrl.hostname === host) {
                info(`[tokenManager] Step 2b: follow redirect → ${loginUrl.pathname.slice(0, 50)}`);
                const step2b = await request({
                    hostname: host,
                    path: loginUrl.pathname + loginUrl.search,
                    method: 'GET',
                    headers: baseHeaders(),
                });
                jar.ingest(step2b.headers);
                info(`[tokenManager] Step 2b: HTTP ${step2b.statusCode}, cookies: ${Object.keys(jar._cookies).join(', ') || 'none'}`);
            }
        } catch (_) { /* not IDP URL — ignore */ }
    }

    // IDP sets _hazkpw='' (empty); browser JS normally fills it with a UUID.
    // We replicate the browser behaviour: set cookie + matching _csrf form field.
    const csrfToken = crypto.randomUUID();
    jar._cookies['_hazkpw'] = csrfToken;
    info(`[tokenManager] CSRF token generated (${csrfToken.slice(0, 8)}…)`);

    // Step 3: GET RSA public key for password encryption
    info(`[tokenManager] Step 3: GET https://${host}/auth/api/v1/accounts/certs`);
    const step3 = await request({ hostname: host, path: '/auth/api/v1/accounts/certs', method: 'GET', headers: baseHeaders() });
    jar.ingest(step3.headers);
    info(`[tokenManager] Step 3: HTTP ${step3.statusCode}`);
    if (step3.statusCode !== 200) {
        throw new Error(`Certs endpoint returned ${step3.statusCode}: ${step3.body.slice(0, 200)}`);
    }
    const jwk = JSON.parse(step3.body).retValue;
    if (!jwk || !jwk.kid) {
        throw new Error(`No JWK in certs response: ${step3.body.slice(0, 200)}`);
    }
    info(`[tokenManager] Step 3: JWK kid=${jwk.kid}`);

    const encryptedPw = encryptPassword(jwk, password);
    info(`[tokenManager] Step 3: Password RSA-encrypted, base64 len=${encryptedPw.length}`);

    // Step 4: POST /signin with connector_session_key
    info(`[tokenManager] Step 4: POST https://${host}/auth/account/signin (csrf=${csrfToken.slice(0, 8)}…, csk=${connectorSessionKey.slice(0, 8)}…)`);
    const signinBody = new URLSearchParams({
        client_id: cfg.clientId,
        encryptedPassword: 'true',
        password: encryptedPw,
        redirect_uri: cfg.redirectUri,
        scope: '', nonce: '', state: 'ccsp',
        username,
        connector_session_key: connectorSessionKey,
        kid: jwk.kid,
        _csrf: csrfToken,
    }).toString();

    const step4 = await request({
        hostname: host,
        path: '/auth/account/signin',
        method: 'POST',
        headers: baseHeaders({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(signinBody),
            Origin: `https://${host}`,
            Referer: `https://${host}/auth/ui/login?client_id=${cfg.clientId}&response_type=code&redirect_uri=${encodeURIComponent(cfg.redirectUri)}&lang=de&state=ccsp&country=DE`,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }),
    }, signinBody);
    jar.ingest(step4.headers);
    info(`[tokenManager] Step 4: HTTP ${step4.statusCode}`);
    if (step4.body) {
        info(`[tokenManager] Step 4: body=${step4.body.slice(0, 200)}`);
    }

    if (step4.statusCode !== 302) {
        throw new Error(`Signin returned HTTP ${step4.statusCode}: ${step4.body.slice(0, 300)}`);
    }

    const signinLocation = step4.headers['location'] || '';
    info(`[tokenManager] Step 4: location=${signinLocation.slice(0, 150)}`);

    // Check for explicit signin error
    if (signinLocation.includes('error=')) {
        const locUrl = new URL(signinLocation, `https://${host}`);
        const err = locUrl.searchParams.get('error');
        const errDesc = locUrl.searchParams.get('error_description');
        throw new Error(`Signin error: ${err} — ${errDesc}`);
    }

    // Extract authorization code from redirect location
    let codeParam;
    try {
        const locUrl = new URL(signinLocation, `https://${host}`);
        codeParam = locUrl.searchParams.get('code');
    } catch (_) { /* URL parse error */ }

    if (!codeParam) {
        throw new Error(`No code in signin redirect: ${signinLocation.slice(0, 300)}`);
    }
    info(`[tokenManager] Step 4: Authorization code obtained (${codeParam.length} chars)`);

    // Step 5: Exchange code for tokens
    info(`[tokenManager] Step 5: POST https://${host}/auth/api/v2/user/oauth2/token`);
    const tokenBody = new URLSearchParams({
        grant_type: 'authorization_code',
        code: codeParam,
        redirect_uri: cfg.redirectUri,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
    }).toString();

    const step5 = await request({
        hostname: host,
        path: '/auth/api/v2/user/oauth2/token',
        method: 'POST',
        headers: baseHeaders({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(tokenBody),
        }),
    }, tokenBody);
    info(`[tokenManager] Step 5: HTTP ${step5.statusCode}`);

    if (step5.statusCode !== 200) {
        throw new Error(`Token exchange failed HTTP ${step5.statusCode}: ${step5.body.slice(0, 300)}`);
    }

    const tokens = JSON.parse(step5.body);
    if (!tokens.refresh_token) {
        throw new Error(`No refresh_token in token response: ${step5.body.slice(0, 200)}`);
    }
    info(`[tokenManager] Step 5: refresh_token and access_token received`);

    const expiresAt = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    return { refreshToken: tokens.refresh_token, accessToken: tokens.access_token, expiresAt };
}

/**
 * Returns true if the stored token expires within 14 days (or is missing).
 *
 * @param {string} expiresAt  ISO date string
 */
function isExpiringSoon(expiresAt) {
    if (!expiresAt) {
return true;
}
    const msLeft = new Date(expiresAt).getTime() - Date.now();
    return msLeft < 14 * 24 * 60 * 60 * 1000;
}

module.exports = { fetchToken, isExpiringSoon };
