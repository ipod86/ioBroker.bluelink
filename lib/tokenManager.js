'use strict';

const https = require('node:https');
const http = require('node:http');
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

/** Simple cookie jar — stores name=value pairs, domain-agnostic (all cookies sent to all requests) */
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
 * Low-level HTTPS/HTTP request returning { statusCode, headers, body }
 *
 * @param opts
 * @param {string} [body]
 */
function request(opts, body = undefined) {
    return new Promise((resolve, reject) => {
        const isHttps = !opts.port || opts.port !== 80;
        const agent = isHttps ? new https.Agent({
            ciphers: CHROME_CIPHERS,
            honorCipherOrder: false,
            minVersion: 'TLSv1.2',
        }) : undefined;

        const mod = isHttps ? https : http;
        const req = mod.request({ ...opts, agent }, (res) => {
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
 * Flow (based on RustyDust/bluelink_refresh_token headless mode):
 *  (1) GET /authorize — follow all redirects to collect session cookies.
 *      Key cookies: account (IDP session), _hazkpw (CSRF seed).
 *
 *  (2) GET /certs → RSA JWK for password encryption.
 *
 *  (3) POST /signin with empty connector_session_key and _csrf.
 *      IDP authenticates user and responds 302 with code= directly in the location.
 *
 *  (4) POST /token → access_token + refresh_token.
 *
 * @param {string} brand     'hyundai' | 'kia'
 * @param {string} username
 * @param {string} password  actual account password
 * @param {Function} [log]   optional logger (msg) => void
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

    // ── Step 1: GET /authorize — follow redirects to collect cookies ────────────
    info(`[tokenManager] Step 1: GET https://${host}/auth/api/v2/user/oauth2/authorize`);
    const authorizeUrl = (
        `/auth/api/v2/user/oauth2/authorize?response_type=code` +
        `&client_id=${cfg.clientId}` +
        `&redirect_uri=${encodeURIComponent(cfg.redirectUri)}` +
        `&lang=de&state=ccsp&country=de`
    );

    let currentLocation = `https://${host}${authorizeUrl}`;
    for (let hop = 0; hop < 5; hop++) {
        const locUrl = new URL(currentLocation);
        const resp = await request({
            hostname: locUrl.hostname,
            port: locUrl.port ? parseInt(locUrl.port, 10) : (locUrl.protocol === 'https:' ? 443 : 80),
            path: locUrl.pathname + locUrl.search,
            method: 'GET',
            headers: baseHeaders(),
        });
        jar.ingest(resp.headers);
        if (resp.statusCode === 302 && resp.headers['location']) {
            const next = resp.headers['location'];
            currentLocation = next.startsWith('http') ? next : `https://${locUrl.hostname}${next}`;
            info(`[tokenManager] Step 1 hop ${hop + 1}: HTTP 302 → ${currentLocation.slice(0, 80)}…`);
        } else {
            info(`[tokenManager] Step 1: HTTP ${resp.statusCode}, cookies: ${Object.keys(jar._cookies).join(', ') || 'none'}`);
            break;
        }
    }

    // ── Step 2: GET /certs → RSA JWK ────────────────────────────────────────────
    info(`[tokenManager] Step 2: GET https://${host}/auth/api/v1/accounts/certs`);
    const step2 = await request({ hostname: host, path: '/auth/api/v1/accounts/certs', method: 'GET', headers: baseHeaders() });
    jar.ingest(step2.headers);
    info(`[tokenManager] Step 2: HTTP ${step2.statusCode}`);
    if (step2.statusCode !== 200) {
        throw new Error(`Certs endpoint returned ${step2.statusCode}: ${step2.body.slice(0, 200)}`);
    }
    const jwk = JSON.parse(step2.body).retValue;
    if (!jwk || !jwk.kid) {
        throw new Error(`No JWK in certs response: ${step2.body.slice(0, 200)}`);
    }
    info(`[tokenManager] Step 2: JWK kid=${jwk.kid}`);

    const encryptedPw = encryptPassword(jwk, password);
    info(`[tokenManager] Step 2: Password RSA-encrypted, base64 len=${encryptedPw.length}`);

    // ── Step 3: POST /signin → expect 302 with code= directly ───────────────────
    // Sending connector_session_key="" bypasses the connector flow entirely;
    // the IDP responds with code= in the redirect location directly.
    info(`[tokenManager] Step 3: POST https://${host}/auth/account/signin`);
    const signinBody = new URLSearchParams({
        client_id: cfg.clientId,
        encryptedPassword: 'true',
        password: encryptedPw,
        redirect_uri: cfg.redirectUri,
        scope: '', nonce: '', state: 'ccsp',
        username,
        connector_session_key: '',
        kid: jwk.kid,
        _csrf: '',
    }).toString();

    const step3 = await request({
        hostname: host,
        path: '/auth/account/signin',
        method: 'POST',
        headers: baseHeaders({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(signinBody),
            Origin: `https://${host}`,
            Referer: `https://${host}/auth/ui/login`,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }),
    }, signinBody);
    jar.ingest(step3.headers);
    const signinLocation = step3.headers['location'] || '';
    info(`[tokenManager] Step 3: HTTP ${step3.statusCode}, location=${signinLocation.slice(0, 120)}`);

    if (step3.statusCode !== 302) {
        throw new Error(`Signin returned HTTP ${step3.statusCode}: ${step3.body.slice(0, 300)}`);
    }

    // Follow up to 3 redirects after /signin until code= appears.
    // With empty connector_session_key the IDP redirects once more to /authorize
    // (with the authenticated session) which then returns the code.
    let codeParam = null;
    let nextLoc = signinLocation;

    for (let hop = 0; hop < 4 && !codeParam; hop++) {
        if (!nextLoc) {
break;
}
        const locUrl = new URL(nextLoc.startsWith('http') ? nextLoc : `https://${host}${nextLoc}`);
        if (locUrl.searchParams.has('error')) {
            throw new Error(`OAuth error: ${locUrl.searchParams.get('error')} — ${locUrl.searchParams.get('error_description')}`);
        }
        if (locUrl.searchParams.has('code')) {
            codeParam = locUrl.searchParams.get('code');
            break;
        }
        // Need to follow this redirect
        info(`[tokenManager] Step 3 hop ${hop + 1}: follow ${nextLoc.slice(0, 100)}`);
        const hopResp = await request({
            hostname: locUrl.hostname,
            port: locUrl.port ? parseInt(locUrl.port, 10) : 443,
            path: locUrl.pathname + locUrl.search,
            method: 'GET',
            headers: baseHeaders({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-site',
                'Upgrade-Insecure-Requests': '1',
            }),
        });
        jar.ingest(hopResp.headers);
        info(`[tokenManager] Step 3 hop ${hop + 1}: HTTP ${hopResp.statusCode}, next=${(hopResp.headers['location'] || '').slice(0, 100)}`);
        nextLoc = hopResp.headers['location'] || '';
    }

    if (!codeParam) {
        throw new Error(`No authorization code in redirect chain. Last location: ${nextLoc.slice(0, 300)}`);
    }
    info(`[tokenManager] Step 3: Authorization code obtained (${codeParam.length} chars)`);

    // ── Step 4: Exchange code for tokens ─────────────────────────────────────────
    info(`[tokenManager] Step 4: POST https://${host}/auth/api/v2/user/oauth2/token`);
    const tokenBody = new URLSearchParams({
        grant_type: 'authorization_code',
        code: codeParam,
        redirect_uri: cfg.redirectUri,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
    }).toString();

    const step4 = await request({
        hostname: host,
        path: '/auth/api/v2/user/oauth2/token',
        method: 'POST',
        headers: baseHeaders({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(tokenBody),
        }),
    }, tokenBody);
    info(`[tokenManager] Step 4: HTTP ${step4.statusCode}`);

    if (step4.statusCode !== 200) {
        throw new Error(`Token exchange failed HTTP ${step4.statusCode}: ${step4.body.slice(0, 300)}`);
    }

    const tokens = JSON.parse(step4.body);
    if (!tokens.refresh_token) {
        throw new Error(`No refresh_token in token response: ${step4.body.slice(0, 200)}`);
    }
    info(`[tokenManager] Step 4: refresh_token and access_token received`);

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
