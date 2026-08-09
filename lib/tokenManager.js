'use strict';

const https = require('node:https');
const crypto = require('node:crypto');
const { URLSearchParams, URL } = require('node:url');

const BRANDS = {
    hyundai: {
        idpHost: 'idpconnect-eu.hyundai.com',
        // Portal login client — no CCAPI session required for initial auth
        loginClientId: 'peuhyundaiidm-ctb',
        loginRedirectUri: 'https://ctbapi.hyundai-europe.com/api/auth',
        // CCAPI client — used after auth to obtain the authorization code
        clientId: '6d477c38-3ca4-4cf3-9557-2a1929a94654',
        clientSecret: 'KUy49XxPzLpLuoK0xhBC77W6VXhmtQR9iQhmIFjjoY4IpxsV',
        redirectUri: 'https://prd.eu-ccapi.hyundai.com:8080/api/v1/user/oauth2/token',
    },
    kia: {
        idpHost: 'idpconnect-eu.kia.com',
        loginClientId: 'peukiaidm-online-sales',
        loginRedirectUri: 'https://www.kia.com/api/bin/oneid/login',
        clientId: 'fdc85c00-0a2f-4c64-bcb4-2cfb1500730a',
        clientSecret: 'secret',
        redirectUri: 'https://prd.eu-ccapi.kia.com:8080/api/v1/user/oauth2/redirect',
    },
};

const USER_AGENT = 'Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/535.19_CCS_APP_AOS';

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
 * @param body
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
 * @param password
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
 * Flow: (1) GET /authorize with portal login client → IDP session cookies
 *       (2) GET /certs → JWK for password encryption
 *       (3) POST /signin with login client → authenticated IDP session
 *       (4) GET /authorize with CCAPI client → IDP issues code via 302
 *       (5) POST /token → access_token + refresh_token
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

    // Step 1: GET /authorize with portal login client — establishes IDP session, no CCAPI required
    info(`[tokenManager] Step 1: GET https://${host}/auth/api/v2/user/oauth2/authorize (login client=${cfg.loginClientId})`);
    const loginAuthorizeUrl = (
        `/auth/api/v2/user/oauth2/authorize?client_id=${cfg.loginClientId}` +
        `&redirect_uri=${encodeURIComponent(cfg.loginRedirectUri)}` +
        `&nonce=&state=PL_&scope=openid+profile+email+phone&response_type=code` +
        `&connector_client_id=${cfg.loginClientId}&connector_scope=&connector_session_key=` +
        `&country=&captcha=1&ui_locales=de`
    );
    const step1 = await request({ hostname: host, path: loginAuthorizeUrl, method: 'GET', headers: baseHeaders() });
    jar.ingest(step1.headers);
    info(`[tokenManager] Step 1: HTTP ${step1.statusCode}, cookies: ${Object.keys(jar._cookies).join(', ') || 'none'}`);

    // IDP sets _hazkpw='' (empty); browser JS normally fills it with a UUID.
    // We replicate the browser behaviour: set cookie + matching _csrf form field.
    const csrfToken = crypto.randomUUID();
    jar._cookies['_hazkpw'] = csrfToken;
    info(`[tokenManager] CSRF token generated (${csrfToken.slice(0, 8)}…)`);

    // Step 2: GET RSA public key for password encryption
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

    // Step 3: POST /signin — authenticates with login client (no connector_session_key needed)
    info(`[tokenManager] Step 3: POST https://${host}/auth/account/signin (csrf=${csrfToken.slice(0, 8)}…)`);
    const signinBody = new URLSearchParams({
        client_id: cfg.loginClientId,
        encryptedPassword: 'true',
        password: encryptedPw,
        redirect_uri: cfg.loginRedirectUri,
        scope: 'openid profile email phone',
        nonce: '',
        state: 'PL_',
        username,
        connector_session_key: '',
        kid: jwk.kid,
        _csrf: csrfToken,
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
    const step3Location = step3.headers['location'] || '';
    info(`[tokenManager] Step 3: HTTP ${step3.statusCode}, location=${step3Location.slice(0, 120)}`);
    if (step3.body) {
        info(`[tokenManager] Step 3: body=${step3.body.slice(0, 200)}`);
    }

    if (step3.statusCode !== 302) {
        throw new Error(`Signin returned HTTP ${step3.statusCode}: ${step3.body.slice(0, 300)}`);
    }

    // A redirect back to /authorize (no error param) is the normal post-signin OAuth redirect.
    // Only throw if the server explicitly signals an error.
    if (step3Location.includes('error=')) {
        const loc3 = new URL(step3Location, `https://${host}`);
        const err3 = loc3.searchParams.get('error') || loc3.searchParams.get('error_description') || loc3.searchParams.get('msg');
        throw new Error(`Signin error: ${err3 || step3Location.slice(0, 200)}`);
    }
    info(`[tokenManager] Step 3: signin redirect → ${step3Location.split('?')[0].slice(0, 70)}`);

    // Step 4: GET /authorize with CCAPI client — authenticated session → IDP issues code directly
    info(`[tokenManager] Step 4: GET https://${host}/auth/api/v2/user/oauth2/authorize (CCAPI client=${cfg.clientId.slice(0, 8)}…)`);
    const ccapiAuthorizeUrl = (
        `/auth/api/v2/user/oauth2/authorize?response_type=code` +
        `&client_id=${cfg.clientId}` +
        `&redirect_uri=${encodeURIComponent(cfg.redirectUri)}` +
        `&lang=de&state=ccsp`
    );
    const step4 = await request({ hostname: host, path: ccapiAuthorizeUrl, method: 'GET', headers: baseHeaders() });
    jar.ingest(step4.headers);
    const step4Location = step4.headers['location'] || '';
    info(`[tokenManager] Step 4: HTTP ${step4.statusCode}, location=${step4Location.slice(0, 120)}`);

    if (step4.statusCode !== 302) {
        throw new Error(`CCAPI authorize returned HTTP ${step4.statusCode}: ${step4.body.slice(0, 200)}`);
    }

    let codeParam;
    try {
        const loc4 = new URL(step4Location, `https://${host}`);
        codeParam = loc4.searchParams.get('code');
        const err4 = loc4.searchParams.get('error');
        if (err4) {
            const errDesc = loc4.searchParams.get('error_description');
            throw new Error(`CCAPI authorize error: ${err4} — ${errDesc}`);
        }
    } catch (e) {
        if (String(e).includes('CCAPI authorize')) {
throw e;
}
        throw new Error(`Cannot parse Step 4 location: ${step4Location.slice(0, 200)}`);
    }

    if (!codeParam) {
        // If still redirecting to CCAPI SPA, mention it explicitly
        const step4Host = step4Location.split('/').slice(0, 3).join('/');
        if (step4Location.includes('prd.eu-ccapi') || step4Location.includes('idpconnect')) {
            throw new Error(`No code — IDP redirected to ${step4Host} instead of issuing code. Session may not be authenticated.`);
        }
        throw new Error(`No code in Step 4 redirect: ${step4Location.slice(0, 200)}`);
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
