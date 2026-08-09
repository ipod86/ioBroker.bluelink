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
 * Fetch a new refresh token using the Hyundai/Kia EU OAuth CCAPI connector flow.
 *
 * Flow:
 *  (1) GET /authorize (CCAPI client) → IDP 302 → CCAPI SPA URL
 *       IDP sets account=<token> cookie with Domain=hyundai.com (valid for both IDP + CCAPI).
 *       The SPA URL contains connector_session_key in the next_uri query parameter.
 *
 *  (1b) GET CCAPI SPA URL → sends account cookie to CCAPI domain.
 *       CCAPI /session endpoint checks account cookie → returns 204 (connector session ready).
 *       This activates the connector session on the IDP side via IDP↔CCAPI communication.
 *
 *  (2) GET /certs → RSA JWK for password encryption.
 *
 *  (3) POST /signin with connector_session_key and encrypted password.
 *       IDP authenticates user, updates account cookie to authenticated state.
 *       Response is 302 → back to IDP /authorize (standard OAuth post-signin redirect).
 *
 *  (4) Follow redirect chain from POST /signin until code appears:
 *       a) 302 → IDP /authorize (authenticated) → 302 → CCAPI SPA URL
 *       b) GET CCAPI SPA URL → GET CCAPI /session → 204 → next_uri is the target
 *       c) GET next_uri (IDP /authorize callback with connector_session_key)
 *          IDP sees authenticated user + valid connector_session_key → 302 → redirect_uri?code=XXX
 *       d) Extract code from redirect_uri URL.
 *
 *  (5) POST /token → access_token + refresh_token.
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

    // ── Step 1: GET /authorize → CCAPI SPA URL ──────────────────────────────────
    // IDP sets account cookie (Domain=hyundai.com) and redirects to CCAPI SPA URL.
    // The CCAPI SPA URL contains next_uri with the connector_session_key (CSK).
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

    // Extract connector_session_key and next_uri from CCAPI SPA URL
    let connectorSessionKey = '';
    let nextUri = '';
    let ccapiSpaHostname = '';
    let ccapiSpaPort = 8080;
    try {
        const ccapiUrl = new URL(ccapiSpaLocation);
        ccapiSpaHostname = ccapiUrl.hostname;
        ccapiSpaPort = parseInt(ccapiUrl.port || '443', 10);
        const rawNextUri = ccapiUrl.searchParams.get('next_uri') || '';
        if (rawNextUri) {
            nextUri = decodeURIComponent(rawNextUri);
            const country = ccapiUrl.searchParams.get('country') || '';
            if (country) {
nextUri += `${nextUri.includes('?') ? '&' : '?'  }country=${country}`;
}
            const nextUriParsed = new URL(nextUri);
            connectorSessionKey = nextUriParsed.searchParams.get('connector_session_key') || '';
        }
    } catch (_) { /* URL parse failed */ }

    info(`[tokenManager] Step 1: connector_session_key=${connectorSessionKey ? `${connectorSessionKey.slice(0, 8)}…` : 'not found'}`);

    if (!connectorSessionKey) {
        throw new Error(`connector_session_key not found in CCAPI SPA URL: ${ccapiSpaLocation.slice(0, 300)}`);
    }

    // ── Step 1b: GET CCAPI SPA URL ───────────────────────────────────────────────
    // Sends the IDP account cookie (Domain=hyundai.com) to the CCAPI domain,
    // establishing a CCAPI-side browser context for the connector session.
    info(`[tokenManager] Step 1b: GET CCAPI SPA URL`);
    try {
        const ccapiSpaUrl = new URL(ccapiSpaLocation);
        const step1b = await request({
            hostname: ccapiSpaUrl.hostname,
            port: parseInt(ccapiSpaUrl.port || '443', 10),
            path: ccapiSpaUrl.pathname + ccapiSpaUrl.search,
            method: 'GET',
            headers: baseHeaders({ Accept: 'text/html' }),
        });
        jar.ingest(step1b.headers);
        info(`[tokenManager] Step 1b: HTTP ${step1b.statusCode}`);
    } catch (e) {
        info(`[tokenManager] Step 1b: failed (${e instanceof Error ? e.message : String(e)}) — continuing`);
    }

    // ── Step 1c: GET CCAPI /session ──────────────────────────────────────────────
    // The CCAPI SPA JavaScript calls GET /api/v1/user/session after loading.
    // With the IDP account cookie (Domain=hyundai.com) in the jar, CCAPI returns
    // HTTP 204, which signals the IDP (via server-to-server communication) that
    // the connector session is activated and ready for login.
    // Without this step, the IDP /authorize call after signin fails with 500.
    info(`[tokenManager] Step 1c: GET CCAPI /session (connector session activation)`);
    try {
        const ccapiSpaUrl = new URL(ccapiSpaLocation);
        const step1c = await request({
            hostname: ccapiSpaUrl.hostname,
            port: parseInt(ccapiSpaUrl.port || '443', 10),
            path: '/api/v1/user/session',
            method: 'GET',
            headers: baseHeaders({
                Accept: 'application/json, text/plain, */*',
                Origin: `https://${ccapiSpaUrl.hostname}:${ccapiSpaUrl.port || '443'}`,
                Referer: ccapiSpaLocation.slice(0, 200),
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Dest': 'empty',
            }),
        });
        jar.ingest(step1c.headers);
        info(`[tokenManager] Step 1c: HTTP ${step1c.statusCode} (expected 204)`);
        if (step1c.statusCode !== 204 && step1c.statusCode !== 200) {
            info(`[tokenManager] Step 1c: unexpected status ${step1c.statusCode} — ${step1c.body.slice(0, 100)}`);
        }
    } catch (e) {
        info(`[tokenManager] Step 1c: failed (${e instanceof Error ? e.message : String(e)}) — continuing`);
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

    // Generate CSRF token — simulates browser JS setting the _hazkpw cookie
    // (IDP sends Set-Cookie: _hazkpw=; Max-Age=0 to delete any old value;
    //  browser JS then fills it with a fresh UUID; we replicate that here)
    const csrfToken = crypto.randomUUID();
    jar._cookies['_hazkpw'] = csrfToken;
    info(`[tokenManager] CSRF token: ${csrfToken.slice(0, 8)}…`);

    // ── Step 3: POST /signin ─────────────────────────────────────────────────────
    info(`[tokenManager] Step 3: POST https://${host}/auth/account/signin`);
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

    const step3 = await request({
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
    jar.ingest(step3.headers);
    info(`[tokenManager] Step 3: HTTP ${step3.statusCode}, location=${( step3.headers['location'] || '').slice(0, 120)}`);

    if (step3.statusCode !== 302) {
        throw new Error(`Signin returned HTTP ${step3.statusCode}: ${step3.body.slice(0, 300)}`);
    }

    // ── Step 4: Follow redirect chain until code appears ───────────────────────
    // After successful signin the IDP sends:
    //   302 → IDP /authorize (authenticated) → 302 → CCAPI SPA URL
    //   Simulate SPA: GET /session → 204 → GET next_uri
    //   GET next_uri (IDP callback + CSK, now with authenticated account cookie)
    //   → 302 → redirect_uri?code=XXX
    //
    // Up to 8 hops to handle all intermediate redirects.

    let codeParam = null;
    let currentLocation = step3.headers['location'] || '';

    for (let hop = 0; hop < 8 && !codeParam; hop++) {
        if (!currentLocation) {
break;
}

        info(`[tokenManager] Step 4 hop ${hop + 1}: ${currentLocation.slice(0, 120)}`);

        // Absolute URL → parse; relative → resolve against IDP host
        let locUrl;
        try {
            locUrl = new URL(currentLocation.startsWith('http') ? currentLocation : `https://${host}${currentLocation}`);
        } catch (_) {
            info(`[tokenManager] Step 4: cannot parse location, stopping`);
            break;
        }

        // Success: redirect_uri with code
        if (locUrl.searchParams.has('code')) {
            codeParam = locUrl.searchParams.get('code');
            break;
        }

        // Explicit OAuth error
        if (locUrl.searchParams.has('error')) {
            const err = locUrl.searchParams.get('error');
            const errDesc = locUrl.searchParams.get('error_description');
            throw new Error(`OAuth error: ${err} — ${errDesc}`);
        }

        // CCAPI SPA URL → simulate SPA: GET CCAPI SPA + GET next_uri
        if (locUrl.hostname === ccapiSpaHostname && locUrl.pathname.startsWith('/web/')) {
            info(`[tokenManager] Step 4 hop ${hop + 1}: CCAPI SPA URL — loading SPA, then calling next_uri`);

            // GET CCAPI SPA URL (sends account cookie, activates session)
            try {
                const spaResp = await request({
                    hostname: locUrl.hostname,
                    port: parseInt(locUrl.port || '443', 10),
                    path: locUrl.pathname + locUrl.search,
                    method: 'GET',
                    headers: baseHeaders({ Accept: 'text/html' }),
                });
                jar.ingest(spaResp.headers);
                info(`[tokenManager] Step 4 hop ${hop + 1}: CCAPI SPA loaded (${spaResp.statusCode})`);
            } catch (e) {
                info(`[tokenManager] Step 4 hop ${hop + 1}: CCAPI SPA load failed (${e instanceof Error ? e.message : String(e)})`);
            }

            // Extract next_uri from the (possibly updated) CCAPI SPA URL params
            // Use the original nextUri if SPA URL has no next_uri (post-login SPA URL should have one)
            let hopNextUri = nextUri;
            try {
                const rawHopNextUri = locUrl.searchParams.get('next_uri') || '';
                if (rawHopNextUri) {
                    hopNextUri = decodeURIComponent(rawHopNextUri);
                    const country = locUrl.searchParams.get('country') || '';
                    if (country) {
hopNextUri += `${hopNextUri.includes('?') ? '&' : '?'  }country=${country}`;
}
                }
            } catch (_) { /* keep original nextUri */ }

            if (!hopNextUri) {
                info(`[tokenManager] Step 4 hop ${hop + 1}: no next_uri available — stopping`);
                break;
            }

            // GET next_uri — IDP callback with connector_session_key + authenticated account cookie
            info(`[tokenManager] Step 4 hop ${hop + 1}: GET next_uri=${hopNextUri.slice(0, 80)}…`);
            const nuParsed = new URL(hopNextUri);
            const nuResp = await request({
                hostname: nuParsed.hostname,
                port: parseInt(nuParsed.port || '443', 10),
                path: nuParsed.pathname + nuParsed.search,
                method: 'GET',
                headers: baseHeaders({
                    Referer: locUrl.href,
                    'Sec-Fetch-Site': 'cross-site',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Dest': 'document',
                    'Upgrade-Insecure-Requests': '1',
                }),
            });
            jar.ingest(nuResp.headers);
            info(`[tokenManager] Step 4 hop ${hop + 1}: next_uri HTTP ${nuResp.statusCode}, location=${( nuResp.headers['location'] || '').slice(0, 120)}`);

            if (nuResp.statusCode === 302) {
                currentLocation = nuResp.headers['location'] || '';
            } else if (nuResp.statusCode === 200) {
                // Possible: IDP login page rendered (no redirect). Flow stalled.
                info(`[tokenManager] Step 4: next_uri returned 200 (login page?) — stalled`);
                break;
            } else {
                throw new Error(`next_uri returned HTTP ${nuResp.statusCode}: ${nuResp.body.slice(0, 200)}`);
            }

            continue;
        }

        // IDP or other URL → follow the redirect
        const followResp = await request({
            hostname: locUrl.hostname,
            port: parseInt(locUrl.port || '443', 10),
            path: locUrl.pathname + locUrl.search,
            method: 'GET',
            headers: baseHeaders({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-site',
                'Upgrade-Insecure-Requests': '1',
            }),
        });
        jar.ingest(followResp.headers);
        info(`[tokenManager] Step 4 hop ${hop + 1}: follow HTTP ${followResp.statusCode}, next=${( followResp.headers['location'] || '').slice(0, 100)}`);

        currentLocation = followResp.headers['location'] || '';
    }

    if (!codeParam) {
        throw new Error(`No authorization code found in redirect chain. Last location: ${currentLocation.slice(0, 300)}`);
    }
    info(`[tokenManager] Step 4: Authorization code obtained (${codeParam.length} chars)`);

    // ── Step 5: Exchange code for tokens ─────────────────────────────────────────
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
