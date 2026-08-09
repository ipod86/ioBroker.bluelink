#!/usr/bin/env python3
"""Hyundai/Kia EU headless token fetch — uses curl_cffi for Chrome TLS impersonation."""
import sys
import json
import base64
import datetime
from urllib.parse import urlparse, parse_qs, quote

BRANDS = {
    'hyundai': {
        'idp': 'idpconnect-eu.hyundai.com',
        'client_id': '6d477c38-3ca4-4cf3-9557-2a1929a94654',
        'client_secret': 'KUy49XxPzLpLuoK0xhBC77W6VXhmtQR9iQhmIFjjoY4IpxsV',
        'redirect_uri': 'https://prd.eu-ccapi.hyundai.com:8080/api/v1/user/oauth2/token',
    },
    'kia': {
        'idp': 'idpconnect-eu.kia.com',
        'client_id': 'fdc85c00-0a2f-4c64-bcb4-2cfb1500730a',
        'client_secret': 'secret',
        'redirect_uri': 'https://prd.eu-ccapi.kia.com:8080/api/v1/user/oauth2/redirect',
    },
}

UA = ('Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) '
      'AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19_CCS_APP_AOS')


def b64url_to_bytes(s):
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def encrypt_rsa_pkcs1_hex(n_b64, e_b64, plaintext):
    n = int.from_bytes(b64url_to_bytes(n_b64), 'big')
    e = int.from_bytes(b64url_to_bytes(e_b64), 'big')
    try:
        from cryptography.hazmat.primitives.asymmetric import padding as apad
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.backends import default_backend
        pub = RSAPublicNumbers(e, n).public_key(default_backend())
        return pub.encrypt(plaintext.encode(), apad.PKCS1v15()).hex()
    except ImportError:
        pass
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
        key = RSA.construct((n, e))
        return PKCS1_v1_5.new(key).encrypt(plaintext.encode()).hex()
    except ImportError:
        pass
    raise ImportError(
        'No RSA library found. Run: pip3 install cryptography  or  pip3 install pycryptodome'
    )


def main():
    args = json.loads(sys.argv[1])
    brand    = args['brand']
    username = args['username']
    password = args['password']

    cfg  = BRANDS[brand]
    base = f"https://{cfg['idp']}"
    ruri = cfg['redirect_uri']

    try:
        from curl_cffi.requests import Session
        sess = Session(impersonate='chrome131_android')
        print('[py] curl_cffi chrome131_android', file=sys.stderr)
    except ImportError:
        import requests
        sess = requests.Session()
        print('[py] WARNING: curl_cffi missing — no TLS impersonation (pip3 install curl_cffi)', file=sys.stderr)

    hdrs = {
        'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8',
    }

    # Step 1: establish session cookies
    r1 = sess.get(
        f"{base}/auth/api/v2/user/oauth2/authorize"
        f"?response_type=code&client_id={cfg['client_id']}"
        f"&redirect_uri={quote(ruri, safe='')}"
        f"&lang=de&state=ccsp&country=DE",
        headers=hdrs, allow_redirects=False, timeout=15,
    )
    print(f'[py] Step 1: HTTP {r1.status_code}, cookies: {list(sess.cookies.keys())}', file=sys.stderr)

    # Step 2: RSA public key
    r2 = sess.get(f"{base}/auth/api/v1/accounts/certs", headers=hdrs, timeout=15)
    jwk = r2.json()['retValue']
    print(f'[py] Step 2: HTTP {r2.status_code}, kid={jwk["kid"]}', file=sys.stderr)

    enc_pw  = encrypt_rsa_pkcs1_hex(jwk['n'], jwk['e'], password)
    hazkpw  = sess.cookies.get('_hazkpw', '')
    print(f'[py] _hazkpw={"[" + hazkpw[:8] + "…]" if hazkpw else "empty"}', file=sys.stderr)

    # Step 3: POST signin
    r3 = sess.post(
        f"{base}/auth/account/signin",
        data={
            'client_id': cfg['client_id'],
            'encryptedPassword': 'true',
            'password': enc_pw,
            'redirect_uri': ruri,
            'scope': '', 'nonce': '', 'state': 'ccsp',
            'username': username,
            'connector_session_key': '',
            'kid': jwk['kid'],
            '_csrf': hazkpw,
        },
        headers={
            **hdrs,
            'Origin': base,
            'Referer': f"{base}/auth/ui/login",
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
        },
        allow_redirects=False, timeout=15,
    )
    location = r3.headers.get('location', '')
    print(f'[py] Step 3: HTTP {r3.status_code}, location={location[:120]}', file=sys.stderr)

    code = parse_qs(urlparse(location).query).get('code', [None])[0]
    if not code:
        raise ValueError(f'No code in redirect location: {location[:250]}')

    # Step 4: token exchange
    r4 = sess.post(
        f"{base}/auth/api/v2/user/oauth2/token",
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': ruri,
            'client_id': cfg['client_id'],
            'client_secret': cfg['client_secret'],
        },
        headers={**hdrs, 'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=15,
    )
    print(f'[py] Step 4: HTTP {r4.status_code}', file=sys.stderr)
    tokens = r4.json()
    if 'refresh_token' not in tokens:
        raise ValueError(f'No refresh_token in response: {r4.text[:200]}')

    expires = (datetime.datetime.utcnow() + datetime.timedelta(days=180)).strftime(
        '%Y-%m-%dT%H:%M:%S.000Z'
    )
    print(json.dumps({
        'refreshToken': tokens['refresh_token'],
        'accessToken':  tokens['access_token'],
        'expiresAt':    expires,
    }))


try:
    main()
except Exception as ex:
    print(json.dumps({'error': str(ex)}))
    sys.exit(1)
