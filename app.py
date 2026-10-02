"""PC-compatible WAR2 license verification; persistence lives in Supabase."""
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request as HttpRequest, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
PUBLIC = serialization.load_pem_public_key(Path(__file__).with_name('owner-public.pem').read_bytes())


def response(status, body):
    return JSONResponse(body, status_code=status, headers={'Cache-Control': 'no-store'})


def un64(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid token encoding')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def verify(token):
    if not isinstance(token, str) or len(token) > 8192:
        raise ValueError('Invalid key')
    prefix, payload, signature = token.split('.')
    if prefix != 'WAR2':
        raise ValueError('Wrong product')
    raw = un64(payload)
    PUBLIC.verify(un64(signature), raw, PSS, hashes.SHA256())
    claims = json.loads(raw)
    if not isinstance(claims, dict):
        raise ValueError('Invalid claims')
    return claims


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Invalid expiry')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timezone required')
    return parsed


def signing_key():
    pem = os.environ['OWNER_PRIVATE_KEY_PEM'].replace('\\n', '\n').encode()
    private = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(private, rsa.RSAPrivateKey) or private.public_key().public_numbers() != PUBLIC.public_numbers():
        raise ValueError('Owner signing key mismatch')
    return private


def sign(claims, private):
    raw = json.dumps(claims, separators=(',', ':'), ensure_ascii=True).encode()
    return 'WAR2.' + b64(raw) + '.' + b64(private.sign(raw, PSS, hashes.SHA256()))


def normalize_macs(values):
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError('Invalid MAC list')
    result = set()
    for value in values:
        if not isinstance(value, str) or len(value) > 32:
            raise ValueError('Invalid MAC')
        value = re.sub(r'[:-]', '', value).upper()
        if re.fullmatch(r'[0-9A-F]{12}', value) and value not in ('000000000000', 'FFFFFFFFFFFF') and not int(value[:2], 16) & 1:
            result.add(value)
    return sorted(result)


def requester_ip(request):
    # Vercel overwrites X-Forwarded-For. Outside Vercel, trust the socket only.
    if os.environ.get('VERCEL') == '1':
        value = request.headers.get('x-forwarded-for', '')
        if ',' in value:
            raise ValueError('Ambiguous gateway address')
    else:
        value = request.client.host if request.client else ''
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def authorize_db(arguments):
    url = os.environ['SUPABASE_URL'].rstrip('/')
    if not re.fullmatch(r'https://[a-z0-9]+\.supabase\.co', url):
        raise ValueError('Invalid Supabase URL')
    secret = os.environ['SUPABASE_SECRET_KEY']
    headers = {'apikey': secret, 'Content-Type': 'application/json'}
    if not secret.startswith('sb_secret_'):
        headers['Authorization'] = 'Bearer ' + secret
    req = HttpRequest(url + '/rest/v1/rpc/war_authorize', json.dumps(arguments).encode(), headers=headers)
    with urlopen(req, timeout=5) as result:
        body = json.load(result)
    if not isinstance(body, dict) or body.get('status') not in (200, 403, 429):
        raise ValueError('Invalid database result')
    return body


@app.get('/health')
def health():
    # Does not expose configuration or claim database readiness.
    return response(200, {'status': 'running', 'product': 'WiFi Audio Robot License Server', 'runtime': 'Python'})


@app.post('/v1/authorize')
async def authorize(request: Request):
    try:
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 16384:
                return response(413, {'error': 'Request too large.'})
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('Invalid request')
        device, nonce, key = data.get('deviceId'), data.get('nonce'), data.get('key')
        if not isinstance(device, str) or not re.fullmatch(r'[A-F0-9]{32}', device):
            raise ValueError('Invalid device code')
        if not isinstance(nonce, str) or not re.fullmatch(r'[A-Fa-f0-9]{32}', nonce) or not isinstance(key, str) or len(key) > 8192:
            raise ValueError('Invalid nonce or key')
        macs = normalize_macs([] if data.get('macAddresses') is None else data['macAddresses'])
        ip = requester_ip(request)
    except (ValueError, TypeError):
        return response(400, {'error': 'Invalid device, nonce or identity request.'})
    claims = None
    if key.strip():
        try:
            claims = verify(key)
            if claims.get('Kind') != 'subscription' or claims.get('DeviceId') != device:
                raise ValueError('Wrong PC')
            if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', claims.get('LicenseId', '')):
                raise ValueError('Invalid license ID')
            timestamp(claims['ExpiresUtc'])
        except (ValueError, TypeError, KeyError, InvalidSignature):
            return response(403, {'error': 'Invalid license or key belongs to another PC.'})
    try:
        # Validate configuration before writing trial state.
        private = signing_key()
        arguments = {'p_device': device, 'p_ip_hash': hashlib.sha256(('WiFiAudioRobot-IP-v2|' + ip).encode()).hexdigest().upper(), 'p_macs': macs,
                     'p_license_id': claims['LicenseId'] if claims else None, 'p_expires': claims['ExpiresUtc'] if claims else None}
        # The synchronous route work runs in a worker thread, not on the ASGI loop.
        from starlette.concurrency import run_in_threadpool
        result = await run_in_threadpool(authorize_db, arguments)
        if result['status'] != 200:
            return response(result['status'], {'error': result.get('error', 'License rejected.')})
        server_time = result['serverUtc']
        # Preserve .NET's exact seven-digit expiry for offline cache equality.
        expiry = claims['ExpiresUtc'] if claims else result['expiresUtc']
        seconds = min(180, math.floor((timestamp(expiry) - timestamp(server_time)).total_seconds()))
        if seconds < 1:
            return response(403, {'error': 'License expired.'})
        grant = {'Kind': 'subscription' if claims else 'trial', 'DeviceId': device,
                 'LicenseId': claims['LicenseId'] if claims else 'trial-' + device,
                 'ExpiresUtc': expiry, 'Nonce': nonce, 'LeaseSeconds': seconds, 'ServerUtc': server_time}
        return response(200, {'token': sign(grant, private)})
    except Exception:
        # Fail closed without logging request keys or infrastructure credentials.
        return response(503, {'error': 'License service unavailable. Try again shortly.'})
