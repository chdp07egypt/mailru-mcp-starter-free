# SPDX-License-Identifier: Apache-2.0
# Public starter adaptation, 2026-10-25: configurable origin and explicit mail.access consent.
"""Single-owner OAuth authorization server with Google OIDC identity verification.

No Google tokens are returned to MCP clients. Authorization codes and browser
transactions are short-lived and deliberately lost on process restart.
"""
import base64
import hashlib
import hmac
import html
import os
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import anyio
import httpx
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

# Public template: one permission, explicitly consented on first connection.
SCOPE = 'mail.access'
SCOPES = [SCOPE]
COOKIE = '__Host-mailru-oauth'
JWKS = jwt.PyJWKClient('https://www.googleapis.com/oauth2/v3/certs')
flows = {}
codes = {}


def origin():
    base = os.environ.get('PUBLIC_BASE_URL', '').strip()
    if not base:
        hostname = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
        base = 'https://' + hostname if hostname else 'http://localhost:8000'
    parsed = urlsplit(base)
    local_http = parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1'}
    if (not parsed.hostname or (parsed.scheme != 'https' and not local_http)
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {'', '/'}):
        raise ValueError('PUBLIC_BASE_URL must be an HTTPS origin without path or credentials')
    return base.rstrip('/')


def signing_key():
    key = os.environ.get('MCP_ACCESS_TOKEN', '')
    if len(key) < 32:
        raise ValueError('OAuth signing key not configured')
    # Domain separation prevents using raw API keys as JWT keys.
    return hashlib.sha256(('mailru-oauth-v1:' + key).encode()).digest()


def signed(kind, data, ttl):
    now = int(time.time())
    return jwt.encode({**data, 'iss': origin(), 'aud': kind,
                       'iat': now, 'exp': now + ttl}, signing_key(), algorithm='HS256')


def unpack(value, kind):
    return jwt.decode(value, signing_key(), algorithms=['HS256'], issuer=origin(),
                      audience=kind, options={'require': ['iss', 'aud', 'exp', 'iat']})


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def redirect_allowed(uri):
    # Only callbacks owned by the ChatGPT client. Never fetch caller-supplied URLs.
    u = urlsplit(uri)
    return (u.scheme == 'https' and u.hostname in {'chatgpt.com', 'chat.openai.com'}
            and u.port in {None, 443} and not u.username and not u.password
            and not u.fragment and not u.query
            and (u.path == '/connector_platform_oauth_redirect'
                 or re.fullmatch(r'/aip/[A-Za-z0-9_-]+/oauth/callback', u.path) is not None
                 or re.fullmatch(r'/connector/oauth/[A-Za-z0-9_-]+', u.path) is not None))


def cleanup(store):
    for key in list(store):
        if store[key]['expires'] < time.time():
            del store[key]
    if len(store) >= 500:
        raise ValueError('Too many pending authorizations; try later')


def secure(response):
    response.headers.update({'Cache-Control': 'no-store', 'Pragma': 'no-cache',
                             'Referrer-Policy': 'same-origin',
                             'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com/connector_platform_oauth_redirect https://chat.openai.com/connector_platform_oauth_redirect https://chatgpt.com/aip/ https://chat.openai.com/aip/ https://chatgpt.com/connector/oauth/ https://chat.openai.com/connector/oauth/; frame-ancestors 'none'; base-uri 'none'"})
    return response


def error(message, status=400):
    return secure(JSONResponse({'error': message}, status_code=status))


def configured():
    return all(os.environ.get(x) for x in ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'ALLOWED_GOOGLE_EMAIL'])


def check_owner(claims, nonce):
    if claims.get('nonce') != nonce or claims.get('email_verified') is not True:
        raise ValueError('Unverified Google identity')
    allowed = os.environ.get('ALLOWED_GOOGLE_EMAIL', '').strip().lower()
    if not allowed or claims.get('email', '').lower() != allowed:
        raise ValueError('This Google account is not allowed')
    if os.environ.get('ALLOWED_GOOGLE_SUB') and claims.get('sub') != os.environ['ALLOWED_GOOGLE_SUB']:
        raise ValueError('Google account identifier mismatch')
    if not claims.get('sub'):
        raise ValueError('Google subject missing')
    return claims['sub']


def normalized_scope(value):
    scopes = set(value.split())
    if SCOPE not in scopes or not scopes <= set(SCOPES):
        raise ValueError('invalid_scope')
    return ' '.join(s for s in SCOPES if s in scopes)


def access_scopes(token):
    try:
        claims = unpack(token, origin() + '/mcp')
        normalized_scope(claims.get('scope', ''))
        valid = (claims.get('email') == os.environ.get('ALLOWED_GOOGLE_EMAIL', '').strip().lower()
                and bool(claims.get('sub'))
                and (not os.getenv('ALLOWED_GOOGLE_SUB') or claims['sub'] == os.environ['ALLOWED_GOOGLE_SUB']))
    except (jwt.PyJWTError, ValueError):
        return None
    return frozenset([SCOPE]) if valid else None


def access_valid(token):
    return access_scopes(token) is not None


async def metadata(request):
    base = origin()
    if 'oauth-protected-resource' in request.url.path:
        return JSONResponse({'resource': base + '/mcp', 'authorization_servers': [base],
                             'scopes_supported': SCOPES, 'bearer_methods_supported': ['header']})
    return JSONResponse({'issuer': base, 'authorization_endpoint': base + '/oauth/authorize',
                         'token_endpoint': base + '/oauth/token', 'registration_endpoint': base + '/oauth/register',
                         'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code', 'refresh_token'],
                         'code_challenge_methods_supported': ['S256'], 'token_endpoint_auth_methods_supported': ['none'],
                         'scopes_supported': SCOPES, 'authorization_response_iss_parameter_supported': True})


async def register(request):
    try:
        if len(await request.body()) > 8192:
            return error('invalid_client_metadata')
        data = await request.json()
        uris = data.get('redirect_uris', [])
        if not isinstance(uris, list) or not 1 <= len(uris) <= 5 or not all(isinstance(u, str) and redirect_allowed(u) for u in uris):
            return error('invalid_redirect_uri')
        if data.get('token_endpoint_auth_method', 'none') != 'none':
            return error('invalid_client_metadata')
        name = str(data.get('client_name', 'ChatGPT'))[:100]
        client = signed('client', {'redirect_uris': uris, 'client_name': name, 'jti': secrets.token_urlsafe(16)}, 86400 * 365)
        return secure(JSONResponse({'client_id': client, 'client_name': name, 'redirect_uris': uris,
                                    'token_endpoint_auth_method': 'none',
                                    'grant_types': ['authorization_code', 'refresh_token'],
                                    'response_types': ['code'], 'scope': SCOPE}, status_code=201))
    except (ValueError, TypeError, jwt.PyJWTError):
        return error('invalid_client_metadata')


async def authorize(request):
    if not configured():
        return error('Google OAuth is not configured by the server owner', 503)
    try:
        q = request.query_params
        client = unpack(q.get('client_id', ''), 'client')
        redirect = q.get('redirect_uri', '')
        if redirect not in client['redirect_uris'] or not redirect_allowed(redirect):
            return error('invalid_redirect_uri')
        granted_scope = normalized_scope(q.get('scope', SCOPE))
        if q.get('response_type') != 'code':
            return error('unsupported_response_type_or_scope')
        if q.get('resource', origin() + '/mcp') != origin() + '/mcp':
            return error('invalid_target')
        if q.get('code_challenge_method') != 'S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', q.get('code_challenge', '')):
            return error('S256 PKCE required')
        cleanup(flows)
        state, binding, verifier, nonce = [secrets.token_urlsafe(32) for _ in range(4)]
        flows[state] = {'expires': time.time() + 600, 'binding': binding, 'verifier': verifier, 'nonce': nonce,
                        'client_id': q['client_id'], 'client_name': client['client_name'], 'redirect': redirect,
                        'state': q.get('state', ''), 'scope': granted_scope,
                        'challenge': q['code_challenge'], 'csrf': secrets.token_urlsafe(32)}
        params = {'client_id': os.environ['GOOGLE_CLIENT_ID'], 'redirect_uri': origin() + '/oauth/google/callback',
                  'response_type': 'code', 'scope': 'openid email', 'state': state, 'nonce': nonce,
                  'code_challenge': challenge(verifier), 'code_challenge_method': 'S256', 'prompt': 'select_account'}
        response = secure(RedirectResponse('https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)))
        response.set_cookie(COOKIE, binding, max_age=600, secure=True, httponly=True, samesite='lax', path='/')
        return response
    except (ValueError, TypeError, KeyError, jwt.PyJWTError):
        return error('invalid_request')


def bound_flow(request, state):
    flow = flows.get(state)
    if not flow or flow['expires'] < time.time() or not hmac.compare_digest(request.cookies.get(COOKIE, ''), flow['binding']):
        raise ValueError('Expired or invalid authorization; restart connection')
    return flow


async def google_callback(request):
    state = request.query_params.get('state', '')
    try:
        flow = bound_flow(request, state)
        # Consume upstream callback before exchanging the code; never replay it.
        if flow.get('callback_used'):
            return error('invalid_request')
        flow['callback_used'] = True
        code = request.query_params.get('code', '')
        if not code or request.query_params.get('error'):
            return error('Google sign-in cancelled')
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post('https://oauth2.googleapis.com/token', data={
                'grant_type': 'authorization_code', 'code': code, 'client_id': os.environ['GOOGLE_CLIENT_ID'],
                'client_secret': os.environ['GOOGLE_CLIENT_SECRET'], 'code_verifier': flow['verifier'],
                'redirect_uri': origin() + '/oauth/google/callback'})
            response.raise_for_status()
            id_token = response.json()['id_token']
        def verify():
            key = JWKS.get_signing_key_from_jwt(id_token).key
            return jwt.decode(id_token, key, algorithms=['RS256'], audience=os.environ['GOOGLE_CLIENT_ID'],
                              issuer=['https://accounts.google.com', 'accounts.google.com'],
                              options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'nonce']})
        claims = await anyio.to_thread.run_sync(verify)
        flow['sub'] = check_owner(claims, flow['nonce'])
        flow['email'] = claims['email'].lower()
        # Consent is explicit for every requesting client, even after Google login.
        esc = html.escape
        permission = 'Поиск, чтение, перемещение писем Mail.ru и удаление в корзину. Отправка и безвозвратное удаление недоступны.'
        page = f'''<!doctype html><meta charset="utf-8"><title>Mail.ru MCP — разрешение</title>
<h1>Разрешить доступ к почте?</h1><p>Аккаунт: {esc(flow['email'])}</p>
<p>Клиент: {esc(flow['client_name'])}</p><p>Адрес возврата: {esc(flow['redirect'])}</p>
<p>Доступ: {permission}</p>
<form method="post" action="/oauth/consent"><input type="hidden" name="state" value="{esc(state)}">
<input type="hidden" name="csrf" value="{esc(flow['csrf'])}">
<button name="decision" value="allow">Разрешить</button><button name="decision" value="deny">Отмена</button></form>'''
        return secure(HTMLResponse(page))
    except Exception:
        flows.pop(state, None)
        return error('Google identity verification failed or account is not allowed', 403)


async def consent(request):
    try:
        if request.headers.get('origin') != origin():
            return error('invalid_origin', 403)
        form = await request.form()
        state = str(form.get('state', ''))
        flow = bound_flow(request, state)
        if not flow.get('sub') or not hmac.compare_digest(str(form.get('csrf', '')), flow['csrf']):
            return error('invalid_consent', 403)
        params = {'state': flow['state'], 'iss': origin()}
        if form.get('decision') == 'allow':
            cleanup(codes)
            code = secrets.token_urlsafe(40)
            codes[code] = {**flow, 'expires': time.time() + 120}
            params['code'] = code
        else:
            params['error'] = 'access_denied'
        flows.pop(state, None)
        response = secure(RedirectResponse(flow['redirect'] + '?' + urlencode(params), status_code=303))
        response.delete_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='lax')
        return response
    except (ValueError, TypeError, KeyError):
        return error('invalid_consent', 403)


async def token(request):
    try:
        if len(await request.body()) > 16384:
            return error('invalid_request')
        form = await request.form()
        client_id = str(form.get('client_id', ''))
        unpack(client_id, 'client')
        if form.get('resource', origin() + '/mcp') != origin() + '/mcp':
            return error('invalid_target')
        if form.get('grant_type') == 'authorization_code':
            cleanup(codes)
            entry = codes.pop(str(form.get('code', '')), None)
            verifier = str(form.get('code_verifier', ''))
            if (not entry or entry['client_id'] != client_id or entry['redirect'] != form.get('redirect_uri')
                or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier)
                or not hmac.compare_digest(challenge(verifier), entry['challenge'])):
                return error('invalid_grant')
        elif form.get('grant_type') == 'refresh_token':
            entry = unpack(str(form.get('refresh_token', '')), 'refresh')
            if entry.get('client_id') != client_id:
                return error('invalid_grant')
        else:
            return error('unsupported_grant_type')
        if (entry['email'] != os.environ.get('ALLOWED_GOOGLE_EMAIL', '').strip().lower()
            or (os.getenv('ALLOWED_GOOGLE_SUB') and entry['sub'] != os.environ['ALLOWED_GOOGLE_SUB'])):
            return error('invalid_grant')
        granted_scope = normalized_scope(entry.get('scope', SCOPE))
        if form.get('scope'):
            requested = normalized_scope(str(form['scope']))
            if not set(requested.split()) <= set(granted_scope.split()):
                return error('invalid_scope')
            granted_scope = requested
        identity = {'sub': entry['sub'], 'email': entry['email'], 'client_id': client_id, 'scope': granted_scope}
        return secure(JSONResponse({'access_token': signed(origin() + '/mcp', identity, 3600), 'token_type': 'Bearer',
                                    'expires_in': 3600, 'scope': granted_scope,
                                    'refresh_token': signed('refresh', identity, 86400 * 7)}))
    except (ValueError, TypeError, KeyError, jwt.PyJWTError):
        return error('invalid_grant')


HANDLERS = {
    ('GET', '/.well-known/oauth-protected-resource'): metadata,
    ('GET', '/.well-known/oauth-protected-resource/mcp'): metadata,
    ('GET', '/.well-known/oauth-authorization-server'): metadata,
    ('POST', '/oauth/register'): register,
    ('GET', '/oauth/authorize'): authorize,
    ('GET', '/oauth/google/callback'): google_callback,
    ('POST', '/oauth/consent'): consent,
    ('POST', '/oauth/token'): token,
}


async def dispatch(scope, receive, send):
    handler = HANDLERS.get((scope['method'], scope['path']))
    if handler:
        response = await handler(Request(scope, receive))
        await response(scope, receive, send)
        return True
    return False

