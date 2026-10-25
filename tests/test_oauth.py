# SPDX-License-Identifier: Apache-2.0
import time
import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient
import oauth

CALLBACK='https://chatgpt.com/connector_platform_oauth_redirect'

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('MCP_ACCESS_TOKEN','test-key-'*8)
    monkeypatch.setenv('PUBLIC_BASE_URL','https://mailru-test.example')
    monkeypatch.setenv('GOOGLE_CLIENT_ID','test-google-client')
    monkeypatch.setenv('GOOGLE_CLIENT_SECRET','test-google-secret')
    monkeypatch.setenv('ALLOWED_GOOGLE_EMAIL','owner@example.com')
    monkeypatch.delenv('ALLOWED_GOOGLE_SUB',raising=False)
    oauth.codes.clear(); oauth.flows.clear()
    app=Starlette(routes=[Route(path,fn,methods=[method]) for (method,path),fn in oauth.HANDLERS.items()])
    with TestClient(app,base_url=oauth.origin()) as c: yield c


def register(c):
    r=c.post('/oauth/register',json={'redirect_uris':[CALLBACK],'client_name':'ChatGPT','token_endpoint_auth_method':'none'})
    assert r.status_code==201
    return r.json()['client_id']


def test_metadata(client):
    r=client.get('/.well-known/oauth-protected-resource')
    assert r.json()['resource']==oauth.origin()+'/mcp'
    assert client.get('/.well-known/oauth-authorization-server').json()['code_challenge_methods_supported']==['S256']

@pytest.mark.parametrize('uri',['https://evil.example/callback','https://chatgpt.com.evil.example/connector_platform_oauth_redirect','http://chatgpt.com/connector_platform_oauth_redirect','https://chatgpt.com/connector_platform_oauth_redirect?next=https://evil.example'])
def test_redirect_rejected(client,uri):
    assert client.post('/oauth/register',json={'redirect_uris':[uri]}).status_code==400


def test_google_pkce_and_browser_binding(client):
    cid=register(client)
    r=client.get('/oauth/authorize',params={'client_id':cid,'redirect_uri':CALLBACK,'response_type':'code','code_challenge':oauth.challenge('v'*43),'code_challenge_method':'S256','state':'outer'},follow_redirects=False)
    assert r.status_code==307
    assert r.headers['location'].startswith('https://accounts.google.com/o/oauth2/v2/auth?')
    assert 'code_challenge_method=S256' in r.headers['location']
    assert 'Secure' in r.headers['set-cookie'] and 'HttpOnly' in r.headers['set-cookie']
    flow=next(iter(oauth.flows.values()))
    assert flow['state']=='outer' and 'sub' not in flow


def test_pkce_required(client):
    assert client.get('/oauth/authorize',params={'client_id':register(client),'redirect_uri':CALLBACK,'response_type':'code'}).status_code==400


def test_owner_verified_email_required(client):
    claims={'sub':'123','email':'owner@example.com','email_verified':True,'nonce':'n'}
    assert oauth.check_owner(claims,'n')=='123'
    for change in [{'email':'attacker@example.com'},{'email_verified':False},{'nonce':'wrong'}]:
        with pytest.raises(ValueError): oauth.check_owner({**claims,**change},'n')


def test_token_pkce_replay_audience(client):
    cid=register(client); verifier='v'*43
    oauth.codes['once']={'expires':time.time()+120,'client_id':cid,'redirect':CALLBACK,'challenge':oauth.challenge(verifier),'sub':'123','email':'owner@example.com'}
    data={'grant_type':'authorization_code','code':'once','client_id':cid,'redirect_uri':CALLBACK,'code_verifier':verifier,'resource':oauth.origin()+'/mcp'}
    r=client.post('/oauth/token',data=data)
    assert r.status_code==200
    access=r.json()['access_token']; refresh=r.json()['refresh_token']
    assert oauth.access_valid(access)
    assert not oauth.access_valid(refresh)
    assert not oauth.access_valid(access+'x')
    assert client.post('/oauth/token',data=data).status_code==400
    assert client.post('/oauth/token',data={'grant_type':'refresh_token','refresh_token':refresh,'client_id':cid}).status_code==200
    assert client.post('/oauth/token',data={'grant_type':'refresh_token','refresh_token':refresh,'client_id':register(client)}).status_code==400


def test_wrong_pkce_fails(client):
    cid=register(client)
    oauth.codes['once']={'expires':time.time()+120,'client_id':cid,'redirect':CALLBACK,'challenge':oauth.challenge('v'*43),'sub':'123','email':'owner@example.com'}
    assert client.post('/oauth/token',data={'grant_type':'authorization_code','code':'once','client_id':cid,'redirect_uri':CALLBACK,'code_verifier':'a'*43}).status_code==400


def test_consent_requires_cookie_csrf_and_identity(client):
    oauth.flows['s']={'expires':time.time()+100,'binding':'b','csrf':'csrf','sub':'123','email':'owner@example.com','redirect':CALLBACK,'state':'outer','client_id':register(client),'challenge':oauth.challenge('v'*43)}
    assert client.post('/oauth/consent',data={'state':'s','csrf':'csrf','decision':'allow'},headers={'origin':oauth.origin()}).status_code==403
    client.cookies.set(oauth.COOKIE,'b')
    assert client.post('/oauth/consent',data={'state':'s','csrf':'wrong','decision':'allow'},headers={'origin':oauth.origin()}).status_code==403
    r=client.post('/oauth/consent',data={'state':'s','csrf':'csrf','decision':'allow'},headers={'origin':oauth.origin()},follow_redirects=False)
    assert r.status_code==303 and 'code=' in r.headers['location']
    assert len(oauth.codes)==1
    assert client.post('/oauth/consent',data={'state':'s','csrf':'csrf','decision':'allow'},headers={'origin':oauth.origin()}).status_code==403


def test_missing_config_fails_closed(client,monkeypatch):
    monkeypatch.delenv('GOOGLE_CLIENT_SECRET')
    assert client.get('/oauth/authorize').status_code==503


def test_consent_preserves_same_origin_post_origin():
    from starlette.responses import HTMLResponse
    response = oauth.secure(HTMLResponse('consent'))
    assert response.headers['referrer-policy'] == 'same-origin'


def test_form_policy_allows_validated_chatgpt_callback():
    from starlette.responses import HTMLResponse
    policy = oauth.secure(HTMLResponse('consent')).headers['content-security-policy']
    assert "form-action 'self' https://chatgpt.com/connector_platform_oauth_redirect" in policy
    assert 'https://evil.example' not in policy



def test_access_scope_declared_on_registration_and_refresh(client):
    cid=register(client)
    assert client.get('/.well-known/oauth-authorization-server').json()['scopes_supported']==['mail.access']
    r=client.get('/oauth/authorize',params={'client_id':cid,'redirect_uri':CALLBACK,'response_type':'code','code_challenge':oauth.challenge('v'*43),'code_challenge_method':'S256'},follow_redirects=False)
    assert r.status_code==307
    assert next(iter(oauth.flows.values()))['scope']=='mail.access'
    oauth.codes['once']={'expires':time.time()+120,'client_id':cid,'redirect':CALLBACK,'challenge':oauth.challenge('v'*43),'sub':'123','email':'owner@example.com','scope':'mail.access'}
    tokens=client.post('/oauth/token',data={'grant_type':'authorization_code','code':'once','client_id':cid,'redirect_uri':CALLBACK,'code_verifier':'v'*43}).json()
    assert tokens['scope']=='mail.access'
    refreshed=client.post('/oauth/token',data={'grant_type':'refresh_token','refresh_token':tokens['refresh_token'],'client_id':cid})
    assert refreshed.json()['scope']=='mail.access'
    assert oauth.access_scopes(tokens['access_token'])==frozenset(['mail.access'])


@pytest.mark.parametrize('scope',['mail.read','mail.modify','mail.access mail.send',''])
def test_bad_scopes_rejected(client,scope):
    assert client.get('/oauth/authorize',params={'client_id':register(client),'redirect_uri':CALLBACK,'response_type':'code','scope':scope}).status_code==400


@pytest.mark.parametrize('value',['https://example.com/path','https://user:pass@example.com','http://remote.example','https://example.com?token=x'])
def test_public_origin_rejects_ambiguous_values(monkeypatch,value):
    monkeypatch.setenv('PUBLIC_BASE_URL',value)
    with pytest.raises(ValueError): oauth.origin()


def test_public_origin_from_render_or_local(monkeypatch):
    monkeypatch.delenv('PUBLIC_BASE_URL',raising=False)
    monkeypatch.setenv('RENDER_EXTERNAL_HOSTNAME','starter-test.onrender.com')
    assert oauth.origin()=='https://starter-test.onrender.com'
    monkeypatch.delenv('RENDER_EXTERNAL_HOSTNAME')
    assert oauth.origin()=='http://localhost:8000'
