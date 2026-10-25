# SPDX-License-Identifier: Apache-2.0
from contextlib import contextmanager
from unittest.mock import patch
import pytest
from starlette.testclient import TestClient
import mailbox_client as mail
from server import app

class Fake:
    def __init__(self): self.calls=[]
    def select(self, folder, readonly=False):
        self.calls.append(('select', folder, readonly)); return 'OK',[b'1']
    def response(self, name): return name,[b'88']
    def uid(self, command, *args):
        self.calls.append((command,*args))
        if command == 'SEARCH': return 'OK',[b'1 2']
        return 'OK',[(b'2 FETCH',b'From: sender@example.com\r\nSubject: Test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello')]

@contextmanager
def fake_connection(client): yield client

def test_search_readonly_and_peek():
    c=Fake()
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        result=mail.search(unread_only=True,subject='hello "world"',limit=1)
    assert result['messages'][0]['uid']=='2'
    assert result['uidvalidity']=='88'
    assert c.calls[0]==('select','"INBOX"',True)
    assert 'UNSEEN' in c.calls[1][-1].decode()
    assert 'BODY.PEEK' in c.calls[2][-1]

def test_read_preserves_unread():
    c=Fake()
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        result=mail.read('2','88')
    assert result['body']=='Hello'
    assert c.calls[0][-1] is True
    assert 'BODY.PEEK[]' in c.calls[1][-1]

def test_stale_uid_fails_before_fetch():
    c=Fake()
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        with pytest.raises(ValueError,match='Folder changed'): mail.read('2','77')
    assert len(c.calls)==1

@pytest.mark.parametrize('value',['INBOX\r\nEXPUNGE','x\x00','a'*301])
def test_imap_injection_rejected(value):
    with pytest.raises(ValueError): mail.quoted(value)

def test_auth_and_discovery(monkeypatch):
    monkeypatch.setenv('MCP_ACCESS_TOKEN','a'*40)
    with TestClient(app,base_url='http://localhost') as client:
        assert client.get('/healthz').status_code==200
        assert client.post('/mcp',json={}).status_code==401
        headers={'Authorization':'Bearer '+'a'*40,'Accept':'application/json, text/event-stream'}
        r=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
        assert r.status_code==200, r.text
        tools = {t['name']:t for t in r.json()['result']['tools']}
        assert set(tools)=={'mail_list_folders','mail_search','mail_read','mail_move','mail_delete'}
        assert tools['mail_delete']['annotations']['readOnlyHint'] is False
        assert tools['mail_move']['annotations']['destructiveHint'] is True

def test_auth_fails_closed(monkeypatch):
    monkeypatch.delenv('MCP_ACCESS_TOKEN',raising=False)
    client = TestClient(app)
    assert client.post('/mcp',headers={'Authorization':'Bearer '}).status_code==401


class MovingFake(Fake):
    capabilities = (b'IMAP4rev1', b'MOVE', b'UIDPLUS')
    def __init__(self):
        super().__init__(); self.moved = False; self.fail = False
    def list(self):
        return 'OK', [b'() "/" "INBOX"', b'() "/" "Archive"', b'(\\Trash) "/" "&BBoEPgRABDcEOAQ9BDA-"']
    def uid(self, command, *args):
        self.calls.append((command, *args))
        if command == 'SEARCH': return 'OK', [b'' if self.moved else b'2']
        if command == 'MOVE':
            if self.fail: raise OSError('lost connection')
            self.moved = True
            return 'OK', [b'Moved']
        raise AssertionError(command)
    def response(self, name):
        return name, [b'99 2 7' if name == 'COPYUID' else b'88']


def test_move_single_uid_and_receipt():
    c=MovingFake()
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        result=mail.move('2','88',destination='Archive')
    assert result['status']=='moved' and result['source_absent']
    assert result['destination_message']=={'uidvalidity':'99','uid':'7'}
    assert ('select','"INBOX"',False) in c.calls
    assert ('MOVE','2','"Archive"') in c.calls
    assert not any(call[0] in {'EXPUNGE','STORE','COPY','CLOSE'} for call in c.calls)


def test_delete_uses_special_use_trash():
    c=MovingFake()
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        result=mail.move('2','88',to_trash=True)
    assert result['destination']=='&BBoEPgRABDcEOAQ9BDA-'


@pytest.mark.parametrize('uid',['1:9','1,2','0','4294967296','2\r\nEXPUNGE'])
def test_move_rejects_non_single_uid(uid):
    with patch.object(mail,'connection',side_effect=AssertionError('must not connect')):
        with pytest.raises(ValueError): mail.move(uid,'88',destination='Archive')


@pytest.mark.parametrize('case',['stale','missing','unsupported','same','bad_destination','no_trash'])
def test_move_rejects_before_mutation(case):
    c=MovingFake(); kwargs={'uid':'2','uidvalidity':'88','destination':'Archive'}
    if case=='stale': kwargs['uidvalidity']='77'
    if case=='missing': c.moved=True
    if case=='unsupported': c.capabilities=(b'IMAP4rev1',)
    if case=='same': kwargs['destination']='INBOX'
    if case=='bad_destination': kwargs['destination']='Archive\r\nEXPUNGE'
    if case=='no_trash':
        kwargs['to_trash']=True
        c.list=lambda:('OK',[b'() "/" "INBOX"'])
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        with pytest.raises(ValueError): mail.move(**kwargs)
    assert not any(call[0]=='MOVE' for call in c.calls)


def test_move_disconnect_does_not_retry():
    c=MovingFake(); c.fail=True
    with patch.object(mail,'connection',lambda:fake_connection(c)):
        result=mail.move('2','88',destination='Archive')
    assert result['status']=='unknown'
    assert sum(call[0]=='MOVE' for call in c.calls)==1


def test_wrong_scope_cannot_move_and_access_token_can(monkeypatch):
    import importlib
    import server
    import oauth
    fresh_app = importlib.reload(server).app
    monkeypatch.setenv('MCP_ACCESS_TOKEN','a'*40)
    monkeypatch.setenv('ALLOWED_GOOGLE_EMAIL','owner@example.com')
    monkeypatch.delenv('ALLOWED_GOOGLE_SUB',raising=False)
    c=MovingFake()
    with TestClient(fresh_app,base_url='http://localhost') as client, patch.object(mail,'connection',lambda:fake_connection(c)):
        for scope in ['mail.read','mail.access','mail.read']:
            token=oauth.signed(oauth.origin()+'/mcp',{'sub':'owner','email':'owner@example.com','scope':scope},3600)
            headers={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream'}
            r=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'mail_move','arguments':{'uid':'2','uidvalidity':'88','destination':'Archive'}}})
            result=r.json().get('result', {})
            if scope=='mail.read':
                assert r.status_code == 401
                assert not c.moved or sum(call[0]=='MOVE' for call in c.calls)==1
            else:
                assert result.get('isError') is not True
                assert c.moved
    assert sum(call[0]=='MOVE' for call in c.calls)==1

