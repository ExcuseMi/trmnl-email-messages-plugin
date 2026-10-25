import logging
import socket

import pytest

import app as backend
from modules.providers.imap_provider import IMAPAuthenticationError
from modules.utils.cache import CacheManager

MESSAGES = [{'subject': 'private', 'from': 'a@example.com'}]


class MemoryCache(CacheManager):
    def __init__(self):
        super().__init__('unused', 0, 0, ttl_seconds=300, enabled=False)
        self.store = {}

    def get(self, cache_key):
        return dict(self.store[cache_key]) if cache_key in self.store else None

    def set(self, cache_key, data):
        self.store[cache_key] = dict(data)
        return True


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(backend, 'cache_manager', MemoryCache())
    monkeypatch.setattr(backend, 'login_limiter', backend.LoginLimiter())
    monkeypatch.setattr(backend, 'ENABLE_IP_WHITELIST', False)
    public = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('142.250.27.108', 993))]
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: public)
    return backend.app.test_client()


def body(password='right', server='imap.gmail.com'):
    return {'server': server, 'port': 993, 'username': 'victim@gmail.com', 'password': password}


def test_wrong_password_never_gets_cached_mail(client, monkeypatch):
    async def fetch(**kw):
        if kw['password'] != 'right':
            raise IMAPAuthenticationError('bad')
        return MESSAGES
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)

    assert client.post('/messages', json=body()).get_json()['messages'] == MESSAGES
    stolen = client.post('/messages', json=body(password='guess')).get_json()
    assert 'messages' not in stolen
    assert stolen['success'] is False


def test_same_password_still_uses_cache(client, monkeypatch):
    calls = []

    async def fetch(**kw):
        calls.append(1)
        return MESSAGES
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    client.post('/messages', json=body())
    client.post('/messages', json=body())
    assert len(calls) == 1


def test_async_route_and_get_are_gone(client):
    assert client.post('/async/messages', json=body()).status_code == 404
    assert client.get('/messages', query_string=body()).status_code == 405


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.9', '192.168.1.1', '169.254.169.254', '::1'])
def test_internal_mail_server_refused(client, monkeypatch, address):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(family, socket.SOCK_STREAM, 6, '', (address, 993))])

    async def fetch(**kw):
        raise AssertionError('must not connect')
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    result = client.post('/messages', json=body(server='internal.example')).get_json()
    assert result['code'] == 'INVALID_SERVER'


def test_forwarded_header_does_not_pass_whitelist(client, monkeypatch):
    monkeypatch.setattr(backend, 'ENABLE_IP_WHITELIST', True)
    monkeypatch.setattr(backend, 'TRMNL_IPS', {'203.0.113.7'})
    for header in ('X-Forwarded-For', 'X-Real-IP'):
        resp = client.post('/messages', json=body(), headers={header: '203.0.113.7'})
        assert resp.status_code == 403


def test_imap_debug_log_stays_off_at_debug_level():
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG
    assert logging.getLogger('aioimaplib').getEffectiveLevel() >= logging.WARNING


def test_tls_checks_the_hostname():
    import inspect
    from modules.providers import imap_provider
    assert 'check_hostname = False' not in inspect.getsource(imap_provider)
