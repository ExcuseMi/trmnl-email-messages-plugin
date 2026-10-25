import asyncio
import pathlib
import re
import socket
import time

import pytest

import app as backend
from modules.providers import imap_provider
from modules.providers.imap_provider import IMAPConnectionError, IMAPProvider
from modules.utils import security
from test_security import client, body  # noqa: F401  (fixture and helper)

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_mail_fields_are_escaped_in_markup():
    unescaped = []
    for path in sorted((ROOT / 'plugin' / 'src').glob('*.liquid')):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            for out in re.findall(r'\{\{(.*?)\}\}', line):
                if re.search(r'\b(data|message)\.', out) and 'escape' not in out and '| date' not in out:
                    unescaped.append(f'{path.name}:{n}: {out.strip()}')
    assert unescaped == []


def test_redis_keeps_nothing_on_disk():
    compose = (ROOT / 'docker-compose.yml').read_text()
    assert '--save ""' in compose and '--appendonly no' in compose
    assert 'redis_data' not in compose


class FakeTransport:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, key):
        return self.peer if key == 'peername' else None


class FakeClient:
    def __init__(self, peer):
        self.protocol = type('P', (), {'transport': FakeTransport(peer)})()
        self.logged_in = False

    async def wait_hello_from_server(self):
        return None

    async def login(self, *a):
        self.logged_in = True
        raise AssertionError('must not log in')

    async def logout(self):
        return None

    async def close(self):
        return None


def test_rebound_name_to_internal_address_never_gets_credentials(monkeypatch):
    fake = FakeClient(('10.0.0.9', 993))
    monkeypatch.setattr(imap_provider.aioimaplib, 'IMAP4_SSL', lambda **kw: fake)
    with pytest.raises(IMAPConnectionError):
        asyncio.run(IMAPProvider().fetch_messages(server='rebind.example', port=993, username='u', password='p'))
    assert fake.logged_in is False


def test_slow_dns_times_out_without_blocking(monkeypatch):
    monkeypatch.setattr(security, 'DNS_TIMEOUT_SECONDS', 0.2)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: time.sleep(1) or [])

    async def run():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1
        t = asyncio.create_task(ticker())
        result = await security.check_mail_server('slow.example', 993)
        t.cancel()
        return result, ticks
    result, ticks = asyncio.run(run())
    assert result == 'Server not found'
    assert ticks >= 5  # the event loop kept running while DNS waited


def test_connection_errors_give_one_fixed_text(client, monkeypatch):  # noqa: F811
    async def fetch(**kw):
        raise IMAPConnectionError('Connection refused by 203.0.113.9:6379')
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    result = client.post('/messages', json=body()).get_json()
    assert '6379' not in result['message'] and 'refused' not in result['message']


def test_limit_is_clamped(client, monkeypatch):  # noqa: F811
    seen = []

    async def fetch(**kw):
        seen.append(kw['limit'])
        return []
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    client.post('/messages', json={**body(), 'limit': -1})
    client.post('/messages', json={**body(), 'limit': 10_000, 'password': 'other'})
    assert seen == [1, backend.MAX_MESSAGES_LIMIT]


@pytest.mark.parametrize('bad', [{'port': 'abc'}, {'limit': 'x'}, {'username': ['a']}, {'port': None, 'limit': True}])
def test_malformed_input_is_400_not_500(client, bad):  # noqa: F811
    assert client.post('/messages', json={**body(), **bad}).status_code == 400
