import pathlib

import pytest

import app as backend
from modules.providers.imap_provider import IMAPProtocolError
from test_security import client, body  # noqa: F401  (fixture and helper)

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_unexpected_errors_never_echo_details(client, monkeypatch):  # noqa: F811
    async def fetch(**kw):
        raise RuntimeError('secret internal detail /app/x.py')
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    assert 'secret' not in client.post('/messages', json=body()).get_data(as_text=True)


def test_protocol_errors_never_echo_details(client, monkeypatch):  # noqa: F811
    async def fetch(**kw):
        raise IMAPProtocolError('IMAP protocol state error: secret')
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    assert 'secret' not in client.post('/messages', json=body()).get_data(as_text=True)


@pytest.mark.parametrize('field', ['folder', 'gmail_category', 'from_emails'])
def test_imap_command_injection_refused(client, field):  # noqa: F811
    assert client.post('/messages', json={**body(), field: 'INBOX"\r\nA1 DELETE "x'}).status_code == 400


def test_huge_body_refused(client):  # noqa: F811
    assert client.post('/messages', json={**body(), 'pad': 'x' * 200_000}).status_code == 413


def test_health_tells_nothing_about_the_caller(client):  # noqa: F811
    health = client.get('/health', headers={'CF-Connecting-IP': '203.0.113.7'}).get_json()
    text = str(health)
    assert '203.0.113.7' not in text and 'whitelisted' not in text


def test_container_runs_unprivileged():
    assert 'USER nobody' in (ROOT / 'backend' / 'Dockerfile').read_text()
    compose = (ROOT / 'docker-compose.yml').read_text()
    assert 'read_only: true' in compose and 'no-new-privileges:true' in compose


def test_every_dependency_is_pinned():
    lines = [line for line in (ROOT / 'backend' / 'requirements.txt').read_text().splitlines()
             if line and not line.startswith('#')]
    assert all('==' in line for line in lines)
    assert any(line.lower().startswith('h11==') for line in lines)


def test_oauth_is_not_accepted(client, monkeypatch):  # noqa: F811
    async def fetch(**kw):
        raise AssertionError('must not connect')
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    no_password = {k: v for k, v in body().items() if k != 'password'}
    resp = client.post('/messages', json={**no_password, 'oauth_access_token': 'token'})
    assert resp.status_code == 400
