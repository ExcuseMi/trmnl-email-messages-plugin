import app as backend
from modules.providers.imap_provider import IMAPAuthenticationError
from modules.utils import login_limit, store
from test_security import client, body, MESSAGES  # noqa: F401  (fixture and helpers)


def counting_fetch(monkeypatch, good='right'):
    calls = []

    async def fetch(**kw):
        calls.append(kw['password'])
        if kw['password'] != good:
            raise IMAPAuthenticationError('bad')
        return MESSAGES
    monkeypatch.setattr(backend.imap_provider, 'fetch_messages', fetch)
    return calls


def test_guessing_stops_reaching_the_mail_server(client, monkeypatch):  # noqa: F811
    calls = counting_fetch(monkeypatch)
    for i in range(20):
        client.post('/messages', json=body(password=f'guess{i}'))
    assert len(calls) == login_limit.ACCOUNT_MAX_FAILURES
    last = client.post('/messages', json=body(password='guess99')).get_json()
    assert last['code'] == 'TOO_MANY_FAILURES'


def test_known_good_password_is_never_locked_out(client, monkeypatch):  # noqa: F811
    counting_fetch(monkeypatch)
    assert client.post('/messages', json=body()).get_json()['success'] is True
    for i in range(20):
        client.post('/messages', json=body(password=f'guess{i}'))
    backend.throttle.store.values.clear()  # past the 5-minute window
    assert client.post('/messages', json=body()).get_json()['success'] is True


def test_spraying_many_accounts_hits_the_global_limit(client, monkeypatch):  # noqa: F811
    calls = counting_fetch(monkeypatch)
    for i in range(login_limit.GLOBAL_MAX_FAILURES + 30):
        client.post('/messages', json={**body(password='x'), 'username': f'user{i}@gmail.com'})
    assert len(calls) == login_limit.GLOBAL_MAX_FAILURES


def test_limit_expires(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(store.time, 'time', lambda: now[0])
    limiter = login_limit.LoginLimiter()
    for _ in range(login_limit.ACCOUNT_MAX_FAILURES):
        limiter.failed('a')
    assert limiter.blocked('a', 'c')
    now[0] += login_limit.ACCOUNT_WINDOW_SECONDS + 1
    assert limiter.blocked('a', 'c') is None
