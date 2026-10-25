# Run: python3 -m pytest plugin/test
import imaplib
import pathlib
import socket
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import transform  # noqa: E402

HEADER = (b'From: =?utf-8?q?J=C3=BCrgen?= <jurgen@example.com>\r\n'
          b'Subject: =?utf-8?q?Caf=C3=A9_tonight?=\r\nDate: Sat, 25 Oct 2026 09:00:00 +0000\r\n\r\n')
OLDER = b'From: bob@example.com\r\nSubject: Older\r\nDate: Fri, 24 Oct 2026 09:00:00 +0000\r\n\r\n'
GMAIL = {'provider': 'gmail', 'email': 'me@gmail.com', 'gmail_password': 'right'}
PREVIOUS = {'data': {'messages': [{'subject': 'old'}]}}


class FakeImap:
    instances = []
    password = 'right'

    def __init__(self, host, port, ssl_context=None, timeout=None):
        self.host, self.port, self.commands = host, port, []
        FakeImap.instances.append(self)

    def login(self, user, password):
        if password != FakeImap.password:
            raise imaplib.IMAP4.error('AUTHENTICATIONFAILED')

    def select(self, folder, readonly=False):
        self.commands.append(('select', folder, readonly))
        return 'OK', [b'2']

    def search(self, charset, criteria):
        return 'OK', [b'1 2']

    def fetch(self, ids, what):
        return 'OK', [(b'1 (FLAGS (\\Seen) BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', OLDER), b')',
                      (b'2 (FLAGS (\\Flagged) BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {90}', HEADER), b')']

    def logout(self):
        pass


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    FakeImap.instances.clear()
    FakeImap.password = 'right'
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', FakeImap)


def run(values, previous=None):
    return transform.run({'trmnl': {'plugin_settings': {'custom_fields_values': values},
                                    'previous_merge_variables': previous or {}}})


def refuse_with(monkeypatch, error):
    def refuse(*a, **k):
        raise error
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', refuse)


def test_reads_latest_mail_newest_first_with_decoded_headers():
    data = run(GMAIL)['data']
    assert data['success'] is True and data['count'] == 2
    first = data['messages'][0]
    assert first['subject'] == 'Café tonight' and first['sender'] == 'Jürgen'
    assert first['sender_email'] == 'jurgen@example.com' and first['flagged'] and not first['read']
    assert FakeImap.instances[0].host == 'imap.gmail.com'
    assert ('select', '"INBOX"', True) in FakeImap.instances[0].commands


def test_wrong_password_is_shown_not_hidden():
    FakeImap.password = 'other'
    assert run(GMAIL, PREVIOUS)['data']['code'] == 'AUTH_FAILED'


def test_connection_failure_keeps_previous_mail(monkeypatch):
    refuse_with(monkeypatch, OSError('network unreachable'))
    assert run(GMAIL, PREVIOUS) == PREVIOUS


def test_timeout_without_previous_explains(monkeypatch):
    refuse_with(monkeypatch, socket.timeout())
    assert run(GMAIL)['data']['code'] == 'TIMEOUT'


def test_filters_build_the_search():
    s = transform._settings({**GMAIL, 'provider': 'custom', 'custom_server': 'mail.example.com',
                             'custom_password': 'x', 'unread_only': 'yes',
                             'from_emails': 'a@x.com, b@x.com,c@x.com'})
    assert transform.search_criteria(s) == 'UNSEEN OR OR FROM "a@x.com" FROM "b@x.com" FROM "c@x.com"'
    g = transform._settings({**GMAIL, 'gmail_category': 'Primary', 'unread_only': 'yes'})
    assert transform.search_criteria(g) == 'X-GM-RAW "category:primary is:unread"'


@pytest.mark.parametrize('field', ['folder', 'gmail_category', 'from_emails'])
def test_imap_command_injection_refused(field):
    assert run({**GMAIL, field: 'INBOX"\r\nA1 DELETE "x'})['data']['code'] == 'INVALID'


def test_missing_settings_explained():
    assert run({'provider': 'gmail'})['data']['code'] == 'INVALID'


def test_limit_is_clamped():
    assert transform._settings({**GMAIL, 'limit': '500'})['limit'] == transform.MAX_MESSAGES
    assert transform._settings({**GMAIL, 'limit': '-3'})['limit'] == 1
