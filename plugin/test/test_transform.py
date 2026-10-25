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


class FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class FakeImap:
    instances = []
    password = 'right'

    def __init__(self, host, port, ssl_context=None, timeout=None):
        self.host, self.port, self.commands = host, port, []
        self.connect_timeout = timeout
        self.sock = FakeSocket()
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
    data = run(GMAIL, PREVIOUS)['data']
    assert data['messages'] == PREVIOUS['data']['messages']
    assert data['stale_reason'] == 'CONNECTION' and 'total_ms' in data['timing']


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


def test_timing_is_in_the_payload():
    timing = run(GMAIL)['data']['timing']
    assert list(timing['steps_ms']) == ['connect', 'login', 'select', 'search', 'fetch']
    assert timing['total_ms'] <= timing['limit_ms'] == 4000


def test_errors_carry_timing_too():
    FakeImap.password = 'other'
    data = run(GMAIL)['data']
    assert data['code'] == 'AUTH_FAILED' and 'connect' in data['timing']['steps_ms']


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_slow_step_stops_the_run_before_the_limit(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(transform.time, 'monotonic', clock)

    def slow_login(self, user, password):
        clock.now += 4.5  # longer than the whole budget
    monkeypatch.setattr(FakeImap, 'login', slow_login)
    data = run(GMAIL)['data']
    assert data['code'] == 'TIMEOUT'
    assert ('select', '"INBOX"', True) not in FakeImap.instances[0].commands


def test_each_step_may_only_wait_for_the_time_left(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(transform.time, 'monotonic', clock)

    def login(self, user, password):
        clock.now += 1.5
    monkeypatch.setattr(FakeImap, 'login', login)
    run(GMAIL)
    imap = FakeImap.instances[0]
    assert imap.connect_timeout == 4.0
    timeouts = imap.sock.timeouts[:-1]  # the last one is the short logout timeout
    assert timeouts[0] == 4.0 and all(t == 2.5 for t in timeouts[1:])


def test_list_is_the_default_display():
    data = run(GMAIL)['data']
    assert data['display'] == 'list' and 'messages' in data and 'message' not in data


INVITE = (b'From: calendar-notification@google.com\r\nSubject: Invitation: Vaccination @ Tue Oct 20\r\n'
          b'Date: Sat, 25 Oct 2026 10:00:00 +0000\r\n\r\n')
INVITE_LINE = (b'3 (FLAGS () BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7bit" 10 1)("text" "calendar" '
               b'("method" "REQUEST") NIL NIL "7bit" 300 5) "alternative") BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {99}')


def with_invitation(monkeypatch):
    original = FakeImap.fetch

    def fetch(self, ids, what):
        status, data = original(self, ids, what)
        self.commands.append(('fetch', ids, what))
        return status, data + [(INVITE_LINE, INVITE), b')']
    monkeypatch.setattr(FakeImap, 'fetch', fetch)


def test_invitations_shown_by_default(monkeypatch):
    with_invitation(monkeypatch)
    subjects = [m['subject'] for m in run(GMAIL)['data']['messages']]
    assert 'Invitation: Vaccination @ Tue Oct 20' in subjects


def test_invitations_hidden_when_asked(monkeypatch):
    with_invitation(monkeypatch)
    data = run({**GMAIL, 'hide_invitations': 'yes', 'limit': '2'})['data']
    assert [m['subject'] for m in data['messages']] == ['Café tonight', 'Older']
    fetch = [c for c in FakeImap.instances[0].commands if c[0] == 'fetch'][0]
    assert 'BODYSTRUCTURE' in fetch[2]
