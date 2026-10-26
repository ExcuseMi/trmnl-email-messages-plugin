# Run: python3 -m pytest plugin/test
import imaplib
import pathlib
import socket
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import transform  # noqa: E402
from imap_answers import STATIC_DATA  # noqa: E402
from imap_answers import answer  # noqa: E402

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
    # Like TRMNL: the static data from settings.yml comes with every run
    return transform.run({**STATIC_DATA, 'trmnl': {'plugin_settings': {'custom_fields_values': values},
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
    assert timing['total_ms'] <= timing['limit_ms'] == 4300


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
        clock.now += transform.DEADLINE_SECONDS + 1  # longer than the whole budget
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
    assert imap.connect_timeout == 4.3
    timeouts = imap.sock.timeouts[:-1]  # the last one is the short logout timeout
    assert timeouts[0] == 4.3 and all(abs(t - 2.8) < 1e-9 for t in timeouts[1:])


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


def full_mail(sender, subject, date, text):
    return (f'From: {sender}\r\nSubject: {subject}\r\nDate: {date}\r\nContent-Type: text/plain\r\n\r\n{text}\r\n').encode()


FIRST = full_mail('jurgen@example.com', 'Cafe', 'Sat, 25 Oct 2026 09:00:00 +0000', 'See you at 8.\r\n\r\nJ.')
SECOND = full_mail('bob@example.com', 'Older', 'Fri, 24 Oct 2026 09:00:00 +0000', 'word ' * 400)


def preview_fetch(self, ids, what):
    self.commands.append(('fetch', ids, what))
    if 'HEADER.FIELDS (FROM SUBJECT DATE' in what and 'BODY.PEEK[TEXT]' not in what:
        return 'OK', [(b'1 (FLAGS (\\Seen) BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', SECOND), b')',
                      (b'2 (FLAGS (\\Flagged) BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', FIRST), b')']
    texts = {'1': SECOND, '2': FIRST}
    return 'OK', [part for i in ids.split(',') for part in answer(i, texts[i], '', what)]


def test_preview_fetches_text_only_for_the_shown_entries(monkeypatch):
    monkeypatch.setattr(FakeImap, 'fetch', preview_fetch)
    data = run({**GMAIL, 'display': 'preview'})['data']
    newest, older = data['messages']
    assert newest['subject'] == 'Cafe' and newest['paragraphs'] == ['See you at 8.', 'J.'] and newest['flagged']
    assert older['read'] and older['truncated'] and len(older['body']) <= transform.SNIPPET_CHARS + 1
    fetches = [c for c in FakeImap.instances[0].commands if c[0] == 'fetch']
    assert [f[1] for f in fetches[1:]] == ['2', '1']  # newest first, one message per fetch
    assert f'BODY.PEEK[TEXT]<0.{transform.SNIPPET_BYTES}>' in fetches[1][2]
    data = run({**GMAIL, 'display': 'preview', 'limit': '1'})['data']
    assert FakeImap.instances[1].commands[-1][1] == '2'  # 2026-10-25: one fetch of all candidates timed out


def test_preview_text_survives_large_headers(monkeypatch):
    # 2026-10-25: Gmail's Received/DKIM/ARC headers filled the whole partial fetch; only short mails had text
    big = ''.join(f'X-Received-{k}: {"x" * 60}\r\n' for k in range(400)).encode()  # 27 KB of headers
    monkeypatch.setattr(sys.modules[__name__], 'FIRST', big + FIRST)
    monkeypatch.setattr(FakeImap, 'fetch', preview_fetch)
    newest = run({**GMAIL, 'display': 'preview'})['data']['messages'][0]
    assert newest['subject'] == 'Cafe' and newest['paragraphs'] == ['See you at 8.', 'J.']


def test_preview_short_of_time_stops_between_texts(monkeypatch):
    # The clock is checked before each text: the newest gets its text, the rest show without
    clock = FakeClock()
    monkeypatch.setattr(transform.time, 'monotonic', clock)

    def slow_text(self, ids, what):
        if 'BODY.PEEK[TEXT]' in what:
            clock.now += transform.DEADLINE_SECONDS - 0.6  # leaves less than TEXT_MARGIN
        return preview_fetch(self, ids, what)
    monkeypatch.setattr(FakeImap, 'fetch', slow_text)
    data = run({**GMAIL, 'display': 'preview'})['data']
    newest, older = data['messages']
    assert data['success'] and newest['paragraphs'] == ['See you at 8.', 'J.'] and not older.get('paragraphs')
    assert [c[1] for c in FakeImap.instances[0].commands if c[0] == 'fetch' and 'TEXT' in c[2]] == ['2']


def test_payload_stays_under_trmnls_limit():
    # TRMNL refuses plugin data over 100 KB: text goes first from the oldest entries
    entry = {'msg_id': '1', 'sender': 'S' * 200, 'subject': 'x' * 900, 'timestamp': '2026-10-25T09:00:00+00:00',
             'body': 'é' * 3000, 'paragraphs': ['é' * 3000], 'markdown': 'é' * 3000}
    data = {'success': True, 'messages': [dict(entry, msg_id=str(i)) for i in range(50)], 'count': 50}
    transform.fit_payload(data)
    size = len(transform.json.dumps(data, ensure_ascii=False).encode('utf-8'))
    assert size <= transform.PAYLOAD_TARGET < 100_000
    assert data['messages'][0].get('paragraphs') and not data['messages'][-1].get('paragraphs')
    assert data['count'] == len(data['messages']) == 50  # entries stay, only text was dropped
    latest = {'success': True, 'message': dict(entry, body='word ' * 40000)}
    transform.fit_payload(latest)
    assert len(transform.json.dumps(latest, ensure_ascii=False).encode('utf-8')) <= transform.PAYLOAD_TARGET
    assert latest['message']['truncated'] and latest['message']['body'].endswith('…')

def test_a_long_answer_cannot_pass_the_deadline(monkeypatch):
    # A server that keeps sending lines: every line read gets only the time left of the whole run
    clock = FakeClock()
    monkeypatch.setattr(transform.time, 'monotonic', clock)

    def readline(self):
        clock.now += 0.5
        return b'* line\r\n'

    original = FakeImap.fetch

    def dribbling_fetch(self, ids, what):
        for _ in range(20):  # 10 s of lines
            self.readline()
        return original(self, ids, what)
    monkeypatch.setattr(FakeImap, 'readline', readline, raising=False)
    monkeypatch.setattr(FakeImap, 'fetch', dribbling_fetch)
    data = run(GMAIL)['data']
    assert data['code'] == 'TIMEOUT' and clock.now - 1000.0 <= transform.DEADLINE_SECONDS + 0.5


def test_without_a_filter_no_search_lists_the_whole_folder(monkeypatch):
    # 2026-10-25: SEARCH ALL on a full mailbox took seconds and the run timed out
    def select(self, folder, readonly=False):
        self.commands.append(('select', folder, readonly))
        return 'OK', [b'120000']

    def search(self, charset, criteria):
        raise AssertionError('no SEARCH without a filter')
    monkeypatch.setattr(FakeImap, 'select', select)
    monkeypatch.setattr(FakeImap, 'search', search)
    monkeypatch.setattr(FakeImap, 'fetch', lambda self, ids, what: (self.commands.append(('fetch', ids, what)), ('OK', []))[1])
    assert run({**GMAIL, 'limit': '10'})['data']['success']
    fetch = [c for c in FakeImap.instances[0].commands if c[0] == 'fetch'][0]
    assert fetch[1] == ','.join(str(i) for i in range(119991, 120001))


def test_a_filter_still_searches(monkeypatch):
    searched = []
    monkeypatch.setattr(FakeImap, 'search', lambda self, charset, criteria: (searched.append(criteria), ('OK', [b'1 2']))[1])
    data = run({**GMAIL, 'unread_only': 'yes'})['data']
    assert data['success'] and searched == ['UNSEEN'] and len(data['messages']) == 2


@pytest.mark.parametrize('extra', [{}, {'unread_only': 'yes', 'flagged_only': 'yes', 'hide_invitations': True,
                                     'group_conversations': True, 'from_emails': 'a@x.com', 'hide_quoted': False}])
def test_plain_list_fetches_no_text(monkeypatch, extra):
    # Owner 2026-10-26: no message content without a setting that shows it; only headers, as the live plugin.
    # (Before 2026-10-26 this test read requests this fake never recorded, so it could not fail.)
    whats, original = [], FakeImap.fetch
    monkeypatch.setattr(FakeImap, 'fetch', lambda self, ids, what: (whats.append(what), original(self, ids, what))[1])
    run({**GMAIL, **extra})
    assert whats and not any('BODY.PEEK[]' in w or 'BODY.PEEK[TEXT]' in w for w in whats)


def test_run_applies_the_payload_limit(monkeypatch):
    monkeypatch.setattr(FakeImap, 'fetch', preview_fetch)
    monkeypatch.setattr(transform, 'PAYLOAD_TARGET', 1200)
    newest, older = run({**GMAIL, 'display': 'preview'})['data']['messages']
    assert newest.get('paragraphs') and not older.get('paragraphs')


def big_folder(monkeypatch, answers, clock=None, cost=0.0):
    """A folder of 120000 messages whose SEARCH answers come from answers, in order"""
    searched = []

    def select(self, folder, readonly=False):
        return 'OK', [b'120000']

    def search(self, charset, criteria):
        searched.append(criteria)
        if clock:
            clock.now += cost
        return 'OK', [answers[len(searched) - 1]]
    monkeypatch.setattr(FakeImap, 'select', select)
    monkeypatch.setattr(FakeImap, 'search', search)
    monkeypatch.setattr(FakeImap, 'fetch', lambda self, ids, what: ('OK', []))
    return searched


def test_a_filter_searches_the_newest_messages_first(monkeypatch):
    # 2026-10-25: Gmail's category search over a full mailbox timed out
    searched = big_folder(monkeypatch, [b'119990 119995', b' '.join(str(i).encode() for i in range(119980, 120000))])
    assert run({**GMAIL, 'gmail_category': 'Primary', 'limit': '10'})['data']['success']
    assert searched == ['119501:* X-GM-RAW "category:primary"', '115001:* X-GM-RAW "category:primary"']


def test_the_search_stops_widening_when_time_runs_short(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(transform.time, 'monotonic', clock)
    searched = big_folder(monkeypatch, [b'119990 119995'], clock, cost=transform.DEADLINE_SECONDS - 1.0)
    assert run({**GMAIL, 'unread_only': 'yes', 'limit': '10'})['data']['success']
    assert searched == ['119501:* UNSEEN']


@pytest.mark.parametrize('value, expected', [(True, True), ('true', True), ('yes', True), (False, False),
                                             ('false', False), ('no', False), (None, False), ('', False)])
def test_switches_read_booleans_and_the_old_yes_no(value, expected):
    # Owner 2026-10-25: yes/no selects became switches; installs from before keep their saved yes/no
    assert transform._settings({**GMAIL, 'unread_only': value})['unread_only'] is expected


def test_show_previews_switch_and_the_old_preview_option():
    assert transform._settings(GMAIL)['display'] == 'list'  # previews default off
    assert transform._settings({**GMAIL, 'show_previews': True})['display'] == 'preview'
    assert transform._settings({**GMAIL, 'display': 'preview'})['display'] == 'preview'
    assert transform._settings({**GMAIL, 'display': 'combined', 'show_previews': True})['display'] == 'combined'


def test_hide_quoted_is_on_unless_switched_off():
    assert transform._settings(GMAIL)['hide_quoted'] is True
    assert transform._settings({**GMAIL, 'hide_quoted': False})['hide_quoted'] is False
    assert transform._settings({**GMAIL, 'hide_quoted': 'no'})['hide_quoted'] is False


def test_newest_first_across_time_zones(monkeypatch):
    # 2026-10-25: sorted as text, 13:31 +02:00 (11:31 UTC) came before 12:12 +00:00
    def header(subject, date):
        return f'From: a@example.com\r\nSubject: {subject}\r\nDate: {date}\r\n\r\n'.encode()
    answers = [(b'1 (FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', header('earlier', 'Fri, 23 Oct 2026 13:31:00 +0200')), b')',
               (b'2 (FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', header('later', 'Fri, 23 Oct 2026 12:12:00 +0000')), b')']
    monkeypatch.setattr(FakeImap, 'fetch', lambda self, ids, what: ('OK', answers))
    assert [m['subject'] for m in run(GMAIL)['data']['messages']] == ['later', 'earlier']


@pytest.mark.parametrize('value, expected', [(True, True), (False, False), ('yes', True), ('no', False)])
def test_new_switches_hide_invitations_and_quoted(value, expected):
    s = transform._settings({**GMAIL, 'hide_invitations': value, 'hide_quoted': value})
    assert s['hide_invites'] is expected and s['hide_quoted'] is expected


def personal_of(to, cc=''):
    raw = f'From: a@example.com\r\nTo: {to}\r\nCc: {cc}\r\nSubject: x\r\n\r\n'.encode()
    return transform.parse_message('1', b'', raw, 'Me@Example.com')['personal']


def test_personal_level_from_to_and_cc():
    # Owner 2026-10-26: Gmail's personal level, worked out from To/Cc for every provider
    assert personal_of('Me <me@example.com>') == 'only'
    assert personal_of('me@example.com, bob@example.com') == 'others'
    assert personal_of('bob@example.com', 'me@example.com') == 'others'
    assert personal_of('list@lists.example') is None
    assert transform.parse_message('1', b'', b'To: me@example.com\r\n\r\n')['personal'] is None  # switched off


def test_to_and_cc_are_always_fetched(monkeypatch):
    # Owner 2026-10-26: the personal level is always shown, no setting
    whats = []
    monkeypatch.setattr(FakeImap, 'fetch', lambda self, ids, what: (whats.append(what), ('OK', []))[1])
    run(GMAIL)
    assert 'FROM SUBJECT DATE TO CC' in whats[0]


def row(subject, msg_id, read=True, flagged=False, thread=None):
    return {'subject': subject, 'msg_id': msg_id, 'read': read, 'flagged': flagged, 'thread': thread}


def test_conversations_group_by_subject_without_reply_prefixes():
    # Owner 2026-10-26: Gmail's conversation count ("apswood 2")
    rows = transform.group_conversations([row('RE: Lunch', '3', read=False), row('Report', '2'), row('Lunch', '1', flagged=True),
                                          row('Fwd: AW: lunch', '0')])
    assert [(r['msg_id'], r['count']) for r in rows] == [('3', 3), ('2', 1)]
    assert rows[0]['read'] is False and rows[0]['flagged'] is True  # unread if any is, flagged if any is


def test_gmail_conversations_use_its_thread_id(monkeypatch):
    header = b'From: a@example.com\r\nSubject: Same subject\r\nDate: Sat, 25 Oct 2026 09:00:00 +0000\r\n\r\n'
    answers = [(b'1 (X-GM-THRID 111 FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', header), b')',
               (b'2 (X-GM-THRID 222 FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', header), b')',
               (b'3 (X-GM-THRID 111 FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {80}', header), b')']
    whats = []
    monkeypatch.setattr(FakeImap, 'fetch', lambda self, ids, what: (whats.append(what), ('OK', answers))[1])
    rows = run({**GMAIL, 'group_conversations': True})['data']['messages']
    assert 'X-GM-THRID' in whats[0] and sorted(r['count'] for r in rows) == [1, 2]  # same subject, two threads
    run(GMAIL)
    assert 'X-GM-THRID' not in whats[1]
