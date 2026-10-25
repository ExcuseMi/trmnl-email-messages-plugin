# The 'Latest message' display. Run: python3 -m pytest plugin/test
import imaplib
import pathlib
import socket
import sys
from email.message import EmailMessage

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import transform  # noqa: E402

GMAIL = {'provider': 'gmail', 'email': 'me@gmail.com', 'gmail_password': 'right', 'display': 'latest'}


def mail(body=None, html=None, subject='Café tonight', sender='Jürgen <j@example.com>', attachment=False,
         charset='utf-8'):
    msg = EmailMessage()
    msg['From'], msg['Subject'], msg['Date'] = sender, subject, 'Sat, 25 Oct 2026 09:00:00 +0000'
    if body is not None:
        msg.set_content(body, charset=charset)
        if html is not None:
            msg.add_alternative(html, subtype='html')
    else:
        msg.set_content(html, subtype='html')
    if attachment:
        msg.add_attachment(b'%PDF' + b'x' * 5000, maintype='application', subtype='pdf', filename='invoice.pdf')
    return msg.as_bytes()


class FakeSocket:
    def settimeout(self, value):
        pass


class FakeImap:
    instances = []
    raw = b''
    flags = b'5 (FLAGS (\\Flagged) BODY[]<0> {100}'
    ids = b'3 4 5'
    password = 'right'

    def __init__(self, host, port, ssl_context=None, timeout=None):
        self.host, self.commands, self.sock = host, [], FakeSocket()
        FakeImap.instances.append(self)

    def login(self, user, password):
        if password != FakeImap.password:
            raise imaplib.IMAP4.error('AUTHENTICATIONFAILED')

    def select(self, folder, readonly=False):
        self.commands.append(('select', folder, readonly))
        return 'OK', [b'5']

    def search(self, charset, criteria):
        self.commands.append(('search', criteria))
        return 'OK', [FakeImap.ids]

    def fetch(self, ids, what):
        self.commands.append(('fetch', ids, what))
        return 'OK', [(FakeImap.flags, FakeImap.raw), b')']

    def logout(self):
        pass


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    FakeImap.instances.clear()
    FakeImap.password, FakeImap.ids = 'right', b'3 4 5'
    FakeImap.raw = mail('Hi,\n\nSee you at 8.\n\nJ.')
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', FakeImap)


def run(values=GMAIL, previous=None):
    return transform.run({'trmnl': {'plugin_settings': {'custom_fields_values': values},
                                    'previous_merge_variables': previous or {}}})


def test_shows_the_latest_message_with_its_text():
    data = run()['data']
    m = data['message']
    assert m['subject'] == 'Café tonight' and m['sender'] == 'Jürgen' and m['flagged'] and not m['read']
    assert m['body'] == 'Hi,\n\nSee you at 8.\n\nJ.'
    fetch = FakeImap.instances[0].commands[-1]
    assert fetch[1] == '5'  # the newest id
    assert 'BODY.PEEK[]<0.' in fetch[2]  # never marks it read, fetches only the start
    assert list(data['timing']['steps_ms']) == ['connect', 'login', 'select', 'search', 'fetch', 'parse']


def test_html_only_mail_becomes_text_without_styles_or_images():
    FakeImap.raw = mail(html='<html><head><style>p{color:red}</style></head><body><p>Hello&nbsp;there</p>'
                             '<img src="https://track.example/pixel.gif"><script>x()</script><p>Second</p></body></html>')
    body = run()['data']['message']['body']
    assert body == 'Hello there\n\nSecond'
    assert 'track.example' not in body and 'color' not in body


def test_plain_part_is_preferred_and_attachments_noted():
    FakeImap.raw = mail('Plain text', html='<p>HTML text</p>', attachment=True)
    m = run()['data']['message']
    assert m['body'] == 'Plain text' and m['has_attachments']


def test_quoted_reply_and_signature_hidden():
    FakeImap.raw = mail('Yes, works for me.\n\n-- \nJürgen\n')
    assert run()['data']['message']['body'] == 'Yes, works for me.'
    FakeImap.raw = mail('Sounds good.\n\nOn Fri, 24 Oct 2026, Me wrote:\n> Shall we meet?\n')
    assert run()['data']['message']['body'] == 'Sounds good.'


def test_quoted_reply_kept_when_asked():
    FakeImap.raw = mail('Sounds good.\n> Shall we meet?')
    body = run({**GMAIL, 'hide_quoted': 'no'})['data']['message']['body']
    assert '> Shall we meet?' in body


def test_long_body_is_cut():
    FakeImap.raw = mail('word ' * 2000)
    m = run()['data']['message']
    assert m['truncated'] and len(m['body']) <= transform.MAX_BODY_CHARS + 1 and m['body'].endswith('…')


def test_partial_fetch_still_parses():
    FakeImap.raw = mail('Start of a long letter. ' * 50, attachment=True)[:900]
    m = run()['data']['message']
    assert m['body'].startswith('Start of a long letter.')


def test_other_charsets_are_decoded():
    FakeImap.raw = mail('Café crème à côté', charset='iso-8859-1')
    assert run()['data']['message']['body'] == 'Café crème à côté'


def test_encrypted_mail_is_marked_not_shown():
    FakeImap.raw = (b'From: a@example.com\r\nSubject: Secret\r\nContent-Type: multipart/encrypted; '
                    b'protocol="application/pgp-encrypted"; boundary=b\r\n\r\n--b\r\nContent-Type: '
                    b'application/pgp-encrypted\r\n\r\nVersion: 1\r\n--b--\r\n')
    m = run()['data']['message']
    assert m['encrypted'] and m['body'] == ''


def test_empty_mailbox_gives_no_message():
    FakeImap.ids = b''
    data = run()['data']
    assert data['success'] and data['message'] is None


def test_unread_only_and_sender_filter_build_the_search():
    s = transform._settings({**GMAIL, 'unread_only': 'yes', 'from_emails': 'a@x.com,b@x.com'})
    assert transform.search_criteria(s) == 'UNSEEN OR FROM "a@x.com" FROM "b@x.com"'


def test_wrong_password_is_shown():
    FakeImap.password = 'other'
    assert run()['data']['code'] == 'AUTH_FAILED'


def test_connection_failure_keeps_previous_message(monkeypatch):
    def refuse(*a, **k):
        raise OSError('unreachable')
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', refuse)
    previous = {'data': {'success': True, 'message': {'subject': 'old'}}}
    data = run(previous=previous)['data']
    assert data['message'] == {'subject': 'old'} and data['stale_reason'] == 'CONNECTION'


def test_timeout_without_previous_explains(monkeypatch):
    def slow(*a, **k):
        raise socket.timeout()
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', slow)
    assert run()['data']['code'] == 'TIMEOUT'


@pytest.mark.parametrize('field', ['folder', 'from_emails'])
def test_imap_command_injection_refused(field):
    assert run({**GMAIL, field: 'INBOX"\r\nA1 DELETE "x'})['data']['code'] == 'INVALID'


def test_quoted_lines_without_a_header_are_hidden():
    FakeImap.raw = mail('Sure.\n> Can you bring the map?\n> Thanks\nSee you')
    assert run()['data']['message']['body'] == 'Sure.\nSee you'


def test_body_is_split_into_paragraphs():
    m = run()['data']['message']
    assert m['paragraphs'] == ['Hi,', 'See you at 8.', 'J.']


def test_latest_skips_a_newest_invitation_when_asked(monkeypatch):
    def fetch(self, ids, what):
        self.commands.append(('fetch', ids, what))
        if what == '(BODYSTRUCTURE)':
            return 'OK', [b'3 (BODYSTRUCTURE ("text" "plain" NIL NIL NIL "7bit" 10 1))',
                          b'4 (BODYSTRUCTURE ("text" "plain" NIL NIL NIL "7bit" 10 1))',
                          b'5 (BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7bit" 9 1)("text" "calendar" '
                          b'("method" "REQUEST") NIL NIL "7bit" 300 5) "alternative"))']
        return 'OK', [(FakeImap.flags, FakeImap.raw), b')']
    monkeypatch.setattr(FakeImap, 'fetch', fetch)
    run({**GMAIL, 'hide_invitations': 'yes'})
    body_fetch = FakeImap.instances[0].commands[-1]
    assert body_fetch[1] == '4'
    run(GMAIL)
    assert FakeImap.instances[1].commands[-1][1] == '5'


def test_wrapped_plain_text_reads_as_paragraphs():
    text = ('Beste ouders\n'
            'Naar aanleiding van de storm vragen we om bij het afhalen van\n'
            'de kinderen om 15u *niet aan de poort te wachten*.\n-\n'
            '*Kleuters:* graag afhalen in de klas.\n'
            '- eerste punt\n- tweede punt\n\n'
            'Met vriendelijke groeten')
    assert transform.to_paragraphs(text) == [
        'Beste ouders\nNaar aanleiding van de storm vragen we om bij het afhalen van de kinderen om 15u '
        'niet aan de poort te wachten. Kleuters: graag afhalen in de klas.\n- eerste punt\n- tweede punt',
        'Met vriendelijke groeten']


def test_markdown_keeps_bold_lists_and_line_breaks():
    text = ('Beste ouders\n'
            'Naar aanleiding van de storm vragen we om bij het afhalen van\n'
            'de kinderen om 15u *niet aan de poort te wachten*.\n-\n'
            '- eerste punt\n- tweede punt\n\n'
            'Met vriendelijke groeten')
    assert transform.to_markdown(text) == (
        'Beste ouders  \nNaar aanleiding van de storm vragen we om bij het afhalen van de kinderen om 15u '
        '**niet aan de poort te wachten**.\n\n- eerste punt\n- tweede punt\n\nMet vriendelijke groeten')
