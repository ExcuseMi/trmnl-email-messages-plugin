# The 'Latest message' display. Run: python3 -m pytest plugin/test
import imaplib
import pathlib
import socket
import sys
from email.message import EmailMessage

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import transform  # noqa: E402
from imap_answers import STATIC_DATA  # noqa: E402
from imap_answers import answer  # noqa: E402

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
    flags = '\\Flagged'
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
        return 'OK', [(FakeImap.ids.split() or [b'0'])[-1]]  # EXISTS: the highest message number

    def search(self, charset, criteria):
        self.commands.append(('search', criteria))
        return 'OK', [FakeImap.ids]

    def fetch(self, ids, what):
        self.commands.append(('fetch', ids, what))
        return 'OK', [part for i in ids.split(',') for part in answer(i, FakeImap.raw, FakeImap.flags, what)]

    def logout(self):
        pass


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    FakeImap.instances.clear()
    FakeImap.password, FakeImap.ids = 'right', b'3 4 5'
    FakeImap.raw = mail('Hi,\n\nSee you at 8.\n\nJ.')
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', FakeImap)


def text_fetch(imap):
    return next(c for c in imap.commands if c[0] == 'fetch' and 'BODY.PEEK[TEXT]' in c[2])


def run(values=GMAIL, previous=None):
    # Like TRMNL: the static data from settings.yml comes with every run
    return transform.run({**STATIC_DATA, 'trmnl': {'plugin_settings': {'custom_fields_values': values},
                                                   'previous_merge_variables': previous or {}}})


def test_shows_the_latest_message_with_its_text():
    data = run()['data']
    m = data['message']
    assert m['subject'] == 'Café tonight' and m['sender'] == 'Jürgen' and m['flagged'] and not m['read']
    assert m['body'] == 'Hi,\n\nSee you at 8.\n\nJ.'
    fetch = text_fetch(FakeImap.instances[0])
    assert fetch[1] == '5'  # the newest id
    assert 'BODY.PEEK[TEXT]<0.' in fetch[2]  # never marks it read, fetches only the start of the text
    assert list(data['timing']['steps_ms']) == ['connect', 'login', 'select', 'search', 'fetch']


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
        return 'OK', answer(ids, FakeImap.raw, FakeImap.flags, what)
    monkeypatch.setattr(FakeImap, 'fetch', fetch)
    run({**GMAIL, 'hide_invitations': 'yes'})
    assert text_fetch(FakeImap.instances[0])[1] == '4'
    run(GMAIL)
    assert text_fetch(FakeImap.instances[1])[1] == '5'


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


def test_links_and_doubled_addresses_are_left_out():
    # 2026-10-25: tracking links and "a@b <a@b>" made previews unreadable
    text = ('View people in this rolehttps://www.example.com/search?keywords=x&lipi=urn%3Ali\n'
            'Send questions to the coach via coach@school.example <coach@school.example>.\n'
            'Book here: <https://booking.example/abc>\n'
            '<https://booking.example/only-a-link>')
    assert transform.clean_text(text) == ('View people in this role\n'
                                          'Send questions to the coach via coach@school.example.\n'
                                          'Book here:')


def test_forwarded_mail_shows_its_text_without_the_header_block():
    text = ('See below.\n\n---------- Forwarded message ---------\nVan: Salon <mail@salon.example>\n'
            'Date: do 22 okt 2026, 16:49\nSubject: Reminder for tomorrow\nTo: <me@example.com>\n\n'
            'Your appointment is tomorrow at 17:00.')
    assert transform.clean_text(text) == 'See below.\n\nYour appointment is tomorrow at 17:00.'
    english = text.replace('Van:', 'From:')  # "From:" also starts a quoted reply; inside a forward it does not
    assert transform.clean_text(english) == 'See below.\n\nYour appointment is tomorrow at 17:00.'


def test_latest_brings_the_messages_before_it_as_rows():
    data = run()['data']
    assert data['message']['subject'] == 'Café tonight'
    assert len(data['others']) == 4 and all('body' not in o for o in data['others'])  # rows: headers only
    rows = [c for c in FakeImap.instances[0].commands if c[0] == 'fetch' and 'HEADER.FIELDS (FROM SUBJECT DATE' in c[2] and 'BODY.PEEK[TEXT]' not in c[2]]
    assert rows[0][1] == '1,2,3,4'  # the ones before the newest (5)


def test_latest_without_time_for_rows_shows_the_message_alone(monkeypatch):
    clock = type('Clock', (), {'now': 1000.0, '__call__': lambda self: self.now})()
    monkeypatch.setattr(transform.time, 'monotonic', clock)
    original = FakeImap.fetch

    def slow_text(self, ids, what):
        if 'BODY.PEEK[TEXT]' in what:
            clock.now += transform.DEADLINE_SECONDS - 0.5  # leaves less than TEXT_MARGIN
        return original(self, ids, what)
    monkeypatch.setattr(FakeImap, 'fetch', slow_text)
    data = run()['data']
    assert data['success'] and data['message'] and data['others'] == []


def test_combined_brings_the_newest_with_its_text_and_the_rest_as_the_list():
    data = run({**GMAIL, 'display': 'combined', 'limit': '3'})['data']
    assert data['display'] == 'combined' and data['message']['paragraphs'] == ['Hi,', 'See you at 8.', 'J.']
    assert len(data['messages']) == 3 and data['count'] == 3 and all('body' not in m for m in data['messages'])
    assert data['messages'][0]['msg_id'] == data['message']['msg_id']  # the open message stays first, as in a mail client
    texts = [c for c in FakeImap.instances[0].commands if c[0] == 'fetch' and 'BODY.PEEK[TEXT]' in c[2]]
    assert len(texts) == 1  # text for the newest only


def test_combined_short_of_time_still_shows_the_newest_by_its_subject(monkeypatch):
    clock = type('Clock', (), {'now': 1000.0, '__call__': lambda self: self.now})()
    monkeypatch.setattr(transform.time, 'monotonic', clock)
    original = FakeImap.fetch

    def slow_headers(self, ids, what):
        if 'HEADER.FIELDS (FROM SUBJECT DATE' in what and 'BODY.PEEK[TEXT]' not in what:
            clock.now += transform.DEADLINE_SECONDS - 0.5  # leaves less than TEXT_MARGIN
        return original(self, ids, what)
    monkeypatch.setattr(FakeImap, 'fetch', slow_headers)
    data = run({**GMAIL, 'display': 'combined'})['data']
    assert data['success'] and data['message']['subject'] == 'Café tonight' and data['message']['paragraphs'] == []


def test_combined_with_previews_gives_the_other_rows_their_text():
    # Owner 2026-10-26: Show Previews also for the list beside the latest message
    data = run({**GMAIL, 'display': 'combined', 'show_previews': True, 'limit': '3'})['data']
    open_row, *others = data['messages']
    assert 'paragraphs' not in open_row  # its full text is in the panel
    assert others and all(m['paragraphs'] == ['Hi,', 'See you at 8.', 'J.'] for m in others)
    assert 'paragraphs' not in run({**GMAIL, 'display': 'combined', 'limit': '3'})['data']['messages'][1]


DEMO = {'provider': 'gmail', 'email': 'master@trmnl.com'}


@pytest.mark.parametrize('display', ['list', 'preview', 'latest', 'combined'])
def test_trmnls_demo_account_gets_the_demo_inbox_without_a_login(monkeypatch, display):
    # 2026-10-26: the backend served mock-data.json for this account; serverless tried a real login instead
    def no_login(*a, **k):
        raise AssertionError('no IMAP for the demo account')
    monkeypatch.setattr(transform.imaplib, 'IMAP4_SSL', no_login)
    data = run({**DEMO, 'display': display})['data']
    assert data['success'] and data['demo'] and data['email'] == STATIC_DATA['demo_inbox']['address']
    if display in ('latest', 'combined'):
        assert data['message']['sender'] == 'Jim Halpert' and data['message']['paragraphs']
    if display != 'latest':
        assert data['messages'][0]['sender'] == 'Jim Halpert'
        assert bool(data['messages'][1].get('paragraphs')) == (display == 'preview')


def test_demo_honours_filters_and_limit():
    data = run({**DEMO, 'flagged_only': 'yes', 'limit': '2'})['data']
    assert [m['sender'] for m in data['messages']] == ['Michael Scott', 'Schrute Farms Online']


def fetched_ids(imap):
    return sum(len(c[1].split(',')) for c in imap.commands if c[0] == 'fetch' and 'HEADER.FIELDS (FROM SUBJECT DATE' in c[2] and 'BODY.PEEK[TEXT]' not in c[2])


@pytest.mark.parametrize('display', ['list', 'preview', 'latest', 'combined'])
def test_no_layout_fetches_more_mail_than_the_number_of_messages(display):
    # Owner 2026-10-26: no more mail fetched than the plain list fetched before (N messages)
    FakeImap.ids = b' '.join(str(i).encode() for i in range(1, 41))
    run({**GMAIL, 'display': display, 'limit': '4'})
    imap = FakeImap.instances[0]
    texts = sum(len(c[1].split(',')) for c in imap.commands if c[0] == 'fetch' and 'BODY.PEEK[TEXT]' in c[2])
    assert fetched_ids(imap) <= 4 and texts <= 4


def test_demo_shows_personal_levels():
    rows = run(DEMO)['data']['messages']
    assert [m['personal'] for m in rows[:4]] == ['only', 'only', 'others', None]


def test_open_message_knows_its_personal_level():
    FakeImap.raw = mail('Hi').replace(b'Subject:', b'To: me@gmail.com\nSubject:', 1)
    assert run({**GMAIL, 'display': 'latest'})['data']['message']['personal'] == 'only'
    assert run({**GMAIL, 'display': 'combined'})['data']['message']['personal'] == 'only'


def test_latest_counts_its_own_conversation_instead_of_showing_it_as_rows():
    # Owner 2026-10-26: the rows under a latest message do not repeat the open conversation
    data = run({**GMAIL, 'display': 'latest', 'group_conversations': True})['data']
    assert data['message']['count'] == 5 and data['others'] == []  # the fake inbox is one conversation of 5
    data = run({**GMAIL, 'display': 'combined', 'group_conversations': True})['data']
    assert data['message']['count'] == data['messages'][0]['count']


@pytest.mark.parametrize('display', ['latest', 'preview'])
def test_newsletter_text_behind_a_lot_of_css_is_fetched(display):
    # 2026-10-26: a newsletter's <head> CSS filled the whole fetch window and the text stayed empty
    from test_mail_shapes import NEWSLETTER, html_mail
    css = '.c{color:#123456;margin:0 auto;padding:4px 8px}\n'
    newsletter = NEWSLETTER.replace(css * 900, css * (2000 if display == 'latest' else 900))  # past each view's window
    FakeImap.raw = html_mail(newsletter)
    data = run({**GMAIL, 'display': display})['data']
    message = data['message'] if display == 'latest' else data['messages'][0]
    assert 'Everything 30% off until Sunday.' in message['body']
    pieces = [c for c in FakeImap.instances[0].commands if c[0] == 'fetch' and c[2].startswith('(BODY.PEEK[TEXT]<')]
    assert pieces and all(int(c[2].split('<')[1].split('.')[1].rstrip('>)')) <= transform.MORE_TEXT_BYTES for c in pieces)


def test_demo_inbox_lives_in_the_static_data():
    # Owner 2026-10-26: the demo inbox is data in settings.yml static_data, not code
    inbox = STATIC_DATA['demo_inbox']
    assert inbox['address'] == 'dwight.schrute@dundermifflin.com' and len(inbox['messages']) == 15
    assert not hasattr(transform, 'DEMO_MESSAGES')


def test_demo_without_static_data_shows_an_empty_inbox_not_an_error():
    data = transform.run({'trmnl': {'plugin_settings': {'custom_fields_values': DEMO}}})['data']
    assert data['success'] and data['messages'] == []


def test_newsletter_follow_up_out_of_time_keeps_the_first_piece(monkeypatch):
    # A follow-up piece that does not finish in time must not turn the whole run into a timeout
    from test_mail_shapes import html_mail
    FakeImap.raw = html_mail('<p>Short intro before the styles.</p><style>' + 'x{y:z}' * 20000 + '</style>')
    original = FakeImap.fetch

    def slow_more(self, ids, what):
        if what.startswith('(BODY.PEEK[TEXT]<'):
            raise socket.timeout()
        return original(self, ids, what)
    monkeypatch.setattr(FakeImap, 'fetch', slow_more)
    data = run({**GMAIL, 'display': 'latest'})['data']
    assert data['success'] and data['message']['body'] == 'Short intro before the styles.'
