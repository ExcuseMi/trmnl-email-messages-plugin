# TRMNL serverless (Python): reads mail over IMAP inside TRMNL's sandbox, so the app password
# never leaves TRMNL except to the mail server itself. Two displays share one mailbox reader:
# a list of the latest headers, or the latest message with its text.
# Standard library only (imaplib, ssl, email, html.parser): the sandbox offers no extra packages.
# Never loads images or links from a mail (tracking pixels); text only.

import email
import email.policy
import imaplib
import json
import re
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

SERVERS = {
    'gmail': ('imap.gmail.com', 993, 'gmail_password'),
    'outlook': ('outlook.office365.com', 993, 'outlook_password'),
    'yahoo': ('imap.mail.yahoo.com', 993, 'yahoo_password'),
    'icloud': ('imap.mail.me.com', 993, 'icloud_password'),
}
MAX_MESSAGES = 50
SEARCH_WINDOWS = (500, 5000, None)  # with a filter: newest 500, then 5000, then the whole folder
SEARCH_MARGIN = 1.5  # seconds kept free before widening the search
NEWEST_IDS = MAX_MESSAGES * 3  # without a filter: enough ids for every display, invitations hidden included
DEADLINE_SECONDS = 4.3  # TRMNL stops a run after 5 s, sandbox start included; Gmail login and select alone took 2.4 s (2026-10-25)
KEEP_PREVIOUS = {'TIMEOUT', 'CONNECTION', 'PROTOCOL', 'UNEXPECTED_ERROR'}
UNSAFE_CHARS = set('"\\\r\n\0')
MORE_TEXT_BYTES = 128 * 1024  # a newsletter's text after a lot of CSS: one more piece, up to here
FETCH_BYTES = 64 * 1024  # latest message: the start of its text, which comes before attachments
MAX_BODY_CHARS = 3000  # more never fits a screen; keeps the plugin data small
SNIPPET_BYTES = 16 * 1024  # List with preview: the start of each shown message's text
TEXT_HEADERS = 'FROM SUBJECT DATE TO CC CONTENT-TYPE CONTENT-TRANSFER-ENCODING MIME-VERSION'
TEXT_MARGIN = 0.8  # seconds kept free before fetching one more text: a fetch, its parse and the return
PAYLOAD_TARGET = 90 * 1000  # bytes of plugin data; TRMNL's limit is 100 KB, the rest is margin
SNIPPET_CHARS = 500  # per entry: a few lines on screen, small plugin data for up to 50 entries
INVITE_STRUCTURE = re.compile(rb'"(text" "calendar|application" "ics)"', re.I)  # an .ics part in BODYSTRUCTURE
INVITE_LOOKBACK = 10  # latest message: how many recent ones to check for a non-invitation
LATEST_OTHERS = 8  # latest message: rows for the messages before it, shown when the text leaves space
ENCRYPTED_TYPES = {'multipart/encrypted', 'application/pkcs7-mime', 'application/x-pkcs7-mime', 'application/pgp-encrypted'}


# TRMNL renders a recipe's demo and preview with this account: it gets example mail, never an IMAP login.
# The demo inbox lives in settings.yml static_data (demo_inbox), which TRMNL passes in with every run.
DEMO_ACCOUNT = 'master@trmnl.com'


def demo_data(s, demo_inbox):
    """The demo inbox from static_data, shaped like a real run for the chosen layout and filters"""
    now = datetime.now(timezone.utc)
    inbox = []
    for i, d in enumerate((demo_inbox or {}).get('messages') or []):
        if (s['unread_only'] and d['read']) or (s['flagged_only'] and not d['flagged']):
            continue
        inbox.append(({'sender': d['sender'], 'sender_email': d['sender_email'], 'subject': d['subject'],
                       'timestamp': (now - timedelta(hours=d['hours_ago'])).isoformat(), 'msg_id': str(1001 + i),
                       'read': d['read'], 'flagged': d['flagged'],
                       'personal': d.get('personal') if s['personal'] else None}, d.get('text') or ''))

    def with_text(m, text, max_chars=MAX_BODY_CHARS):
        body = text[:max_chars]
        return {**m, 'body': body, 'paragraphs': to_paragraphs(body), 'markdown': to_markdown(body),
                'truncated': len(text) > max_chars, 'has_attachments': False, 'encrypted': False}

    if s['threads']:
        texts = {m['msg_id']: t for m, t in inbox}
        inbox = [(row, texts[row['msg_id']]) for row in group_conversations([m for m, _ in inbox])]
    rows = inbox[:s['limit']]
    if s['display'] == 'latest':
        if not inbox:
            return None, []
        return with_text(*inbox[0]), [m for m, _ in inbox[1:min(1 + LATEST_OTHERS, s['limit'])]]
    if s['display'] == 'combined':
        if not rows:
            return None, []
        listed = [rows[0][0]] + [with_text(m, t, SNIPPET_CHARS) if s['previews'] else m for m, t in rows[1:]]
        return with_text(*rows[0]), listed
    if s['display'] == 'preview':
        return None, [with_text(m, t, SNIPPET_CHARS) for m, t in rows]
    return None, [m for m, _ in rows]


class MailError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _on(value, default=False):
    """A switch: boolean fields arrive as true/false; installs from before the switches kept 'yes'/'no'"""
    if value is None or value == '':
        return default
    return str(value).strip().lower() in ('yes', 'true', '1', 'on')


def _display(values):
    """list, latest or combined; the list with previews is 'preview' inside the plugin.
    'preview' was a display option before the Show Previews switch: installs that chose it keep their previews"""
    display = values.get('display')
    if display in ('latest', 'combined'):
        return display
    return 'preview' if display == 'preview' or _on(values.get('show_previews')) else 'list'


def _settings(values):
    provider = values.get('provider') or 'gmail'
    if provider == 'custom':
        server = (values.get('custom_server') or '').strip()
        port = int(values.get('custom_port') or 993)
        password = values.get('custom_password') or ''
    elif provider in SERVERS:
        server, port, password_key = SERVERS[provider]
        password = values.get(password_key) or ''
    else:
        raise MailError('INVALID', f'Unknown provider: {provider}')
    from_emails = values.get('from_emails') or []
    if isinstance(from_emails, str):
        from_emails = [e for e in from_emails.replace('\n', ',').split(',')]
    settings = {
        'server': server, 'port': port, 'password': password,
        'username': (values.get('email') or '').strip(),
        'folder': values.get('folder') or 'INBOX',
        'limit': min(max(int(values.get('limit') or 10), 1), MAX_MESSAGES),
        'unread_only': _on(values.get('unread_only')),
        'flagged_only': _on(values.get('flagged_only')),
        'gmail_category': (values.get('gmail_category') or '') if provider == 'gmail' else '',
        'from_emails': [e.strip() for e in from_emails if e and e.strip()],
        'display': _display(values),
        'previews': values.get('display') == 'preview' or _on(values.get('show_previews')),
        'hide_quoted': _on(values.get('hide_quoted'), default=True),
        'hide_invites': _on(values.get('hide_invitations')),
        'personal': True,  # owner 2026-10-26: always shown, no setting
        'threads': _on(values.get('group_conversations')),
    }
    if not (settings['server'] and settings['username'] and settings['password']):
        raise MailError('INVALID', 'Fill in your email address and app password in the plugin settings.')
    # These go into IMAP commands: a quote or line break would add commands
    for value in [settings['folder'], settings['gmail_category']] + settings['from_emails']:
        if UNSAFE_CHARS & set(value):
            raise MailError('INVALID', 'Folder, category and sender filters must not contain quotes or line breaks.')
    return settings


def search_criteria(s):
    if s['gmail_category']:
        parts = [f"category:{s['gmail_category'].lower()}"]
        if s['unread_only']:
            parts.append('is:unread')
        if s['flagged_only']:
            parts.append('is:starred')
        if s['from_emails']:
            parts.append('(' + ' OR '.join(f'from:{e}' for e in s['from_emails']) + ')')
        return f'X-GM-RAW "{" ".join(parts)}"'
    parts = []
    if s['unread_only']:
        parts.append('UNSEEN')
    if s['flagged_only']:
        parts.append('FLAGGED')
    if s['from_emails']:
        query = f'FROM "{s["from_emails"][0]}"'
        for addr in s['from_emails'][1:]:
            query = f'OR {query} FROM "{addr}"'
        parts.append(query)
    return ' '.join(parts) or 'ALL'


LIST_ITEM = re.compile(r'^([-*•]\s|\d+[.)]\s)')
WRAPPED_LINE = 50  # a line this long was most likely wrapped by the mail program; a shorter one is a real break
SEPARATOR = re.compile(r'^[-*_=~•.\s]+$')
EMPHASIS = re.compile(r'(?<![\w*])\*([^*\n]+?)\*(?![\w*])')


def _blocks(body):
    """Paragraphs as lists of lines: wrapped lines joined again, separators dropped, list items on their own line"""
    blocks = []
    for block in re.split(r'\n\s*\n', body):
        lines = [line.strip() for line in block.split('\n')]
        joined, previous = [], ''
        for line in (line for line in lines if line and not SEPARATOR.match(line)):
            if joined and len(previous) >= WRAPPED_LINE and not LIST_ITEM.match(line):
                joined[-1] += ' ' + line
            else:
                joined.append(line)
            previous = line
        if joined:
            blocks.append(joined)
    return blocks


def to_paragraphs(body):
    """Plain paragraphs (snippets): *bold* markers from plain-text mail removed"""
    return ['\n'.join(EMPHASIS.sub(r'\1', line) for line in block) for block in _blocks(body)]


def to_markdown(body):
    """Markdown for the message view (TRMNL's markdown_to_html): *bold* becomes **bold**, list items a
    real list, deliberate line breaks kept as hard breaks. The markup escapes it first: no raw HTML."""
    out = []
    for block in _blocks(body):
        text, items = [], []
        for line in block:
            if LIST_ITEM.match(line):
                items.append('- ' + LIST_ITEM.sub('', line))
                continue
            if items:  # a list ends: it needs its own block
                out.append('  \n'.join(text)) if text else None
                out.append('\n'.join(items))
                text, items = [], []
            text.append(EMPHASIS.sub(r'**\1**', line))
        if text:
            out.append('  \n'.join(text))
        if items:
            out.append('\n'.join(items))
    return '\n\n'.join(out)


def _decode(header):
    result = []
    for content, encoding in decode_header(header or ''):
        if isinstance(content, bytes):
            try:
                result.append(content.decode(encoding or 'utf-8', errors='ignore'))
            except LookupError:
                result.append(content.decode('utf-8', errors='ignore'))
        else:
            result.append(content)
    return ''.join(result).strip()


def personal_level(msg, me):
    """Gmail's personal level: 'only' = sent only to you, 'others' = to you and others, None = a list or newsletter"""
    if not me:
        return None
    recipients = {a.strip().lower() for _, a in getaddresses([_decode(msg.get(h, '')) for h in ('To', 'Cc')]) if a.strip()}
    if me.lower() not in recipients:
        return None
    return 'only' if len(recipients) == 1 else 'others'


def parse_message(msg_id, flags, header_bytes, me=None):
    msg = email.message_from_bytes(header_bytes)
    from_header = _decode(msg.get('From', ''))
    name, address = parseaddr(from_header)
    try:
        timestamp = parsedate_to_datetime(msg.get('Date', '')).isoformat()
    except (TypeError, ValueError, IndexError):
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        'sender': name or address or 'Unknown',
        'sender_email': address,
        'subject': _decode(msg.get('Subject', '')) or 'No Subject',
        'timestamp': timestamp,
        'msg_id': msg_id,
        'read': b'\\Seen' in flags,
        'flagged': b'\\Flagged' in flags,
        'personal': personal_level(msg, me),
    }


HIDDEN_STYLE = re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden|max-height\s*:\s*0(?![.\d])|font-size\s*:\s*0(?![.\d])'
                          r'|mso-hide\s*:\s*all', re.I)
INVISIBLE = re.compile('[\u200b-\u200d\u2060\ufeff\u034f\u00ad\u180e]')  # zero-width padding behind preheaders


class _TextFromHtml(HTMLParser):
    """HTML to plain text: paragraphs kept; styles, scripts, images and hidden text (newsletter preheaders) dropped"""
    BLOCKS = {'p', 'div', 'br', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'section', 'article', 'blockquote'}
    CELLS = {'td', 'th'}  # a space between cells, so a receipt row reads "Coffee beans 12.50"
    SKIP = {'style', 'script', 'head', 'title', 'noscript'}
    VOID = {'br', 'img', 'hr', 'meta', 'link', 'input', 'wbr', 'col', 'source', 'area', 'base'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.open = [], []  # open: (tag, hidden) of the elements we are inside

    def _hidden(self):
        return any(hidden for _, hidden in self.open)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        hidden = tag in self.SKIP or 'hidden' in attrs or bool(HIDDEN_STYLE.search(attrs.get('style') or ''))
        if tag not in self.VOID:
            self.open.append((tag, hidden))
        if not self._hidden():
            if tag in self.BLOCKS and tag != 'tr':  # rows end with a line break: a table reads as lines, not paragraphs
                self.parts.append('\n')
            elif tag in self.CELLS:
                self.parts.append(' ')

    def handle_endtag(self, tag):
        if any(t == tag for t, _ in self.open):
            while self.open:  # close up to the matching element; mail HTML often leaves tags open
                if self.open.pop()[0] == tag:
                    break
        if not self._hidden() and tag in self.BLOCKS:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self._hidden():
            self.parts.append(re.sub(r'[ \t\r\n]+', ' ', data))


def html_to_text(html):
    parser = _TextFromHtml()
    parser.feed(html)
    parser.close()
    text = INVISIBLE.sub('', ''.join(parser.parts))
    return '\n'.join(re.sub(r'[ \t]+', ' ', line).strip() for line in text.split('\n'))


QUOTE_HEADER = re.compile(r'^(On .{3,200} wrote:|Op .{3,200} schreef .{1,100}:|-{2,} ?Original Message ?-{2,}|From: .+)$', re.I)


FORWARD_MARK = re.compile(r'^-{2,} ?(Forwarded message|Doorgestuurd bericht|Weitergeleitete Nachricht|Message transf\S+) ?-{2,}$', re.I)
FORWARD_HEADER = re.compile(r'^(From|Van|Von|De|Date|Datum|Sent|Verzonden|Subject|Onderwerp|Betreff|Objet|To|Aan|An|Cc):', re.I)
LINK = re.compile(r'<(?:https?://|mailto:)[^>\s]*>|https?://\S+')
ANGLE_ADDRESS = re.compile(r'\s*<[^<>\s@]+@[^<>\s]+>')  # "Name <a@b>" and "a@b <a@b>": the name or address is already there
EMPTY_LEFTOVER = re.compile(r'^[\s()\[\]<>:;,.|-]*$')


def clean_text(text, hide_quoted=True):
    """Mail text for a screen: no quoted earlier mail, signature, forward headers, links or doubled addresses"""
    lines = [line.rstrip() for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n')]
    kept, forward_header = [], False
    for line in lines:
        stripped = line.strip()
        if FORWARD_MARK.match(stripped):
            forward_header = True  # the forwarded mail is the content; only its header lines go
            continue
        if forward_header:
            if not stripped or FORWARD_HEADER.match(stripped) or stripped.startswith('<'):
                continue
            forward_header = False
        if hide_quoted and (line in ('-- ', '--') or QUOTE_HEADER.match(stripped)):
            break  # signature or the start of the quoted earlier message
        if hide_quoted and line.lstrip().startswith('>'):
            continue
        tidy = ANGLE_ADDRESS.sub('', LINK.sub('', line.replace('\u00a0', ' ')))
        tidy = re.sub(r'[ \t]{2,}', ' ', tidy).strip()
        if tidy and EMPTY_LEFTOVER.match(tidy):
            continue  # a line that held only a link or an address
        kept.append(tidy)
    text = re.sub(r'\n{3,}', '\n\n', '\n'.join(kept)).strip()
    return text


def _part_text(part):
    payload = part.get_payload(decode=True) or b''
    charset = part.get_content_charset() or 'utf-8'
    try:
        return payload.decode(charset, errors='replace')
    except LookupError:
        return payload.decode('utf-8', errors='replace')


STUB_CHARS = 80  # a plain part this short next to an HTML part is a stub
STUB_PLAIN = re.compile(r'view (this|it|the) (e-?mail|message|newsletter)? ?(online|in (a|your) (web )?browser)'
                        r'|does(n.t| not) support html|html (version|e-?mail)|bekijk (deze|de) (e-?mail|nieuwsbrief) (online|in je browser)', re.I)


def extract_body(msg, hide_quoted=True):
    """Returns (text, has_attachments, encrypted); prefers text/plain, falls back to HTML"""
    if msg.get_content_type() in ENCRYPTED_TYPES or any(p.get_content_type() in ENCRYPTED_TYPES for p in msg.walk()):
        return '', False, True
    plain, html, attachments = None, None, False
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get('Content-Disposition') or '').lower()
        if 'attachment' in disposition or part.get_filename():
            attachments = True
            continue
        kind = part.get_content_type()
        if kind == 'text/plain' and plain is None:
            plain = _part_text(part)
        elif kind == 'text/html' and html is None:
            html = _part_text(part)
    text = clean_text(plain or '', hide_quoted)
    if html and (len(text) < STUB_CHARS or STUB_PLAIN.search(text)):
        # A stub plain part ("view this email in your browser") next to the real HTML: the HTML wins
        from_html = clean_text(html_to_text(html), hide_quoted)
        if len(from_html) > len(text):
            text = from_html
    return text, attachments, False


def parse_full_message(raw, flags, hide_quoted=True, max_chars=MAX_BODY_CHARS, me=None):
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    name, address = parseaddr(_decode(msg.get('From', '')))
    try:
        timestamp = parsedate_to_datetime(msg.get('Date', '')).isoformat()
    except (TypeError, ValueError, IndexError):
        timestamp = datetime.now(timezone.utc).isoformat()
    body, attachments, encrypted = extract_body(msg, hide_quoted)
    truncated = len(body) > max_chars
    body = body[:max_chars].rstrip() + ('…' if truncated else '')
    return {
        'sender': name or address or 'Unknown',
        'sender_email': address,
        'subject': _decode(msg.get('Subject', '')) or 'No Subject',
        'timestamp': timestamp,
        'read': b'\\Seen' in flags,
        'flagged': b'\\Flagged' in flags,
        'body': body,
        # Paragraphs for the markup's <p> elements; a single line break stays inside a paragraph
        'paragraphs': to_paragraphs(body),
        'markdown': to_markdown(body),
        'truncated': truncated,
        'has_attachments': attachments,
        'encrypted': encrypted,
        'personal': personal_level(msg, me),
    }


class Timer:
    """Guards TRMNL's 5 s limit: every step gets only the time that is left, and each step is timed"""

    def __init__(self, deadline=DEADLINE_SECONDS):
        self.deadline = deadline
        self.started = self.mark = time.monotonic()
        self.steps = {}

    def left(self):
        remaining = self.deadline - (time.monotonic() - self.started)
        if remaining <= 0:
            raise MailError('TIMEOUT', 'The mail server took too long to answer.')
        return remaining

    def remaining(self):
        return self.deadline - (time.monotonic() - self.started)

    def step(self, name):
        now = time.monotonic()
        self.steps[name] = round((now - self.mark) * 1000)
        self.mark = now

    def report(self):
        return {'steps_ms': dict(self.steps), 'total_ms': round((time.monotonic() - self.started) * 1000),
                'limit_ms': round(self.deadline * 1000)}


def search_newest(client, s, exists, timer, guard):
    """Ids of the newest matching messages. A search over a full mailbox takes seconds (Gmail's category
    search above all; 2026-10-25 timeouts), so the newest messages are searched first and the range
    widens only while too few match and time is left"""
    criteria = search_criteria(s)
    if criteria == 'ALL':
        # No filter: the newest messages are the highest numbers
        return [str(i).encode() for i in range(max(1, exists - NEWEST_IDS + 1), exists + 1)]
    wanted = s['limit'] * 3 if s['hide_invites'] else s['limit']
    ids = []
    for window in SEARCH_WINDOWS:
        first = max(1, exists - window + 1) if window else 1
        guard()
        status, data = client.search(None, criteria if first == 1 else f'{first}:* {criteria}')
        if status != 'OK':
            raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
        ids = (data[0] or b'').split()
        if len(ids) >= wanted or first == 1 or timer.remaining() < SEARCH_MARGIN:
            break
    return ids


def read_mailbox(s, timer, read):
    """Connect, log in, select and search; then read(client, ids, guard) fetches what the display needs"""
    try:
        client = imaplib.IMAP4_SSL(s['server'], s['port'], ssl_context=ssl.create_default_context(),
                                   timeout=timer.left())
    except (socket.timeout, TimeoutError):
        raise MailError('TIMEOUT', 'The mail server took too long to answer.')
    except (OSError, ssl.SSLError):
        raise MailError('CONNECTION', 'Could not connect to the mail server. Check the server name and port.')
    timer.step('connect')

    def guard():
        # The socket may wait only for the time that is left of the whole run
        if getattr(client, 'sock', None) is not None:
            client.sock.settimeout(timer.left())
        else:
            timer.left()

    try:
        # Every line read re-arms the socket timeout with what is left, so a long answer cannot pass the deadline
        for name in ('readline', 'read'):
            original = getattr(client, name, None)
            if original is not None:
                setattr(client, name, lambda *a, _f=original: (guard(), _f(*a))[1])
        guard()
        try:
            client.login(s['username'], s['password'])
        except imaplib.IMAP4.error:
            raise MailError('AUTH_FAILED', 'Login failed. Use an app password, not your normal password.')
        timer.step('login')
        guard()
        status, data = client.select(f'"{s["folder"]}"', readonly=True)
        if status != 'OK':
            raise MailError('PROTOCOL', f'Failed to select folder {s["folder"]}')
        timer.step('select')
        exists = int((data[0] or b'0').split()[0]) if data and data[0] else 0
        ids = search_newest(client, s, exists, timer, guard)
        timer.step('search')
        return read(client, ids, guard)
    except (socket.timeout, TimeoutError):
        raise MailError('TIMEOUT', 'The mail server took too long to answer.')
    except (imaplib.IMAP4.abort, OSError, ssl.SSLError):
        raise MailError('CONNECTION', 'Could not connect to the mail server. Check the server name and port.')
    finally:
        try:
            client.sock.settimeout(0.5)
            client.logout()
        except Exception:
            pass


def is_invitation(fetch_line):
    """A calendar invitation carries a text/calendar (.ics) part; BODYSTRUCTURE shows it without fetching it"""
    return bool(INVITE_STRUCTURE.search(fetch_line))


def fetch_texts(client, ids, size):
    """{id: (raw, flags)} with the headers needed to parse and the first size bytes of the text.
    BODY[]<0.N> would spend N on headers first: Gmail's Received/DKIM/ARC lines are often over 8 KB"""
    status, data = client.fetch(','.join(ids), f'(FLAGS BODY.PEEK[HEADER.FIELDS ({TEXT_HEADERS})] BODY.PEEK[TEXT]<0.{size}>)')
    if status != 'OK':
        raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
    found, current = {}, None
    for part in data:
        prefix = part[0] if isinstance(part, tuple) else part
        if not isinstance(prefix, bytes):
            continue
        if prefix[:1].isdigit():  # "12 (BODY[HEADER.FIELDS ...": a new message; later items continue it
            current = found.setdefault(prefix.split(b' ', 1)[0].decode(), {'meta': b'', 'header': b'', 'text': b''})
        if current is None:
            continue
        current['meta'] += prefix  # FLAGS may come before, between or after the literals
        if isinstance(part, tuple):
            current['header' if b'HEADER.FIELDS' in prefix.upper() else 'text'] = part[1]
    result = {}
    for msg_id, m in found.items():
        header = m['header'] if m['header'].endswith(b'\r\n\r\n') else m['header'].rstrip(b'\r\n') + b'\r\n\r\n'
        result[msg_id] = (header + m['text'], m['meta'], len(m['text']))
    return result


def read_message(client, msg_id, size, s, timer, guard, max_chars=MAX_BODY_CHARS):
    """One message parsed from the start of its text. A newsletter can spend the whole window on CSS in <head>:
    when that leaves no text and the window was full, the rest follows in one more piece, up to MORE_TEXT_BYTES"""
    guard()
    found = fetch_texts(client, [msg_id], size).get(msg_id)
    if not found:
        return None
    raw, flags, got = found
    message = parse_full_message(raw, flags, s['hide_quoted'], max_chars, me=s['username'])
    if len(message['body']) < STUB_CHARS and got >= size and timer.remaining() > TEXT_MARGIN:
        try:
            guard()
            status, data = client.fetch(msg_id, f'(BODY.PEEK[TEXT]<{size}.{MORE_TEXT_BYTES - size}>)')
        except (MailError, socket.timeout, TimeoutError):
            return message  # out of time for the rest: what the first piece gave beats a timeout
        more = next((part[1] for part in data if isinstance(part, tuple)), b'') if status == 'OK' else b''
        if more:
            fuller = parse_full_message(raw + more, flags, s['hide_quoted'], max_chars, me=s['username'])
            if len(fuller['body']) > len(message['body']):
                message = fuller
    return message


def add_snippets(client, messages, s, timer, guard):
    """List with preview: text for the newest entry first, one fetch each, the clock checked in between.
    When time runs short the rest show without text: the list without text beats a timeout"""
    result = list(messages)
    for index, m in enumerate(messages):
        if timer.remaining() < TEXT_MARGIN:
            break
        try:
            full = read_message(client, m['msg_id'], SNIPPET_BYTES, s, timer, guard, SNIPPET_CHARS)
        except (MailError, socket.timeout, TimeoutError):
            break  # the connection may be mid-answer: no further commands on it
        if full:
            result[index] = {**m, **{k: full[k] for k in ('body', 'paragraphs', 'truncated', 'has_attachments', 'encrypted')}}
    timer.step('fetch_text')
    return result


def fit_payload(data, limit=None):
    """TRMNL refuses plugin data over 100 KB: drop text from the oldest entries, then entries, until it fits"""
    limit = limit or PAYLOAD_TARGET

    def size():
        return len(json.dumps(data, ensure_ascii=False).encode('utf-8'))
    messages = data.get('messages') or []
    for m in reversed(messages):
        if size() <= limit:
            return data
        for key in ('body', 'paragraphs', 'markdown'):
            m.pop(key, None)
    while messages and size() > limit:
        messages.pop()
    m = data.get('message')
    while m and size() > limit and m.get('body'):
        # The text is in body, paragraphs and markdown: shorten in proportion, a little extra each round
        keep = int(len(m['body']) * limit / size() * 0.9)
        m['body'] = m['body'][:keep].rstrip() + '…' if keep > 0 else ''
        m['paragraphs'] = to_paragraphs(m['body'])
        m['markdown'] = to_markdown(m['body'])
        m['truncated'] = True
    if 'messages' in data:
        data['count'] = len(messages)
    return data


def _moment(timestamp):
    try:
        moment = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


SUBJECT_PREFIX = re.compile(r'^\s*((re|fw|fwd|aw|wg|antw|tr|sv|vs)\s*(\[\d+\])?\s*:\s*)+', re.I)
THREAD_ID = re.compile(rb'X-GM-THRID (\d+)')


def conversation_key(message):
    """Gmail's conversation id when there is one; else the subject without Re:/Fwd: and the like"""
    return message.get('thread') or SUBJECT_PREFIX.sub('', message['subject']).strip().lower()


def group_conversations(messages):
    """One row per conversation, newest first: the newest mail, its count, unread if any is, flagged if any is"""
    rows, by_key = [], {}
    for m in messages:  # newest first
        key = conversation_key(m)
        if key in by_key:
            row = by_key[key]
            row['count'] += 1
            row['read'] = row['read'] and m['read']
            row['flagged'] = row['flagged'] or m['flagged']
            continue
        by_key[key] = row = {**m, 'count': 1}
        rows.append(row)
    return rows


def fetch_headers(client, ids, s, guard, timer):
    """Sender, subject, date and flags of ids in one fetch, newest first; invitations left out when asked"""
    guard()
    fields = 'FROM SUBJECT DATE TO CC' if s['personal'] else 'FROM SUBJECT DATE'  # To/Cc only when shown
    thread = 'X-GM-THRID ' if s['threads'] and s['server'] == 'imap.gmail.com' else ''  # Gmail's conversation id
    what = f"(FLAGS {thread}{'BODYSTRUCTURE ' if s['hide_invites'] else ''}BODY.PEEK[HEADER.FIELDS ({fields})])"
    status, data = client.fetch(b','.join(ids).decode(), what)
    if status != 'OK':
        raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
    timer.step('fetch')
    parts = [part for part in data if isinstance(part, tuple)
             and not (s['hide_invites'] and is_invitation(part[0]))]
    me = s['username'] if s['personal'] else None
    messages = [parse_message(part[0].split(b' ', 1)[0].decode(), part[0], part[1], me) for part in parts]
    for part, m in zip(parts, messages):
        found = THREAD_ID.search(part[0])
        m['thread'] = found.group(1).decode() if found else None
    # By the moment, not the text: '13:31+02:00' is before '12:12+00:00' as text but after it in time
    messages = sorted(messages, key=lambda m: _moment(m['timestamp']), reverse=True)
    # Conversations: grouped within the mail fetched here, so no more mail is fetched than without them
    return group_conversations(messages) if s['threads'] else messages


def fetch_messages(s, timer):
    def read(client, ids, guard):
        # Hidden invitations would leave gaps: fetch some extra headers to fill the list
        ids = ids[-s['limit'] * 3:] if s['hide_invites'] else ids[-s['limit']:]
        if not ids:
            return []
        messages = fetch_headers(client, ids, s, guard, timer)[:s['limit']]
        if s['display'] == 'preview' and messages:
            messages = add_snippets(client, messages, s, timer, guard)
        return messages
    return read_mailbox(s, timer, read)


def newest_non_invitation(client, ids, guard):
    """The newest id among ids that is not a calendar invitation, as a one-item list (or empty)"""
    guard()
    status, data = client.fetch(b','.join(ids).decode(), '(BODYSTRUCTURE)')
    if status != 'OK':
        raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
    lines = [part[0] if isinstance(part, tuple) else part for part in data if part]
    plain = {line.split(b' ', 1)[0] for line in lines if isinstance(line, bytes) and not is_invitation(line)}
    return [i for i in ids if i in plain][-1:]


def fetch_latest(s, timer):
    """The newest message with its text, and the ones before it as rows for the space a short message leaves"""
    def read(client, ids, guard):
        main = newest_non_invitation(client, ids[-INVITE_LOOKBACK:], guard) if s['hide_invites'] and ids else ids[-1:]
        if not main:
            return None, []
        guard()
        # BODY.PEEK keeps the message unread; <0.N> fetches only its start
        message = read_message(client, main[0].decode(), FETCH_BYTES, s, timer, guard)
        timer.step('fetch')
        if not message:
            return None, []
        # Rows: never more than the list would fetch, the message itself included
        rows = min(LATEST_OTHERS, s['limit'] - 1)
        before = [i for i in ids if int(i) < int(main[0])][-rows * (3 if s['hide_invites'] else 1):] if rows > 0 else []
        others = []
        if before and timer.remaining() > TEXT_MARGIN:
            try:
                others = fetch_headers(client, before, s, guard, timer)
                if s['threads']:
                    # Mails of the open conversation count toward its badge instead of showing as rows
                    open_key = conversation_key(message)
                    same = [o for o in others if conversation_key(o) == open_key]
                    message['count'] = 1 + sum(o['count'] for o in same)
                    others = [o for o in others if conversation_key(o) != open_key]
                others = others[:rows]
            except (MailError, socket.timeout, TimeoutError):
                others = []  # the message without the rows beats a timeout
        return message, others
    return read_mailbox(s, timer, read)


def fetch_combined(s, timer):
    """List with the latest message: the list, and the newest with its text for the right panel"""
    def read(client, ids, guard):
        # The open message is the list's first row: N messages in all, as many as the plain list fetches
        ids = ids[-s['limit'] * 3:] if s['hide_invites'] else ids[-s['limit']:]
        if not ids:
            return None, []
        messages = fetch_headers(client, ids, s, guard, timer)[:s['limit']]
        if not messages:
            return None, []
        newest = messages[0]
        message = None
        if timer.remaining() > TEXT_MARGIN:
            try:
                found = read_message(client, newest['msg_id'], FETCH_BYTES, s, timer, guard)
                if found:
                    message = {**found, 'msg_id': newest['msg_id'], 'count': newest.get('count', 1)}
            except (MailError, socket.timeout, TimeoutError):
                message = None
            timer.step('fetch_text')
        # Short of time: the newest still shows, by its sender and subject. The list keeps the newest as its
        # first row, marked as the open one, as a mail client does
        rows = messages[:s['limit']]
        if s['previews'] and len(rows) > 1:
            # Show Previews: text under the other rows; the open one has its full text in the panel
            rows = rows[:1] + add_snippets(client, rows[1:], s, timer, guard)
        return message or {**newest, 'body': '', 'paragraphs': [], 'markdown': ''}, rows
    return read_mailbox(s, timer, read)


def run(input):
    timer = Timer()
    trmnl = input.get('trmnl') or {}
    previous = trmnl.get('previous_merge_variables') or {}
    values = (trmnl.get('plugin_settings') or {}).get('custom_fields_values') or {}
    try:
        demo = (values.get('email') or '').strip().lower() == DEMO_ACCOUNT
        if demo:  # the password field may be empty for TRMNL's demo account
            values = {**values, 'provider': 'gmail', 'gmail_password': 'demo'}
        s = _settings(values)
        if demo:
            demo_inbox = input.get('demo_inbox') or {}
            message, messages = demo_data(s, demo_inbox)
            data = {'success': True, 'display': s['display'], 'email': demo_inbox.get('address', DEMO_ACCOUNT), 'folder': s['folder'],
                    'unread_only': s['unread_only'], 'flagged_only': s['flagged_only'], 'demo': True}
            if s['display'] == 'latest':
                data['message'], data['others'] = message, messages
            else:
                data['messages'], data['count'] = messages, len(messages)
                if s['display'] == 'combined':
                    data['message'] = message
            data['timing'] = timer.report()
            return {'data': data}
        data = {'success': True, 'display': s['display'], 'email': s['username'], 'folder': s['folder'],
                'unread_only': s['unread_only'], 'flagged_only': s['flagged_only']}
        if s['display'] == 'latest':
            data['message'], data['others'] = fetch_latest(s, timer)
        elif s['display'] == 'combined':
            data['message'], data['messages'] = fetch_combined(s, timer)
            data['count'] = len(data['messages'])
        else:
            data['messages'] = fetch_messages(s, timer)
            data['count'] = len(data['messages'])
        if s['gmail_category']:
            data['gmail_category'] = s['gmail_category']
        fit_payload(data)
        data['timing'] = timer.report()
        return {'data': data}
    except MailError as e:
        code, message = e.code, e.message
    except Exception:
        code, message = 'UNEXPECTED_ERROR', 'Something went wrong while reading your mail.'
    timing = timer.report()
    # Errors that pass on their own keep the last mail on screen, marked with this run's code and timing
    previous_data = previous.get('data') or {}
    if code in KEEP_PREVIOUS and (isinstance(previous_data.get('messages'), list) or previous_data.get('message')):
        return {**previous, 'data': {**previous_data, 'timing': timing, 'stale_reason': code}}
    return {'data': {'success': False, 'code': code, 'error': code.replace('_', ' ').title(),
                     'message': message, 'timing': timing}}
