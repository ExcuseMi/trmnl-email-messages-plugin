# TRMNL serverless (Python): reads mail over IMAP inside TRMNL's sandbox, so the app password
# never leaves TRMNL except to the mail server itself. Two displays share one mailbox reader:
# a list of the latest headers, or the latest message with its text.
# Standard library only (imaplib, ssl, email, html.parser): the sandbox offers no extra packages.
# Never loads images or links from a mail (tracking pixels); text only.

import email
import email.policy
import imaplib
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

SERVERS = {
    'gmail': ('imap.gmail.com', 993, 'gmail_password'),
    'outlook': ('outlook.office365.com', 993, 'outlook_password'),
    'yahoo': ('imap.mail.yahoo.com', 993, 'yahoo_password'),
    'icloud': ('imap.mail.me.com', 993, 'icloud_password'),
}
MAX_MESSAGES = 50
DEADLINE_SECONDS = 4.0  # TRMNL stops a run after 5 s; the rest is margin for parsing and the return
KEEP_PREVIOUS = {'TIMEOUT', 'CONNECTION', 'PROTOCOL', 'UNEXPECTED_ERROR'}
UNSAFE_CHARS = set('"\\\r\n\0')
FETCH_BYTES = 64 * 1024  # latest message: only its start, the text comes before attachments
MAX_BODY_CHARS = 3000  # more never fits a screen; keeps the plugin data small
INVITE_STRUCTURE = re.compile(rb'"(text" "calendar|application" "ics)"', re.I)  # an .ics part in BODYSTRUCTURE
INVITE_LOOKBACK = 10  # latest message: how many recent ones to check for a non-invitation
ENCRYPTED_TYPES = {'multipart/encrypted', 'application/pkcs7-mime', 'application/x-pkcs7-mime', 'application/pgp-encrypted'}


class MailError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


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
        'unread_only': values.get('unread_only') == 'yes',
        'flagged_only': values.get('flagged_only') == 'yes',
        'gmail_category': (values.get('gmail_category') or '') if provider == 'gmail' else '',
        'from_emails': [e.strip() for e in from_emails if e and e.strip()],
        'display': 'latest' if values.get('display') == 'latest' else 'list',
        'hide_quoted': values.get('hide_quoted', 'yes') != 'no',
        'hide_invites': values.get('hide_invitations') == 'yes',
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


def parse_message(msg_id, flags, header_bytes):
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
    }


class _TextFromHtml(HTMLParser):
    """HTML to plain text: paragraphs kept, styles, scripts and images dropped"""
    BLOCKS = {'p', 'div', 'br', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'section', 'article', 'blockquote'}
    SKIP = {'style', 'script', 'head', 'title', 'noscript'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skipping = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skipping += 1
        elif tag in self.BLOCKS:
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skipping = max(0, self.skipping - 1)
        elif tag in self.BLOCKS:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.skipping:
            self.parts.append(re.sub(r'[ \t\r\n]+', ' ', data))


def html_to_text(html):
    parser = _TextFromHtml()
    parser.feed(html)
    parser.close()
    return ''.join(parser.parts)


QUOTE_HEADER = re.compile(r'^(On .{3,200} wrote:|Op .{3,200} schreef .{1,100}:|-{2,} ?Original Message ?-{2,}|From: .+)$', re.I)


def clean_text(text, hide_quoted=True):
    lines = [line.rstrip() for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n')]
    kept = []
    for line in lines:
        if hide_quoted and (line in ('-- ', '--') or QUOTE_HEADER.match(line.strip())):
            break  # signature or the start of the quoted earlier message
        if hide_quoted and line.lstrip().startswith('>'):
            continue
        kept.append(line.replace(' ', ' ').strip())
    text = re.sub(r'\n{3,}', '\n\n', '\n'.join(kept)).strip()
    return text


def _part_text(part):
    payload = part.get_payload(decode=True) or b''
    charset = part.get_content_charset() or 'utf-8'
    try:
        return payload.decode(charset, errors='replace')
    except LookupError:
        return payload.decode('utf-8', errors='replace')


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
    text = plain if plain and plain.strip() else html_to_text(html or '')
    return clean_text(text, hide_quoted), attachments, False


def parse_full_message(raw, flags, hide_quoted=True):
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    name, address = parseaddr(_decode(msg.get('From', '')))
    try:
        timestamp = parsedate_to_datetime(msg.get('Date', '')).isoformat()
    except (TypeError, ValueError, IndexError):
        timestamp = datetime.now(timezone.utc).isoformat()
    body, attachments, encrypted = extract_body(msg, hide_quoted)
    truncated = len(body) > MAX_BODY_CHARS
    body = body[:MAX_BODY_CHARS].rstrip() + ('…' if truncated else '')
    return {
        'sender': name or address or 'Unknown',
        'sender_email': address,
        'subject': _decode(msg.get('Subject', '')) or 'No Subject',
        'timestamp': timestamp,
        'read': b'\\Seen' in flags,
        'flagged': b'\\Flagged' in flags,
        'body': body,
        # Paragraphs for the markup's <p> elements; a single line break stays inside a paragraph
        'paragraphs': [p.strip() for p in re.split(r'\n\s*\n', body) if p.strip()],
        'truncated': truncated,
        'has_attachments': attachments,
        'encrypted': encrypted,
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

    def step(self, name):
        now = time.monotonic()
        self.steps[name] = round((now - self.mark) * 1000)
        self.mark = now

    def report(self):
        return {'steps_ms': dict(self.steps), 'total_ms': round((time.monotonic() - self.started) * 1000),
                'limit_ms': round(self.deadline * 1000)}


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
        guard()
        try:
            client.login(s['username'], s['password'])
        except imaplib.IMAP4.error:
            raise MailError('AUTH_FAILED', 'Login failed. Use an app password, not your normal password.')
        timer.step('login')
        guard()
        status, _ = client.select(f'"{s["folder"]}"', readonly=True)
        if status != 'OK':
            raise MailError('PROTOCOL', f'Failed to select folder {s["folder"]}')
        timer.step('select')
        guard()
        status, data = client.search(None, search_criteria(s))
        if status != 'OK':
            raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
        timer.step('search')
        return read(client, (data[0] or b'').split(), guard)
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


def fetch_messages(s, timer):
    def read(client, ids, guard):
        # Hidden invitations would leave gaps: fetch some extra headers to fill the list
        ids = ids[-s['limit'] * 3:] if s['hide_invites'] else ids[-s['limit']:]
        if not ids:
            return []
        guard()
        what = '(FLAGS BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])' if s['hide_invites'] \
            else '(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])'
        status, data = client.fetch(b','.join(ids).decode(), what)
        if status != 'OK':
            raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
        timer.step('fetch')
        messages = [parse_message(part[0].split(b' ', 1)[0].decode(), part[0], part[1])
                    for part in data if isinstance(part, tuple)
                    and not (s['hide_invites'] and is_invitation(part[0]))]
        return sorted(messages, key=lambda m: m['timestamp'], reverse=True)[:s['limit']]
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
    def read(client, ids, guard):
        if s['hide_invites'] and ids:
            ids = newest_non_invitation(client, ids[-INVITE_LOOKBACK:], guard)
        if not ids:
            return None
        guard()
        # BODY.PEEK keeps the message unread; <0.N> fetches only its start
        status, data = client.fetch(ids[-1].decode(), f'(FLAGS BODY.PEEK[]<0.{FETCH_BYTES}>)')
        if status != 'OK':
            raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
        timer.step('fetch')
        part = next((p for p in data if isinstance(p, tuple)), None)
        if part is None:
            return None
        message = parse_full_message(part[1], part[0], s['hide_quoted'])
        timer.step('parse')
        return message
    return read_mailbox(s, timer, read)


def run(input):
    timer = Timer()
    trmnl = input.get('trmnl') or {}
    previous = trmnl.get('previous_merge_variables') or {}
    values = (trmnl.get('plugin_settings') or {}).get('custom_fields_values') or {}
    try:
        s = _settings(values)
        data = {'success': True, 'display': s['display'], 'email': s['username'], 'folder': s['folder'],
                'unread_only': s['unread_only'], 'flagged_only': s['flagged_only']}
        if s['display'] == 'latest':
            data['message'] = fetch_latest(s, timer)
        else:
            data['messages'] = fetch_messages(s, timer)
            data['count'] = len(data['messages'])
        data['timing'] = timer.report()
        if s['gmail_category']:
            data['gmail_category'] = s['gmail_category']
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
