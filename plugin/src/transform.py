# TRMNL serverless (Python): reads the latest mail headers over IMAP inside TRMNL's sandbox,
# so the app password never leaves TRMNL except to the mail server itself.
# Standard library only (imaplib, ssl, email): TRMNL's sandbox offers no extra packages.
# Open question this branch exists to answer: does the sandbox allow outgoing TCP to port 993?

import email
import imaplib
import socket
import ssl
import time
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime

SERVERS = {
    'gmail': ('imap.gmail.com', 993, 'gmail_password'),
    'outlook': ('outlook.office365.com', 993, 'outlook_password'),
    'yahoo': ('imap.mail.yahoo.com', 993, 'yahoo_password'),
    'icloud': ('imap.mail.me.com', 993, 'icloud_password'),
}
MAX_MESSAGES = 50
DEADLINE_SECONDS = 4.0  # TRMNL stops a run after 5 s
KEEP_PREVIOUS = {'TIMEOUT', 'CONNECTION', 'PROTOCOL', 'UNEXPECTED_ERROR'}
UNSAFE_CHARS = set('"\\\r\n\0')


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


def fetch_messages(s):
    started = time.monotonic()

    def left():
        remaining = DEADLINE_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise MailError('TIMEOUT', 'The mail server took too long to answer.')
        return remaining

    try:
        client = imaplib.IMAP4_SSL(s['server'], s['port'], ssl_context=ssl.create_default_context(), timeout=left())
    except (socket.timeout, TimeoutError):
        raise MailError('TIMEOUT', 'The mail server took too long to answer.')
    except (OSError, ssl.SSLError):
        raise MailError('CONNECTION', 'Could not connect to the mail server. Check the server name and port.')
    try:
        try:
            client.login(s['username'], s['password'])
        except imaplib.IMAP4.error:
            raise MailError('AUTH_FAILED', 'Login failed. Use an app password, not your normal password.')
        left()
        status, _ = client.select(f'"{s["folder"]}"', readonly=True)
        if status != 'OK':
            raise MailError('PROTOCOL', f'Failed to select folder {s["folder"]}')
        status, data = client.search(None, search_criteria(s))
        if status != 'OK':
            raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
        ids = (data[0] or b'').split()[-s['limit']:]
        if not ids:
            return []
        left()
        status, data = client.fetch(b','.join(ids).decode(), '(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
        if status != 'OK':
            raise MailError('PROTOCOL', 'The mail server gave an unexpected answer.')
        messages = [parse_message(part[0].split(b' ', 1)[0].decode(), part[0], part[1])
                    for part in data if isinstance(part, tuple)]
        return sorted(messages, key=lambda m: m['timestamp'], reverse=True)
    except (socket.timeout, TimeoutError):
        raise MailError('TIMEOUT', 'The mail server took too long to answer.')
    except (imaplib.IMAP4.abort, OSError, ssl.SSLError):
        raise MailError('CONNECTION', 'Could not connect to the mail server. Check the server name and port.')
    finally:
        try:
            client.logout()
        except Exception:
            pass


def run(input):
    trmnl = input.get('trmnl') or {}
    previous = trmnl.get('previous_merge_variables') or {}
    values = (trmnl.get('plugin_settings') or {}).get('custom_fields_values') or {}
    try:
        s = _settings(values)
        messages = fetch_messages(s)
        data = {'success': True, 'email': s['username'], 'folder': s['folder'], 'count': len(messages),
                'unread_only': s['unread_only'], 'flagged_only': s['flagged_only'], 'messages': messages}
        if s['gmail_category']:
            data['gmail_category'] = s['gmail_category']
        return {'data': data}
    except MailError as e:
        # Errors that pass on their own keep the last mail on screen
        if e.code in KEEP_PREVIOUS and isinstance((previous.get('data') or {}).get('messages'), list):
            return previous
        return {'data': {'success': False, 'code': e.code, 'error': e.code.replace('_', ' ').title(),
                         'message': e.message}}
    except Exception:
        if isinstance((previous.get('data') or {}).get('messages'), list):
            return previous
        return {'data': {'success': False, 'code': 'UNEXPECTED_ERROR', 'error': 'Unexpected Error',
                         'message': 'Something went wrong while reading your mail.'}}
