# Answers in the shape a real IMAP server sends through imaplib (checked against Dovecot 2.3, 2026-10-25)
import json
import pathlib
import re

import yaml

# The static data TRMNL passes into every run, from the plugin's settings.yml
STATIC_DATA = json.loads(yaml.safe_load((pathlib.Path(__file__).resolve().parents[1] / 'src' / 'settings.yml').read_text())['static_data'])


def _split(raw):
    cut = raw.find(b'\r\n\r\n')
    if cut < 0:
        cut = raw.find(b'\n\n')
        return (raw, b'') if cut < 0 else (raw[:cut + 2], raw[cut + 2:])
    return raw[:cut + 4], raw[cut + 4:]


def header_fields(header, names):
    """Only the named header fields (with their folded lines), ending in the blank line"""
    kept, keep = [], False
    for line in header.splitlines(keepends=True):
        if line[:1] in (b' ', b'\t'):
            if keep:
                kept.append(line)
            continue
        keep = line.split(b':', 1)[0].strip().upper().decode(errors='ignore') in names
        if keep:
            kept.append(line)
    return b''.join(kept) + b'\r\n'


def answer(msg_id, raw, flags, what):
    """imaplib's fetch data for one message and the items in what"""
    partial = re.search(r'BODY\.PEEK\[\]<0\.(\d+)>', what)
    if partial:
        return [(f'{msg_id} (FLAGS ({flags}) BODY[]<0> {{9}}'.encode(), raw[:int(partial.group(1))]), b')']
    more = re.fullmatch(r'\(BODY\.PEEK\[TEXT\]<(\d+)\.(\d+)>\)', what)
    if more:  # a follow-up piece of the text, without headers
        start, size = int(more.group(1)), int(more.group(2))
        return [(f'{msg_id} (BODY[TEXT]<{start}> {{9}}'.encode(), _split(raw)[1][start:start + size]), b')']
    fields = re.search(r'BODY\.PEEK\[HEADER\.FIELDS \(([^)]*)\)\]', what)
    text = re.search(r'BODY\.PEEK\[TEXT\]<0\.(\d+)>', what)
    header, body = _split(raw)
    parts = [(f'{msg_id} (FLAGS ({flags}) BODY[HEADER.FIELDS ({fields.group(1)})] {{9}}'.encode(),
              header_fields(header, set(fields.group(1).split())))]
    if text:
        parts.append((b' BODY[TEXT]<0> {9}', body[:int(text.group(1))]))
    return parts + [b')']
