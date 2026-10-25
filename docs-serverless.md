# Serverless variant (branch `serverless`)

The mail is read inside TRMNL's serverless sandbox (`plugin/src/transform.py`), so no backend is needed and the app password goes only to the mail server.

## What it needs from TRMNL

| Need | Status |
|---|---|
| Python runtime with `imaplib`, `ssl`, `email` (standard library) | Python is offered; stdlib modules assumed available, not yet confirmed |
| Outgoing TCP + TLS to port 993 (and custom IMAP ports) | **unknown**: docs only say "network access is included" and show HTTP examples |
| `imaplib.IMAP4_SSL(..., timeout=)` needs Python 3.9+ | Python version not documented |
| Finish within 5 s (login, select, search, fetch headers) | about 0.1 to 1.5 s for Gmail from a normal network |
| Strategy `static` running the serverless code on every refresh | assumed from the docs (Polling, Webhook; saved state also lists Static) |

Node is not an option: the sandbox has `fetch()` but no `require` and no TLS sockets, and an IMAP library (e.g. `imapflow`) would have to be added by TRMNL by hand.

## How to find out

1. Create a private plugin, paste `transform.py` in the Serverless tab (language Python), set the form fields, enable Debug Logs.
2. Force refresh. A `CONNECTION` or `TIMEOUT` error with a correct password means outgoing port 993 is blocked: ask TRMNL whether IMAP (port 993) can be allowed.

Tests: `python3 -m pytest plugin/test` (fake IMAP server).
