"""
Email Reader - Flask Backend for TRMNL
"""

from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import time
import os
from functools import wraps
import asyncio
import httpx
import threading
import logging
import sys
import json
import uuid
import warnings
from typing import Optional

from modules.providers.imap_provider import (
    IMAPProvider,
    IMAPAuthenticationError,
    IMAPConnectionError,
    IMAPProtocolError,
    IMAPTimeoutError
)
from modules.utils.cache import CacheManager
from modules.utils.security import credential_hash, check_mail_server, client_ip
from modules.utils.login_limit import LoginLimiter

warnings.filterwarnings('ignore', category=ResourceWarning)

# Configuration
ENABLE_IP_WHITELIST = os.getenv('ENABLE_IP_WHITELIST', 'true').lower() == 'true'
IP_REFRESH_HOURS = int(os.getenv('IP_REFRESH_HOURS', '24'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
ENABLE_CACHE = os.getenv('ENABLE_CACHE', 'true').lower() == 'true'
CACHE_TTL_SECONDS = int(os.getenv('CACHE_TTL_SECONDS', '300'))
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_DB = int(os.getenv('REDIS_DB', '0'))
IMAP_CONNECT_TIMEOUT = int(os.getenv('IMAP_CONNECT_TIMEOUT', '10'))
IMAP_LOGIN_TIMEOUT = int(os.getenv('IMAP_LOGIN_TIMEOUT', '15'))
IMAP_FETCH_TIMEOUT = int(os.getenv('IMAP_FETCH_TIMEOUT', '30'))
MAX_MESSAGES_LIMIT = int(os.getenv('MAX_MESSAGES_LIMIT', '50'))

TRMNL_IPS_API = 'https://trmnl.com/api/ips'

log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), handlers=[log_handler], force=True)
logger = logging.getLogger(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('hypercorn.access').setLevel(logging.ERROR)
logging.getLogger('hypercorn.error').setLevel(logging.WARNING)
# Its debug output holds the IMAP LOGIN line with the password: never below WARNING
logging.getLogger('aioimaplib').setLevel(logging.WARNING)

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

TRMNL_IPS = set()
TRMNL_IPS_LOCK = threading.Lock()
last_ip_refresh = None
LOCALHOST_IPS = ['127.0.0.1', '::1']

imap_provider = IMAPProvider(
    connect_timeout=IMAP_CONNECT_TIMEOUT,
    login_timeout=IMAP_LOGIN_TIMEOUT,
    fetch_timeout=IMAP_FETCH_TIMEOUT
)
cache_manager = None  # Initialized in startup
login_limiter = LoginLimiter()  # Redis-backed after startup


def mask_email(email_addr):
    if not email_addr or '@' not in email_addr:
        return email_addr[:1] + "***" if email_addr else ""
    if email_addr.startswith('@'):
        return email_addr
    local, domain = email_addr.split('@', 1)
    return f"{local[0]}***@{domain}"


def format_auth_error(email_addr, error_message, is_oauth=False):
    if is_oauth:
        return (
            "OAuth authentication failed. Please check that:\n"
            "1. Your OAuth connection in TRMNL is still valid\n"
            "2. The required scopes are granted\n"
            "3. Your email provider supports OAuth2\n"
            "You may need to reconnect your account in TRMNL settings."
        )
    domain = email_addr.lower().split('@')[-1] if '@' in email_addr else ''
    base_msg = "Unable to connect to your email account. "
    if 'gmail.com' in domain:
        return base_msg + "For Gmail, use an App Password from https://myaccount.google.com/apppasswords"
    elif 'outlook' in domain or 'hotmail' in domain or 'live.com' in domain:
        return base_msg + "For Outlook/Hotmail, enable IMAP and use an App Password."
    elif 'yahoo.com' in domain:
        return base_msg + "For Yahoo, generate an App Password from https://login.yahoo.com/account/security"
    elif 'icloud.com' in domain:
        return base_msg + "For iCloud, use an App-Specific Password from https://appleid.apple.com"
    return base_msg + "Many providers require App Passwords instead of regular passwords."


async def fetch_trmnl_ips():
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(TRMNL_IPS_API)
            response.raise_for_status()
            data = response.json()
            ipv4_list = data.get('data', {}).get('ipv4', [])
            ipv6_list = data.get('data', {}).get('ipv6', [])
            ips = set(ipv4_list + ipv6_list + LOCALHOST_IPS)
            logger.info(f"✓ Loaded {len(ips)} TRMNL IPs")
            return ips
    except Exception as e:
        logger.error(f"✗ Failed to fetch TRMNL IPs: {e}")
        return set(LOCALHOST_IPS)


def update_trmnl_ips_sync():
    global TRMNL_IPS, last_ip_refresh
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            ips = loop.run_until_complete(fetch_trmnl_ips())
            with TRMNL_IPS_LOCK:
                TRMNL_IPS = ips
                last_ip_refresh = datetime.now()
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"✗ IP refresh error: {e}")


def ip_refresh_worker():
    while True:
        try:
            time.sleep(IP_REFRESH_HOURS * 3600)
            update_trmnl_ips_sync()
        except Exception as e:
            logger.error(f"✗ IP refresh worker error: {e}")
            time.sleep(3600)


def start_ip_refresh_worker():
    if not ENABLE_IP_WHITELIST:
        return
    threading.Thread(target=ip_refresh_worker, daemon=True, name='IP-Refresh-Worker').start()
    logger.info(f"✓ IP refresh worker started (every {IP_REFRESH_HOURS}h)")


def get_client_ip():
    return client_ip(request.headers, request.remote_addr)


def require_whitelisted_ip(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not ENABLE_IP_WHITELIST:
            return await f(*args, **kwargs)
        client_ip = get_client_ip()
        with TRMNL_IPS_LOCK:
            allowed_ips = TRMNL_IPS.copy()
        if client_ip not in allowed_ips:
            logger.warning(f"🚫 Blocked unauthorized IP: {client_ip}")
            return jsonify({'error': 'Access denied', 'message': 'Your IP address is not authorized'}), 403
        return await f(*args, **kwargs)
    return decorated_function


def public_error_message(e):
    """One fixed text per kind, so error details never act as a probe of other hosts"""
    if isinstance(e, IMAPConnectionError):
        return 'Could not connect to the mail server. Check the server name and port.'
    if isinstance(e, IMAPTimeoutError):
        return 'The mail server took too long to answer.'
    if isinstance(e, IMAPProtocolError) and str(e).startswith('Failed to select folder'):
        return str(e)
    if isinstance(e, IMAPProtocolError):
        return 'The mail server gave an unexpected answer.'
    return 'Something went wrong while reading your mail.'


def validate_params(data) -> Optional[str]:
    """Return an error message for a malformed request, else None"""
    for key in ('server', 'username', 'password', 'oauth_access_token', 'folder', 'gmail_category'):
        if data.get(key) is not None and not isinstance(data[key], str):
            return f'{key} must be a string'
    for key in ('port', 'limit'):
        if data.get(key) is not None and (isinstance(data[key], bool) or not isinstance(data[key], int)):
            return f'{key} must be a number'
    from_emails = data.get('from_emails')
    # These go into IMAP commands: a quote or line break would add commands of the caller's choosing
    for value in [data.get('folder'), data.get('gmail_category')] + (
            from_emails if isinstance(from_emails, list) else [from_emails]):
        if isinstance(value, str) and any(c in value for c in '"\\\r\n\0'):
            return 'folder, gmail_category and from_emails must not contain quotes, backslashes or line breaks'
    if from_emails is not None and not isinstance(from_emails, (str, list)):
        return 'from_emails must be a string or a list'
    if isinstance(from_emails, list) and not all(isinstance(e, str) for e in from_emails):
        return 'from_emails must hold strings'
    return None


def load_mock_data():
    try:
        with open('mock-data.json', 'r') as f:
            mock_data = json.load(f)
        now = datetime.now()
        for message in mock_data['messages']:
            ts = message['timestamp']
            if ts == 'TODAY':
                message['timestamp'] = now.isoformat()
            elif ts.startswith('TODAY-'):
                hours = int(ts.split('-')[1].replace('h', ''))
                message['timestamp'] = (now - timedelta(hours=hours)).isoformat()
            elif ts == 'YESTERDAY':
                message['timestamp'] = (now - timedelta(days=1)).isoformat()
            elif ts.startswith('YESTERDAY-'):
                hours = int(ts.split('-')[1].replace('h', ''))
                message['timestamp'] = (now - timedelta(days=1, hours=hours)).isoformat()
            elif ts.endswith('DAYS'):
                days = int(ts.replace('DAYS', ''))
                message['timestamp'] = (now - timedelta(days=days)).isoformat()
            elif 'DAYS-' in ts:
                parts = ts.split('-')
                days = int(parts[0].replace('DAYS', ''))
                hours = int(parts[1].replace('h', ''))
                message['timestamp'] = (now - timedelta(days=days, hours=hours)).isoformat()
        mock_data['fetched_at'] = now.isoformat()
        return mock_data
    except Exception as e:
        logger.error(f"✗ Mock data error: {e}")
        return None


# ---------------------------------------------------------------------------
# Core fetch logic
# ---------------------------------------------------------------------------

async def _fetch_messages(params: dict, request_id: str) -> dict:
    server = params.get('server')
    username = params.get('username')
    password = params.get('password')
    oauth_token = params.get('oauth_access_token')
    port = params.get('port', 993)
    folder = params.get('folder', 'INBOX')
    limit = min(max(params.get('limit', 10), 1), MAX_MESSAGES_LIMIT)

    gmail_category = params.get('gmail_category')

    unread_only = params.get('unread_only', False)
    if isinstance(unread_only, str):
        unread_only = unread_only.lower() == 'true'

    flagged_only = params.get('flagged_only', False)
    if isinstance(flagged_only, str):
        flagged_only = flagged_only.lower() == 'true'

    from_emails = params.get('from_emails', [])
    if isinstance(from_emails, str):
        from_emails = [e.strip() for e in from_emails.split(',') if e.strip()]
    elif not isinstance(from_emails, list):
        from_emails = []

    masked_username = mask_email(username)
    auth_method = "OAuth" if oauth_token else "Password"

    filters = []
    if gmail_category:
        filters.append(f"category={gmail_category}")
    if unread_only:
        filters.append("unread")
    if flagged_only:
        filters.append("flagged")
    if from_emails:
        filters.append(f"from={len(from_emails)} senders")
    filter_str = f" ({', '.join(filters)})" if filters else ""
    logger.info(f"[{request_id}] 📨 {masked_username} ({auth_method}) → {folder} (limit={limit}){filter_str}")

    if username == 'master@trmnl.com':
        logger.info(f"[{request_id}] 🎭 Returning mock data")
        return load_mock_data() or {'error': 'Failed to load mock data'}

    server_error = await check_mail_server(server, port)
    if server_error:
        logger.warning(f"[{request_id}] 🚫 {server_error}")
        return {'success': False, 'error': 'Invalid Server', 'message': server_error, 'code': 'INVALID_SERVER'}

    credential = credential_hash(password, oauth_token)
    account = LoginLimiter.account_key(server, username)
    cache_params = {
        'provider': 'imap', 'server': server, 'port': port, 'username': username,
        'auth_type': 'oauth' if oauth_token else 'password',
        'credential': credential,
        'folder': folder, 'limit': limit, 'unread_only': unread_only,
        'flagged_only': flagged_only, 'gmail_category': gmail_category,
        'from_emails': sorted(from_emails) if from_emails else []
    }
    cache_key = cache_manager.generate_key('imap', cache_params)

    cached_response = cache_manager.get(cache_key)
    if cached_response:
        logger.info(f"[{request_id}] 💾 Cache HIT")
        return cached_response

    limited = login_limiter.blocked(account, credential)
    if limited:
        logger.warning(f"[{request_id}] 🚫 Login limit for {masked_username}")
        return {'success': False, 'error': 'Too Many Failed Logins', 'message': limited,
                'code': 'TOO_MANY_FAILURES'}

    try:
        messages = await imap_provider.fetch_messages(
            server=server, port=port, username=username, password=password,
            folder=folder, limit=limit, unread_only=unread_only,
            flagged_only=flagged_only, gmail_category=gmail_category,
            from_emails=from_emails, oauth_token=oauth_token, request_id=request_id
        )
        response_data = {
            'success': True, 'provider': 'imap', 'email': username,
            'folder': folder, 'count': len(messages), 'unread_only': unread_only,
            'flagged_only': flagged_only, 'messages': messages,
            'fetched_at': datetime.now().isoformat(), 'auth_method': auth_method
        }
        if gmail_category:
            response_data['gmail_category'] = gmail_category
        if from_emails:
            response_data['from_emails'] = from_emails
        cache_manager.set(cache_key, response_data)
        login_limiter.succeeded(account, credential)
        return response_data

    except IMAPAuthenticationError as e:
        login_limiter.failed(account)
        cached_fallback = cache_manager.get(cache_key)
        is_oauth = bool(oauth_token)
        if cached_fallback:
            logger.warning(f"[{request_id}] 🔒 Auth failed ({auth_method}), returning stale cache")
            cached_fallback.update({
                'success': False, 'cached': True,
                'cache_warning': 'Authentication failed - returning cached data',
                'error': {
                    'message': format_auth_error(username, str(e), is_oauth),
                    'type': 'AUTH_FAILED', 'auth_method': auth_method,
                    'occurred_at': datetime.now().isoformat()
                }
            })
            return cached_fallback
        logger.warning(f"[{request_id}] 🔒 Auth failed ({auth_method}) for {masked_username} (no cache)")
        return {
            'success': False, 'error': 'Authentication Failed',
            'message': format_auth_error(username, str(e), is_oauth),
            'code': 'AUTH_FAILED', 'auth_method': auth_method, 'email': username
        }

    except (IMAPTimeoutError, IMAPConnectionError, IMAPProtocolError) as e:
        error_type = type(e).__name__
        cached_fallback = cache_manager.get(cache_key)
        if cached_fallback:
            logger.warning(f"[{request_id}] ⚠️  {error_type}, returning stale cache")
            cached_fallback.update({
                'success': False, 'cached': True,
                'cache_warning': f'{error_type} - returning cached data',
                'error': {
                    'message': public_error_message(e),
                    'type': error_type.replace('IMAP', '').replace('Error', '').upper(),
                    'occurred_at': datetime.now().isoformat()
                }
            })
            return cached_fallback
        logger.error(f"[{request_id}] ✗ {error_type}: {e} (no cache)")
        return {
            'success': False,
            'error': error_type.replace('IMAP', '').replace('Error', ''),
            'message': public_error_message(e),
            'code': error_type.replace('IMAP', '').replace('Error', '').upper()
        }

    except Exception as e:
        cached_fallback = cache_manager.get(cache_key)
        if cached_fallback:
            logger.warning(f"[{request_id}] ⚠️  Unexpected error, returning stale cache")
            cached_fallback.update({
                'success': False, 'cached': True,
                'error': {'message': public_error_message(e), 'type': 'UNEXPECTED_ERROR',
                          'occurred_at': datetime.now().isoformat()}
            })
            return cached_fallback
        logger.error(f"[{request_id}] ✗ Unexpected error: {e}")
        return {'success': False, 'error': 'Unexpected Error', 'message': public_error_message(e),
                'code': 'UNEXPECTED_ERROR'}


def _extract_params(req) -> dict:
    return dict(req.get_json(silent=True) or {})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

MAX_REQUEST_BYTES = 64 * 1024


def create_app():
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BYTES
    register_routes(app)
    return app


def register_routes(app):

    @app.route('/messages', methods=['POST'])
    @app.route('/imap/messages', methods=['POST'])
    @require_whitelisted_ip
    async def get_messages():
        request_id = str(uuid.uuid4())[:8]
        data = _extract_params(request)
        invalid = validate_params(data)
        if invalid:
            return jsonify({'error': 'Invalid parameters', 'message': invalid}), 400

        server = data.get('server')
        username = data.get('username')
        password = data.get('password')
        oauth_token = data.get('oauth_access_token')

        if not all([server, username]) or not (password or oauth_token):
            return jsonify({
                'error': 'Missing required parameters',
                'required': ['server', 'username', 'password OR oauth_access_token']
            }), 400

        return jsonify(await _fetch_messages(data, request_id))

    @app.route('/health')
    def health():
        with TRMNL_IPS_LOCK:
            trmnl_count = len(TRMNL_IPS)
            last_refresh = last_ip_refresh.isoformat() if last_ip_refresh else None

        health_data = {
            'status': 'healthy',
            'service': 'email-reader',
            'providers': ['imap'],
            'features': ['password_auth', 'oauth2_auth'],
            'python': sys.version.split()[0],
            'timestamp': datetime.now().isoformat()
        }

        # No caller IP or whitelist verdict here: that would tell a prober whether a spoof worked
        health_data['ip_whitelist'] = {'enabled': ENABLE_IP_WHITELIST, 'ips_loaded': trmnl_count,
                                       'last_refresh': last_refresh}

        return jsonify(health_data)


app = create_app()

logger.info("=" * 60)
logger.info("🚀 Email Reader")
logger.info(f"   Python {sys.version.split()[0]}")
logger.info(f"   Provider: IMAP (password/OAuth)")
logger.info(f"   Features: Caching, IP Whitelist")
logger.info("=" * 60)


async def startup_init():
    global TRMNL_IPS, last_ip_refresh, cache_manager, login_limiter

    if ENABLE_IP_WHITELIST:
        ips = await fetch_trmnl_ips()
        with TRMNL_IPS_LOCK:
            TRMNL_IPS = ips
            last_ip_refresh = datetime.now()
        start_ip_refresh_worker()
    else:
        logger.warning("⚠️  IP whitelist DISABLED")

    cache_manager = CacheManager(
        redis_host=REDIS_HOST, redis_port=REDIS_PORT, redis_db=REDIS_DB,
        ttl_seconds=CACHE_TTL_SECONDS, enabled=ENABLE_CACHE
    )
    if cache_manager.redis_client:
        login_limiter = LoginLimiter(cache_manager.redis_client)
    else:
        logger.warning("⚠️  Login limit per worker only (no Redis)")

    if ENABLE_CACHE:
        logger.info(f"💾 Cache enabled (TTL: {CACHE_TTL_SECONDS}s)")
    else:
        logger.info("💾 Cache disabled")

    logger.info("=" * 60)
    logger.info("✓ Ready to accept requests")
    logger.info("=" * 60)


try:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup_init())
    loop.close()
except Exception as e:
    logger.error(f"✗ Startup error: {e}")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
