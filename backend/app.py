"""
Unified Email Reader - Flask Backend for TRMNL
Supports: IMAP (password/OAuth), Gmail API (OAuth), Microsoft Graph (OAuth)
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

# Import modules
from modules.providers.imap_provider import (
    IMAPProvider,
    IMAPAuthenticationError,
    IMAPConnectionError,
    IMAPProtocolError,
    IMAPTimeoutError
)
from modules.providers.gmail_api import (
    GmailAPIProvider,
    GmailAPIError,
    GmailAuthError
)
from modules.utils.cache import CacheManager

# Suppress warnings
warnings.filterwarnings('ignore', category=ResourceWarning)

# Configuration
ENABLE_IP_WHITELIST = os.getenv('ENABLE_IP_WHITELIST', 'true').lower() == 'true'
IP_REFRESH_HOURS = int(os.getenv('IP_REFRESH_HOURS', '24'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

# Cache configuration
ENABLE_CACHE = os.getenv('ENABLE_CACHE', 'true').lower() == 'true'
CACHE_TTL_SECONDS = int(os.getenv('CACHE_TTL_SECONDS', '300'))
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_DB = int(os.getenv('REDIS_DB', '0'))

# IMAP timeouts
IMAP_CONNECT_TIMEOUT = int(os.getenv('IMAP_CONNECT_TIMEOUT', '10'))
IMAP_LOGIN_TIMEOUT = int(os.getenv('IMAP_LOGIN_TIMEOUT', '15'))
IMAP_FETCH_TIMEOUT = int(os.getenv('IMAP_FETCH_TIMEOUT', '30'))
MAX_MESSAGES_LIMIT = int(os.getenv('MAX_MESSAGES_LIMIT', '50'))

# TRMNL API endpoint
TRMNL_IPS_API = 'https://trmnl.com/api/ips'

# Configure logging
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    handlers=[log_handler],
    force=True
)

logger = logging.getLogger(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('hypercorn.access').setLevel(logging.ERROR)
logging.getLogger('hypercorn.error').setLevel(logging.WARNING)

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Global variables
TRMNL_IPS = set()
TRMNL_IPS_LOCK = threading.Lock()
last_ip_refresh = None
LOCALHOST_IPS = ['127.0.0.1', '::1']

# Initialize providers
imap_provider = IMAPProvider(
    connect_timeout=IMAP_CONNECT_TIMEOUT,
    login_timeout=IMAP_LOGIN_TIMEOUT,
    fetch_timeout=IMAP_FETCH_TIMEOUT
)
gmail_provider = GmailAPIProvider(timeout=30)
# email_formatter = EmailFormatter()
cache_manager = None  # Initialized in startup


def mask_email(email_addr):
    """Mask email address for logging"""
    if not email_addr or '@' not in email_addr:
        return email_addr[:1] + "***" if email_addr else ""

    if email_addr.startswith('@'):
        return email_addr

    local, domain = email_addr.split('@', 1)
    masked_local = local[0] + "***" if len(local) > 0 else "***"
    return f"{masked_local}@{domain}"


def format_auth_error(email_addr, error_message, is_oauth=False):
    """Format authentication errors with helpful guidance"""
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
    else:
        return base_msg + "Many providers require App Passwords instead of regular passwords."


async def fetch_trmnl_ips():
    """Fetch TRMNL server IPs"""
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
    """Update TRMNL IPs sync wrapper"""
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
    """Background worker for IP refresh"""
    while True:
        try:
            time.sleep(IP_REFRESH_HOURS * 3600)
            update_trmnl_ips_sync()
        except Exception as e:
            logger.error(f"✗ IP refresh worker error: {e}")
            time.sleep(3600)


def start_ip_refresh_worker():
    """Start background thread"""
    if not ENABLE_IP_WHITELIST:
        return

    worker_thread = threading.Thread(
        target=ip_refresh_worker,
        daemon=True,
        name='IP-Refresh-Worker'
    )
    worker_thread.start()
    logger.info(f"✓ IP refresh worker started (every {IP_REFRESH_HOURS}h)")


def get_client_ip():
    """Get real client IP"""
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP').strip()
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    return request.remote_addr


def require_whitelisted_ip(f):
    """Decorator for IP whitelisting"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not ENABLE_IP_WHITELIST:
            return await f(*args, **kwargs)

        client_ip = get_client_ip()
        with TRMNL_IPS_LOCK:
            allowed_ips = TRMNL_IPS.copy()

        if client_ip not in allowed_ips:
            logger.warning(f"🚫 Blocked unauthorized IP: {client_ip}")
            return jsonify({
                'error': 'Access denied',
                'message': 'Your IP address is not authorized'
            }), 403

        return await f(*args, **kwargs)

    return decorated_function


def load_mock_data():
    """Load mock data from JSON file"""
    try:
        with open('mock-data.json', 'r') as f:
            mock_data = json.load(f)

        now = datetime.now()

        for message in mock_data['messages']:
            timestamp_str = message['timestamp']

            if timestamp_str == 'TODAY':
                message['timestamp'] = now.isoformat()
            elif timestamp_str.startswith('TODAY-'):
                hours = int(timestamp_str.split('-')[1].replace('h', ''))
                message['timestamp'] = (now - timedelta(hours=hours)).isoformat()
            elif timestamp_str == 'YESTERDAY':
                message['timestamp'] = (now - timedelta(days=1)).isoformat()
            elif timestamp_str.startswith('YESTERDAY-'):
                hours = int(timestamp_str.split('-')[1].replace('h', ''))
                message['timestamp'] = (now - timedelta(days=1, hours=hours)).isoformat()
            elif timestamp_str.endswith('DAYS'):
                days = int(timestamp_str.replace('DAYS', ''))
                message['timestamp'] = (now - timedelta(days=days)).isoformat()
            elif 'DAYS-' in timestamp_str:
                parts = timestamp_str.split('-')
                days = int(parts[0].replace('DAYS', ''))
                hours = int(parts[1].replace('h', ''))
                message['timestamp'] = (now - timedelta(days=days, hours=hours)).isoformat()

        mock_data['fetched_at'] = now.isoformat()
        return mock_data

    except Exception as e:
        logger.error(f"✗ Mock data error: {e}")
        return None


def create_app():
    """Application factory"""
    app = Flask(__name__)
    register_routes(app)
    return app


def register_routes(app):
    """Register all Flask routes"""

    @app.route('/messages', methods=['GET', 'POST'])
    @require_whitelisted_ip
    async def get_messages():
        """
        IMAP email endpoint - supports password and OAuth authentication
        """
        request_id = str(uuid.uuid4())[:8]
        client_ip = get_client_ip()

        # Extract parameters
        if request.method == 'POST':
            data = request.json
        else:
            data = request.args

        server = data.get('server')
        username = data.get('username')
        password = data.get('password')
        oauth_token = data.get('oauth_access_token')

        # Validate required params
        if not all([server, username]) or not (password or oauth_token):
            return jsonify({
                'error': 'Missing required parameters',
                'required': ['server', 'username', 'password OR oauth_access_token']
            }), 400

        port = int(data.get('port', 993))
        folder = data.get('folder', 'INBOX')
        limit = int(data.get('limit', 10))

        if limit > MAX_MESSAGES_LIMIT:
            limit = MAX_MESSAGES_LIMIT

        gmail_category = data.get('gmail_category')

        unread_only = data.get('unread_only', False)
        if isinstance(unread_only, str):
            unread_only = unread_only.lower() == 'true'

        flagged_only = data.get('flagged_only', False)
        if isinstance(flagged_only, str):
            flagged_only = flagged_only.lower() == 'true'

        from_emails = data.get('from_emails')
        if from_emails:
            if isinstance(from_emails, str):
                from_emails = [email.strip() for email in from_emails.split(',') if email.strip()]
            elif not isinstance(from_emails, list):
                from_emails = []
        else:
            from_emails = []

        # Log request
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

        # Mock data mode
        if username == 'master@trmnl.com':
            logger.info(f"[{request_id}] 🎭 Returning mock data")
            mock_response = load_mock_data()
            if mock_response:
                return jsonify(mock_response)
            else:
                return jsonify({'error': 'Failed to load mock data'}), 200

        # Generate cache key
        cache_params = {
            'provider': 'imap',
            'server': server,
            'username': username,
            'auth_type': 'oauth' if oauth_token else 'password',
            'folder': folder,
            'limit': limit,
            'unread_only': unread_only,
            'flagged_only': flagged_only,
            'gmail_category': gmail_category,
            'from_emails': sorted(from_emails) if from_emails else []
        }

        cache_key = cache_manager.generate_key('imap', cache_params)

        # Check cache
        cached_response = cache_manager.get(cache_key)
        if cached_response:
            logger.info(f"[{request_id}] 💾 Cache HIT")
            return jsonify(cached_response)

        # Fetch from IMAP
        try:
            messages = await imap_provider.fetch_messages(
                server=server,
                port=port,
                username=username,
                password=password,
                folder=folder,
                limit=limit,
                unread_only=unread_only,
                flagged_only=flagged_only,
                gmail_category=gmail_category,
                from_emails=from_emails,
                oauth_token=oauth_token,
                request_id=request_id
            )

            response_data = {
                'success': True,
                'provider': 'imap',
                'email': username,
                'folder': folder,
                'count': len(messages),
                'unread_only': unread_only,
                'flagged_only': flagged_only,
                'messages': messages,
                'fetched_at': datetime.now().isoformat(),
                'auth_method': auth_method
            }

            if gmail_category:
                response_data['gmail_category'] = gmail_category

            if from_emails:
                response_data['from_emails'] = from_emails

            # Cache successful response
            cache_manager.set(cache_key, response_data)

            return jsonify(response_data)

        except IMAPAuthenticationError as e:
            cached_fallback = cache_manager.get(cache_key)
            is_oauth = bool(oauth_token)

            if cached_fallback:
                logger.warning(f"[{request_id}] 🔒 Auth failed ({auth_method}), returning stale cache")
                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = 'Authentication failed - returning cached data'
                cached_fallback['error'] = {
                    'message': format_auth_error(username, str(e), is_oauth),
                    'type': 'AUTH_FAILED',
                    'auth_method': auth_method,
                    'occurred_at': datetime.now().isoformat()
                }
                return jsonify(cached_fallback), 200

            friendly_error = format_auth_error(username, str(e), is_oauth)
            logger.warning(f"[{request_id}] 🔒 Auth failed ({auth_method}) for {masked_username} (no cache)")

            return jsonify({
                'success': False,
                'error': 'Authentication Failed',
                'message': friendly_error,
                'code': 'AUTH_FAILED',
                'auth_method': auth_method,
                'email': username
            }), 200

        except (IMAPTimeoutError, IMAPConnectionError, IMAPProtocolError) as e:
            error_type = type(e).__name__
            cached_fallback = cache_manager.get(cache_key)

            if cached_fallback:
                logger.warning(f"[{request_id}] ⚠️  {error_type}, returning stale cache")
                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = f'{error_type} - returning cached data'
                cached_fallback['error'] = {
                    'message': str(e),
                    'type': error_type.replace('IMAP', '').replace('Error', '').upper(),
                    'occurred_at': datetime.now().isoformat()
                }
                return jsonify(cached_fallback), 200

            logger.error(f"[{request_id}] ✗ {error_type}: {e} (no cache)")
            return jsonify({
                'success': False,
                'error': error_type.replace('IMAP', '').replace('Error', ''),
                'message': str(e),
                'code': error_type.replace('IMAP', '').replace('Error', '').upper()
            }), 200

        except Exception as e:
            cached_fallback = cache_manager.get(cache_key)

            if cached_fallback:
                logger.warning(f"[{request_id}] ⚠️  Unexpected error, returning stale cache")
                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['error'] = {
                    'message': str(e),
                    'type': 'UNEXPECTED_ERROR',
                    'occurred_at': datetime.now().isoformat()
                }
                return jsonify(cached_fallback), 200

            logger.error(f"[{request_id}] ✗ Unexpected error: {e}")
            return jsonify({
                'success': False,
                'error': 'Unexpected Error',
                'message': str(e),
                'code': 'UNEXPECTED_ERROR'
            }), 200

    @app.route('/gmail', methods=['GET', 'POST'])
    @require_whitelisted_ip
    async def get_gmail_messages():
        """
        Gmail REST API endpoint - OAuth only
        Returns same simple structure as /messages endpoint
        """
        request_id = str(uuid.uuid4())[:8]
        client_ip = get_client_ip()

        # Extract parameters
        if request.method == 'POST':
            data = request.json
        else:
            data = request.args

        oauth_token = data.get('oauth_access_token')

        if not oauth_token:
            logger.warning(f"[{request_id}] ✗ No OAuth token from {client_ip}")
            return jsonify({
                'error': 'Missing required parameter',
                'required': ['oauth_access_token']
            }), 400

        # Parse parameters
        folder = data.get('folder', 'INBOX')
        gmail_category = data.get('gmail_category')
        limit = int(data.get('limit', 10))

        if limit > MAX_MESSAGES_LIMIT:
            limit = MAX_MESSAGES_LIMIT

        # Parse boolean flags (support both "yes"/"no" and "true"/"false")
        unread_only = data.get('unread_only', False)
        if isinstance(unread_only, str):
            unread_only = unread_only.lower() in ('yes', 'true')

        flagged_only = data.get('flagged_only', False)
        if isinstance(flagged_only, str):
            flagged_only = flagged_only.lower() in ('yes', 'true')

        # Parse from_emails
        from_emails = data.get('from_emails')
        if from_emails:
            if isinstance(from_emails, str):
                from_emails = [email.strip() for email in from_emails.split(',') if email.strip()]
            elif not isinstance(from_emails, list):
                from_emails = []
        else:
            from_emails = []

        # Log request
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
        logger.info(f"[{request_id}] 📧 Gmail API → {folder} (limit={limit}){filter_str}")

        # Generate cache key
        cache_params = {
            'provider': 'gmail_api',
            'folder': folder,
            'gmail_category': gmail_category,
            'limit': limit,
            'unread_only': unread_only,
            'flagged_only': flagged_only,
            'from_emails': sorted(from_emails) if from_emails else []
        }

        cache_key = cache_manager.generate_key('gmail', cache_params)

        # Check cache
        cached_response = cache_manager.get(cache_key)
        if cached_response:
            logger.info(f"[{request_id}] 💾 Cache HIT")
            return jsonify(cached_response)

        # Fetch from Gmail API
        try:
            messages = await gmail_provider.fetch_messages(
                oauth_token=oauth_token,
                folder=folder,
                limit=limit,
                unread_only=unread_only,
                flagged_only=flagged_only,
                gmail_category=gmail_category,
                from_emails=from_emails,
                request_id=request_id
            )

            # Simple response structure (same as /messages)
            response_data = {
                'success': True,
                'provider': 'gmail_api',
                'folder': folder,
                'count': len(messages),
                'unread_only': unread_only,
                'flagged_only': flagged_only,
                'messages': messages,
                'fetched_at': datetime.now().isoformat()
            }

            # Add optional fields if present
            if gmail_category:
                response_data['gmail_category'] = gmail_category

            if from_emails:
                response_data['from_emails'] = from_emails

            # Cache successful response
            cache_manager.set(cache_key, response_data)

            return jsonify(response_data)

        except GmailAuthError as e:
            cached_fallback = cache_manager.get(cache_key)

            if cached_fallback:
                logger.warning(f"[{request_id}] 🔒 Auth failed, returning stale cache")
                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = 'OAuth authentication failed - returning cached data'
                cached_fallback['error'] = {
                    'message': 'OAuth token expired or invalid. Please reconnect Gmail in TRMNL.',
                    'type': 'AUTH_FAILED',
                    'occurred_at': datetime.now().isoformat()
                }
                return jsonify(cached_fallback), 200

            logger.warning(f"[{request_id}] 🔒 Auth failed (no cache)")
            return jsonify({
                'success': False,
                'error': 'Authentication Failed',
                'message': 'OAuth token expired or invalid. Please reconnect Gmail in TRMNL.',
                'code': 'AUTH_FAILED'
            }), 200

        except GmailAPIError as e:
            cached_fallback = cache_manager.get(cache_key)

            if cached_fallback:
                logger.warning(f"[{request_id}] ⚠️  API error, returning stale cache")
                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = 'Gmail API error - returning cached data'
                cached_fallback['error'] = {
                    'message': str(e),
                    'type': 'API_ERROR',
                    'occurred_at': datetime.now().isoformat()
                }
                return jsonify(cached_fallback), 200

            logger.error(f"[{request_id}] ✗ API error: {e} (no cache)")
            return jsonify({
                'success': False,
                'error': 'API Error',
                'message': str(e),
                'code': 'API_ERROR'
            }), 200

        except Exception as e:
            cached_fallback = cache_manager.get(cache_key)

            if cached_fallback:
                logger.warning(f"[{request_id}] ⚠️  Unexpected error, returning stale cache")
                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['error'] = {
                    'message': str(e),
                    'type': 'UNEXPECTED_ERROR',
                    'occurred_at': datetime.now().isoformat()
                }
                return jsonify(cached_fallback), 200

            logger.error(f"[{request_id}] ✗ Unexpected error: {e}")
            return jsonify({
                'success': False,
                'error': 'Unexpected Error',
                'message': str(e),
                'code': 'UNEXPECTED_ERROR'
            }), 200

    @app.route('/health')
    def health():
        """Health check endpoint"""
        client_ip = get_client_ip()

        with TRMNL_IPS_LOCK:
            is_whitelisted = client_ip in TRMNL_IPS if ENABLE_IP_WHITELIST else True
            trmnl_count = len(TRMNL_IPS)
            last_refresh = last_ip_refresh.isoformat() if last_ip_refresh else None

        health_data = {
            'status': 'healthy',
            'service': 'unified-email-reader',
            'providers': ['imap', 'gmail_api'],
            'features': ['password_auth', 'oauth2_auth', 'email_formatting'],
            'python': sys.version.split()[0],
            'timestamp': datetime.now().isoformat()
        }

        if ENABLE_IP_WHITELIST:
            health_data['ip_whitelist'] = {
                'enabled': True,
                'your_ip': client_ip,
                'whitelisted': is_whitelisted,
                'ips_loaded': trmnl_count,
                'last_refresh': last_refresh,
                'refresh_interval_hours': IP_REFRESH_HOURS
            }
        else:
            health_data['ip_whitelist'] = {
                'enabled': False,
                'your_ip': client_ip
            }

        return jsonify(health_data)


# Create app
app = create_app()

logger.info("=" * 60)
logger.info("🚀 Unified Email Reader")
logger.info(f"   Python {sys.version.split()[0]}")
logger.info(f"   Providers: IMAP (password/OAuth), Gmail API (OAuth)")
logger.info(f"   Features: Formatting, Caching, IP Whitelist")
logger.info("=" * 60)


# Startup initialization
async def startup_init():
    """Initialize on startup"""
    global TRMNL_IPS, last_ip_refresh, cache_manager

    if ENABLE_IP_WHITELIST:
        ips = await fetch_trmnl_ips()
        with TRMNL_IPS_LOCK:
            TRMNL_IPS = ips
            last_ip_refresh = datetime.now()
        start_ip_refresh_worker()
    else:
        logger.warning("⚠️  IP whitelist DISABLED")

    # Initialize cache manager
    cache_manager = CacheManager(
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
        redis_db=REDIS_DB,
        ttl_seconds=CACHE_TTL_SECONDS,
        enabled=ENABLE_CACHE
    )

    if ENABLE_CACHE:
        logger.info(f"💾 Cache enabled (TTL: {CACHE_TTL_SECONDS}s)")
    else:
        logger.info("💾 Cache disabled")

    logger.info("=" * 60)
    logger.info("✓ Ready to accept requests")
    logger.info("=" * 60)


# Run startup
try:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup_init())
    loop.close()
except Exception as e:
    logger.error(f"✗ Startup error: {e}")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)