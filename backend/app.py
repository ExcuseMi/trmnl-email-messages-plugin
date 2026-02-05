"""
Async IMAP Email Reader - Flask Backend for TRMNL
Optimized version with resilient error handling, cache-first strategy, and OAuth2 support
"""

from flask import Flask, request, jsonify
import aioimaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timedelta
import time
import os
from functools import wraps
import asyncio
import httpx
import threading
import logging
import sys
import hashlib
import json
import redis
import uuid
import ssl
import warnings
import base64

# Suppress warnings
warnings.filterwarnings('ignore', category=ResourceWarning)

# Configuration
ENABLE_IP_WHITELIST = os.getenv('ENABLE_IP_WHITELIST', 'true').lower() == 'true'
IP_REFRESH_HOURS = int(os.getenv('IP_REFRESH_HOURS', '24'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()  # Default to INFO

# Cache configuration
ENABLE_CACHE = os.getenv('ENABLE_CACHE', 'true').lower() == 'true'
CACHE_TTL_SECONDS = int(os.getenv('CACHE_TTL_SECONDS', '300'))  # 5 minutes default
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_DB = int(os.getenv('REDIS_DB', '0'))

# Production-ready IMAP timeouts and limits
IMAP_CONNECT_TIMEOUT = int(os.getenv('IMAP_CONNECT_TIMEOUT', '10'))
IMAP_LOGIN_TIMEOUT = int(os.getenv('IMAP_LOGIN_TIMEOUT', '15'))
IMAP_FETCH_TIMEOUT = int(os.getenv('IMAP_FETCH_TIMEOUT', '30'))
MAX_MESSAGES_LIMIT = int(os.getenv('MAX_MESSAGES_LIMIT', '50'))

# TRMNL API endpoint for IP addresses
TRMNL_IPS_API = 'https://trmnl.com/api/ips'

# Configure logging for Docker/production
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Configure root logger with environment variable
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    handlers=[log_handler],
    force=True
)

logger = logging.getLogger(__name__)

# Disable Flask's default logger and hypercorn to avoid duplicates
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('hypercorn.access').setLevel(logging.ERROR)
logging.getLogger('hypercorn.error').setLevel(logging.WARNING)

# Ensure logs are flushed immediately (important for Docker)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Global variables for IP management
TRMNL_IPS = set()
TRMNL_IPS_LOCK = threading.Lock()
last_ip_refresh = None

# Always allow localhost
LOCALHOST_IPS = ['127.0.0.1', '::1']

# Redis cache client (initialized on first use)
redis_client = None


# Custom exception classes for better error classification
class IMAPAuthenticationError(Exception):
    """Raised when IMAP authentication fails"""
    pass


class IMAPConnectionError(Exception):
    """Raised when IMAP connection fails"""
    pass


class IMAPProtocolError(Exception):
    """Raised when IMAP protocol encounters an error"""
    pass


class IMAPTimeoutError(Exception):
    """Raised when IMAP operation times out"""
    pass


def mask_email(email_addr):
    """
    Mask email address for logging privacy
    Examples:
        user@example.com -> u***@example.com
        test@gmail.com -> t***@gmail.com
        @domain.com -> @domain.com (keep as-is for domain filters)
    """
    if not email_addr:
        return ""

    # If it's just a domain filter (starts with @), keep it
    if email_addr.startswith('@'):
        return email_addr

    # Split email
    if '@' not in email_addr:
        return email_addr[:1] + "***"

    local, domain = email_addr.split('@', 1)

    # Mask local part: show first char + ***
    if len(local) > 0:
        masked_local = local[0] + "***"
    else:
        masked_local = "***"

    return f"{masked_local}@{domain}"


def format_auth_error(email_addr, error_message, is_oauth=False):
    """Format authentication errors with helpful guidance"""

    # OAuth-specific error message
    if is_oauth:
        return (
            "OAuth authentication failed. Please check that:\n"
            "1. Your OAuth connection in TRMNL is still valid\n"
            "2. The required scopes are granted (IMAP access)\n"
            "3. Your email provider supports OAuth2/XOAUTH2\n"
            "You may need to reconnect your account in TRMNL settings."
        )

    # Detect email provider for password-based auth
    domain = email_addr.lower().split('@')[-1] if '@' in email_addr else ''

    base_msg = "Unable to connect to your email account. "

    # Provider-specific guidance
    if 'gmail.com' in domain:
        return (
            base_msg +
            "For Gmail accounts, you need to use an App Password instead of your regular password. "
            "Visit https://myaccount.google.com/apppasswords to create one."
        )
    elif 'outlook' in domain or 'hotmail' in domain or 'live.com' in domain:
        return (
            base_msg +
            "For Outlook/Hotmail accounts, you may need to enable IMAP access and use an App Password. "
            "Visit your Outlook account settings to enable IMAP."
        )
    elif 'yahoo.com' in domain:
        return (
            base_msg +
            "For Yahoo accounts, you need to generate an App Password. "
            "Visit https://login.yahoo.com/account/security to create one."
        )
    elif 'icloud.com' in domain:
        return (
            base_msg +
            "For iCloud accounts, you need to use an App-Specific Password. "
            "Visit https://appleid.apple.com to generate one."
        )
    else:
        return (
            base_msg +
            "Please check your username and password. Many email providers require App Passwords instead of your regular password."
        )


def get_redis_client():
    """Lazy initialization of Redis client with connection retry"""
    global redis_client, ENABLE_CACHE

    if not ENABLE_CACHE:
        return None

    if redis_client is not None:
        return redis_client

    # Try to connect with retry logic
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            # Test connection
            client.ping()
            logger.info(f"✓ Redis connected at {REDIS_HOST}:{REDIS_PORT}")
            redis_client = client
            return redis_client
        except redis.ConnectionError as e:
            if attempt < max_attempts:
                logger.debug(f"Redis connection attempt {attempt}/{max_attempts} failed")
                time.sleep(0.5)
            else:
                logger.warning(f"✗ Redis unavailable - cache disabled")
                ENABLE_CACHE = False
                redis_client = None
                return None
        except Exception as e:
            logger.warning(f"✗ Redis error: {e} - cache disabled")
            ENABLE_CACHE = False
            redis_client = None
            return None


def load_mock_data():
    """Load and process mock data from JSON file with dynamic timestamps"""
    try:
        with open('mock-data.json', 'r') as f:
            mock_data = json.load(f)

        now = datetime.now()

        # Process timestamps
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


async def fetch_trmnl_ips():
    """Fetch current TRMNL server IPs from their API"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(TRMNL_IPS_API)
            response.raise_for_status()
            data = response.json()

            # Extract IPv4 and IPv6 addresses
            ipv4_list = data.get('data', {}).get('ipv4', [])
            ipv6_list = data.get('data', {}).get('ipv6', [])

            # Combine into set
            ips = set(ipv4_list + ipv6_list + LOCALHOST_IPS)

            logger.info(f"✓ Loaded {len(ips)} TRMNL IPs ({len(ipv4_list)} IPv4, {len(ipv6_list)} IPv6)")
            return ips

    except Exception as e:
        logger.error(f"✗ Failed to fetch TRMNL IPs: {e}")
        return set(LOCALHOST_IPS)


def update_trmnl_ips_sync():
    """Update TRMNL IPs - sync wrapper for background thread"""
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
    """Background worker that refreshes TRMNL IPs periodically"""
    while True:
        try:
            time.sleep(IP_REFRESH_HOURS * 3600)
            update_trmnl_ips_sync()
        except Exception as e:
            logger.error(f"✗ IP refresh worker error: {e}")
            time.sleep(3600)


def start_ip_refresh_worker():
    """Start background thread for IP refresh"""
    if not ENABLE_IP_WHITELIST:
        return

    worker_thread = threading.Thread(
        target=ip_refresh_worker,
        daemon=True,
        name='IP-Refresh-Worker'
    )
    worker_thread.start()
    logger.info(f"✓ IP refresh worker started (every {IP_REFRESH_HOURS}h)")


def generate_cache_key(params):
    """Generate a unique cache key from request parameters"""
    cache_data = {
        'server': params['server'],
        'port': params['port'],
        'username': params['username'],
        'auth_type': 'oauth' if params.get('oauth_token') else 'password',  # OAuth support
        'folder': params['folder'],
        'limit': params['limit'],
        'unread_only': params['unread_only'],
        'flagged_only': params['flagged_only'],
        'gmail_category': params.get('gmail_category'),
        'from_emails': sorted(params.get('from_emails', [])) if params.get('from_emails') else []
    }

    cache_str = json.dumps(cache_data, sort_keys=True)
    cache_hash = hashlib.md5(cache_str.encode()).hexdigest()
    return f"imap:cache:{cache_hash}"


def get_cached_response(cache_key):
    """Retrieve cached response from Redis if valid"""
    if not ENABLE_CACHE:
        return None

    client = get_redis_client()
    if not client:
        return None

    try:
        cached_json = client.get(cache_key)
        if cached_json:
            cached_data = json.loads(cached_json)
            return cached_data
        return None
    except Exception as e:
        logger.error(f"✗ Cache read error: {e}")
        return None


def cache_response(cache_key, response_data):
    """Store response in Redis with TTL"""
    if not ENABLE_CACHE:
        return

    client = get_redis_client()
    if not client:
        return

    try:
        client.setex(
            cache_key,
            CACHE_TTL_SECONDS,
            json.dumps(response_data)
        )
    except Exception as e:
        logger.error(f"✗ Cache write error: {e}")


def get_allowed_ips():
    """Get current list of allowed IPs from TRMNL API"""
    with TRMNL_IPS_LOCK:
        return TRMNL_IPS.copy()


def get_client_ip():
    """Get the real client IP address, accounting for Cloudflare Tunnel"""
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP').strip()
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    return request.remote_addr


def require_whitelisted_ip(f):
    """Decorator to enforce IP whitelisting on routes"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not ENABLE_IP_WHITELIST:
            return await f(*args, **kwargs)

        client_ip = get_client_ip()
        allowed_ips = get_allowed_ips()

        if client_ip not in allowed_ips:
            logger.warning(f"🚫 Blocked unauthorized IP: {client_ip}")
            return jsonify({
                'error': 'Access denied',
                'message': 'Your IP address is not authorized to access this service'
            }), 403

        return await f(*args, **kwargs)

    return decorated_function


def create_app():
    """Application factory for Hypercorn/ASGI servers"""
    app = Flask(__name__)
    register_routes(app)
    return app


def decode_mime_header(header):
    """Decode MIME encoded email headers"""
    if header is None:
        return ""

    decoded_parts = decode_header(header)
    result = []

    for content, encoding in decoded_parts:
        if isinstance(content, bytes):
            try:
                result.append(content.decode(encoding or 'utf-8', errors='ignore'))
            except:
                result.append(content.decode('utf-8', errors='ignore'))
        else:
            result.append(str(content))

    return ' '.join(result)


def extract_sender_name(from_header):
    """Extract clean sender name from email From header"""
    if not from_header:
        return "Unknown"

    decoded = decode_mime_header(from_header)

    if '<' in decoded and '>' in decoded:
        name = decoded.split('<')[0].strip().replace('"', '').replace("'", "")
        if name:
            return name
        email = decoded.split('<')[1].split('>')[0].strip()
        return email

    return decoded.strip()


def parse_message_data(header_data, msg_id, is_read=True, is_flagged=False):
    """Parse header data into message dict"""
    try:
        email_message = email.message_from_bytes(header_data)
    except Exception as e:
        logger.error(f"✗ Failed to parse message {msg_id}: {e}")
        return None

    from_header = email_message.get('From', '')
    sender = extract_sender_name(from_header)
    subject = decode_mime_header(email_message.get('Subject', 'No Subject'))
    date_str = email_message.get('Date', '')

    sender_email = ""
    if from_header:
        decoded_from = decode_mime_header(from_header)
        _, email_addr = parseaddr(decoded_from)
        sender_email = email_addr if email_addr else ""

    try:
        if date_str:
            timestamp = parsedate_to_datetime(date_str)
            timestamp_iso = timestamp.isoformat()
        else:
            timestamp_iso = datetime.now().isoformat()
    except Exception:
        timestamp_iso = datetime.now().isoformat()

    return {
        'sender': sender,
        'sender_email': sender_email,
        'subject': subject,
        'timestamp': timestamp_iso,
        'msg_id': msg_id,
        'read': is_read,
        'flagged': is_flagged
    }


def generate_oauth2_string(username, oauth_token):
    """
    Generate XOAUTH2 authentication string for IMAP
    Format: base64(user={username}\x01auth=Bearer {token}\x01\x01)
    """
    auth_string = f"user={username}\x01auth=Bearer {oauth_token}\x01\x01"
    return base64.b64encode(auth_string.encode()).decode()


async def cleanup_imap_connection(client, request_id=None):
    """Safely cleanup IMAP connection with proper timeout handling"""
    if not client:
        return

    req_prefix = f"[{request_id}]" if request_id else ""

    try:
        # Try to close gracefully with timeout
        await asyncio.wait_for(client.close(), timeout=2.0)
    except asyncio.TimeoutError:
        logger.debug(f"{req_prefix} ⚠️  IMAP close timed out")
    except Exception as e:
        logger.debug(f"{req_prefix} ⚠️  IMAP close error: {e}")

    try:
        # Try to logout with timeout
        await asyncio.wait_for(client.logout(), timeout=2.0)
    except asyncio.TimeoutError:
        logger.debug(f"{req_prefix} ⚠️  IMAP logout timed out")
    except Exception as e:
        logger.debug(f"{req_prefix} ⚠️  IMAP logout error: {e}")


async def fetch_email_messages(server, port, username, password, folder, limit, unread_only, gmail_category=None, from_emails=None, flagged_only=False, oauth_token=None, request_id=None):
    """
    Optimized async IMAP fetch with improved error handling, connection management, and OAuth2 support
    """
    client = None
    req_prefix = f"[{request_id}]" if request_id else ""
    authenticated = False  # Track if we successfully authenticated

    try:
        start_time = time.time()

        # Create SSL context with better compatibility
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False  # More compatible with various servers
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Create async IMAP client
        client = aioimaplib.IMAP4_SSL(
            host=server,
            port=port,
            timeout=IMAP_CONNECT_TIMEOUT,
            ssl_context=ssl_context
        )

        # Wait for server hello
        try:
            await asyncio.wait_for(client.wait_hello_from_server(), timeout=IMAP_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            raise IMAPConnectionError(f'Connection timeout to {server}:{port}')

        # Login - OAuth or Password
        try:
            if oauth_token:
                # OAuth2 authentication using XOAUTH2
                auth_string = generate_oauth2_string(username, oauth_token)

                # Get a new tag (might be bytes or str depending on aioimaplib version)
                tag = client.protocol.new_tag()
                if isinstance(tag, bytes):
                    tag = tag.decode()

                # Build AUTHENTICATE command
                auth_command = f'{tag} AUTHENTICATE XOAUTH2 {auth_string}\r\n'

                # Send the command
                client.protocol.transport.write(auth_command.encode())

                # Wait for server response
                response = await asyncio.wait_for(
                    client.protocol.wait_server_push(),
                    timeout=IMAP_LOGIN_TIMEOUT
                )

                # Check if authentication succeeded
                success = False
                error_msg = 'OAuth authentication failed'

                for line in response.lines:
                    line_str = line.decode('utf-8', errors='ignore') if isinstance(line, bytes) else str(line)

                    if f'{tag} OK' in line_str:
                        success = True
                        break
                    elif f'{tag} NO' in line_str or f'{tag} BAD' in line_str:
                        error_msg = line_str
                        break

                if not success:
                    raise IMAPAuthenticationError(error_msg)

                logger.debug(f"{req_prefix} ✓ OAuth authentication successful")

            else:
                # Password authentication (original method)
                login_response = await asyncio.wait_for(
                    client.login(username, password),
                    timeout=IMAP_LOGIN_TIMEOUT
                )
                if login_response.result != 'OK':
                    raise IMAPAuthenticationError('Invalid credentials')

            authenticated = True  # Mark as successfully authenticated

        except asyncio.TimeoutError:
            raise IMAPTimeoutError(f'Login operation timed out after {IMAP_LOGIN_TIMEOUT}s')
        except IMAPAuthenticationError:
            raise  # Re-raise auth errors as-is
        except Exception as e:
            # Classify other login exceptions
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in
                   ['authentication', 'credentials', 'password', 'authenticationfailed']):
                raise IMAPAuthenticationError(str(e))
            else:
                raise IMAPConnectionError(f'Login failed: {str(e)}')
        # Select folder
        try:
            select_response = await asyncio.wait_for(
                client.select(folder),
                timeout=10
            )
            if select_response.result != 'OK':
                raise IMAPProtocolError(f'Failed to select folder {folder}')
        except asyncio.TimeoutError:
            raise IMAPTimeoutError(f'Folder selection timed out')

        # Build search criteria
        search_parts = []

        if gmail_category:
            gmail_parts = [f'category:{gmail_category.lower()}']
            if unread_only:
                gmail_parts.append('is:unread')
            if flagged_only:
                gmail_parts.append('is:starred')

            if from_emails and len(from_emails) > 0:
                if len(from_emails) == 1:
                    gmail_parts.append(f'from:{from_emails[0]}')
                else:
                    from_query = ' OR '.join([f'from:{email}' for email in from_emails])
                    gmail_parts.append(f'({from_query})')

            search_criteria = f'X-GM-RAW "{" ".join(gmail_parts)}"'
        else:
            if unread_only:
                search_parts.append('UNSEEN')
            if flagged_only:
                search_parts.append('FLAGGED')

            if from_emails and len(from_emails) > 0:
                if len(from_emails) == 1:
                    search_parts.append(f'FROM "{from_emails[0]}"')
                else:
                    or_query = f'FROM "{from_emails[0]}"'
                    for email_addr in from_emails[1:]:
                        or_query = f'OR ({or_query}) (FROM "{email_addr}")'
                    search_parts.append(or_query)

            if not search_parts:
                search_parts.append('ALL')

            search_criteria = ' '.join(search_parts)

        # Search with timeout
        try:
            search_response = await asyncio.wait_for(
                client.search(search_criteria),
                timeout=15
            )

            if search_response.result != 'OK':
                raise IMAPProtocolError('Search failed')
        except asyncio.TimeoutError:
            raise IMAPTimeoutError('Search operation timed out')

        # Get message IDs
        if not search_response.lines:
            return []

        message_ids_text = search_response.lines[0].decode('utf-8', errors='ignore').strip()
        if not message_ids_text:
            return []

        message_ids = message_ids_text.split()
        if not message_ids:
            return []

        message_ids.reverse()
        message_ids = message_ids[:limit]

        # Single batch fetch for FLAGS + HEADERS with extended timeout
        msg_id_str = ','.join(message_ids)

        try:
            fetch_response = await asyncio.wait_for(
                client.fetch(
                    msg_id_str,
                    '(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])'
                ),
                timeout=IMAP_FETCH_TIMEOUT
            )

            if fetch_response.result != 'OK':
                raise IMAPProtocolError('Fetch failed')
        except asyncio.TimeoutError:
            raise IMAPTimeoutError(f'Fetch operation timed out after {IMAP_FETCH_TIMEOUT}s')

        # Parse combined response
        messages = []
        current_msg_id = None
        current_flags = {}
        header_lines = []
        in_headers = False

        for line in fetch_response.lines:
            if not isinstance(line, (bytes, bytearray)):
                continue

            line_bytes = bytes(line) if isinstance(line, bytearray) else line

            try:
                line_str = line_bytes.decode('utf-8', errors='ignore')

                if ' FETCH ' in line_str and 'FLAGS' in line_str:
                    if current_msg_id and header_lines:
                        header_data = b''.join(header_lines)
                        message = parse_message_data(
                            header_data,
                            current_msg_id,
                            current_flags.get('read', True),
                            current_flags.get('flagged', False)
                        )
                        if message:
                            messages.append(message)

                    current_msg_id = line_str.split(' FETCH ', 1)[0].strip()
                    current_flags = {
                        'read': '\\Seen' in line_str,
                        'flagged': '\\Flagged' in line_str
                    }
                    header_lines = []
                    in_headers = False

                elif current_msg_id and not in_headers and (b'From:' in line_bytes or b'Subject:' in line_bytes or b'Date:' in line_bytes):
                    in_headers = True
                    header_lines.append(line_bytes)

                elif current_msg_id and in_headers:
                    if line_bytes.strip() == b')' or line_bytes.strip() == b'':
                        in_headers = False
                    else:
                        header_lines.append(line_bytes)

            except Exception as e:
                logger.error(f"✗ Parse error: {e}")
                continue

        # Last message
        if current_msg_id and header_lines:
            header_data = b''.join(header_lines)
            message = parse_message_data(
                header_data,
                current_msg_id,
                current_flags.get('read', True),
                current_flags.get('flagged', False)
            )
            if message:
                messages.append(message)

        elapsed = time.time() - start_time
        logger.info(f"{req_prefix} ✓ Fetched {len(messages)} messages in {elapsed:.2f}s")

        # Sort by timestamp, newest first
        messages.sort(
            key=lambda x: datetime.fromisoformat(x['timestamp']),
            reverse=True
        )

        return messages

    except IMAPAuthenticationError as e:
        # Authentication errors - these are genuine credential issues
        logger.error(f"{req_prefix} ✗ Auth failed: {e}")
        raise

    except IMAPTimeoutError as e:
        # Timeout errors - could be network or server issues
        logger.error(f"{req_prefix} ✗ Timeout: {e}")
        raise

    except IMAPConnectionError as e:
        # Connection errors - network or server unreachable
        logger.error(f"{req_prefix} ✗ Connection error: {e}")
        raise

    except aioimaplib.aioimaplib.Abort as e:
        # IMAP protocol state errors - these happen AFTER successful auth
        logger.error(f"{req_prefix} ✗ IMAP protocol error: {e}")
        if authenticated:
            # If we authenticated successfully, this is a protocol issue, not auth
            raise IMAPProtocolError(f"IMAP protocol state error: {str(e)}")
        else:
            # If we never authenticated, could be auth-related
            raise IMAPAuthenticationError(f"IMAP protocol error during authentication: {str(e)}")

    except asyncio.TimeoutError:
        # Generic timeout
        logger.error(f"{req_prefix} ✗ Operation timed out")
        raise IMAPTimeoutError("Operation timed out")

    except Exception as e:
        # Generic errors
        logger.error(f"{req_prefix} ✗ Unexpected error: {e}")
        # Classify based on error message if possible
        error_str = str(e).lower()
        if any(keyword in error_str for keyword in ['authentication', 'credentials', 'password', 'authenticationfailed']):
            raise IMAPAuthenticationError(str(e))
        elif any(keyword in error_str for keyword in ['timeout', 'timed out']):
            raise IMAPTimeoutError(str(e))
        elif any(keyword in error_str for keyword in ['connection', 'unreachable', 'refused']):
            raise IMAPConnectionError(str(e))
        else:
            raise IMAPProtocolError(f"Error: {str(e)}")

    finally:
        # Always cleanup connection
        await cleanup_imap_connection(client, request_id)


def get_request_params():
    """Extract and validate request parameters from GET or POST"""
    if request.method == 'POST':
        data = request.json
    else:
        data = request.args

    server = data.get('server')
    username = data.get('username')
    password = data.get('password')
    oauth_token = data.get('oauth_access_token')  # OAuth support

    # Either password OR oauth_token required
    if not all([server, username]) or not (password or oauth_token):
        return None, {
            'error': 'Missing required parameters',
            'required': ['server', 'username', 'password OR oauth_access_token']
        }, 400

    port = int(data.get('port', 993))
    folder = data.get('folder', 'INBOX')
    limit = int(data.get('limit', 10))

    if limit > MAX_MESSAGES_LIMIT:
        return None, {
            'error': f'Message limit too high. Maximum allowed: {MAX_MESSAGES_LIMIT}',
            'requested': limit,
            'maximum': MAX_MESSAGES_LIMIT
        }, 200

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
        elif isinstance(from_emails, list):
            from_emails = [email.strip() for email in from_emails if isinstance(email, str) and email.strip()]
        else:
            from_emails = []
    else:
        from_emails = []

    return {
        'server': server,
        'port': port,
        'username': username,
        'password': password,
        'oauth_token': oauth_token,  # OAuth support
        'folder': folder,
        'limit': limit,
        'unread_only': unread_only,
        'flagged_only': flagged_only,
        'gmail_category': gmail_category,
        'from_emails': from_emails
    }, None, None


def register_routes(app):
    """Register all Flask routes"""

    @app.route('/messages', methods=['GET', 'POST'])
    @require_whitelisted_ip
    async def get_messages():
        """
        Get latest email messages via IMAP with resilient cache fallback and OAuth2 support

        ALWAYS returns 200 when cached data is available, regardless of error type.
        This ensures TRMNL devices continue to display data even during transient failures.
        """
        request_id = str(uuid.uuid4())[:8]
        client_ip = get_client_ip()

        params, error, status_code = get_request_params()
        if error:
            logger.warning(f"[{request_id}] ✗ Invalid params from {client_ip}")
            return jsonify(error), status_code

        # Mask email for logging
        masked_username = mask_email(params['username'])

        # Determine auth method for logging
        auth_method = "OAuth" if params.get('oauth_token') else "Password"

        # Build compact log message
        filters = []
        if params['gmail_category']:
            filters.append(f"category={params['gmail_category']}")
        if params['unread_only']:
            filters.append("unread")
        if params['flagged_only']:
            filters.append("flagged")
        if params['from_emails']:
            masked_senders = [mask_email(e) for e in params['from_emails'][:2]]
            senders = ', '.join(masked_senders)
            if len(params['from_emails']) > 2:
                senders += f" +{len(params['from_emails']) - 2}"
            filters.append(f"from=[{senders}]")

        filter_str = f" ({', '.join(filters)})" if filters else ""

        logger.info(f"[{request_id}] 📨 {masked_username} ({auth_method}) → {params['folder']} (limit={params['limit']}){filter_str}")

        # Check for mock data mode
        if params['username'] == 'master@trmnl.com':
            logger.info(f"[{request_id}] 🎭 Returning mock data")
            mock_response = load_mock_data()
            if mock_response:
                return jsonify(mock_response)
            else:
                return jsonify({'error': 'Failed to load mock data'}), 200

        # Check cache first
        cache_key = generate_cache_key(params)
        cached_response = get_cached_response(cache_key)
        if cached_response:
            logger.info(f"[{request_id}] 💾 Cache HIT")
            return jsonify(cached_response)

        # Try to fetch fresh data
        try:
            messages = await fetch_email_messages(
                params['server'],
                params['port'],
                params['username'],
                params.get('password'),
                params['folder'],
                params['limit'],
                params['unread_only'],
                params['gmail_category'],
                params['from_emails'],
                params['flagged_only'],
                params.get('oauth_token'),  # OAuth token
                request_id
            )

            response_data = {
                'success': True,
                'email': params['username'],
                'folder': params['folder'],
                'count': len(messages),
                'unread_only': params['unread_only'],
                'flagged_only': params['flagged_only'],
                'messages': messages,
                'fetched_at': datetime.now().isoformat(),
                'auth_method': auth_method  # Include auth method in response
            }

            if params['gmail_category']:
                response_data['gmail_category'] = params['gmail_category']

            if params['from_emails']:
                response_data['from_emails'] = params['from_emails']

            # Cache successful response
            cache_response(cache_key, response_data)

            return jsonify(response_data)

        except IMAPAuthenticationError as e:
            # Authentication failure - check for cached data first
            error_msg = str(e)
            is_oauth = bool(params.get('oauth_token'))
            cached_fallback = get_cached_response(cache_key)

            if cached_fallback:
                # ALWAYS return 200 with cached data, even for auth errors
                logger.warning(f"[{request_id}] 🔒 Auth failed ({auth_method}), returning stale cache (200 OK)")

                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = 'Authentication failed - returning cached data'
                cached_fallback['error'] = {
                    'message': format_auth_error(params['username'], error_msg, is_oauth),
                    'type': 'AUTH_FAILED',
                    'auth_method': auth_method,
                    'occurred_at': datetime.now().isoformat()
                }

                return jsonify(cached_fallback), 200  # 200 OK with error info

            # No cache available - return error details
            friendly_error = format_auth_error(params['username'], error_msg, is_oauth)
            logger.warning(f"[{request_id}] 🔒 Auth failed ({auth_method}) for {masked_username} (no cache)")

            return jsonify({
                'success': False,
                'error': 'Authentication Failed',
                'message': friendly_error,
                'code': 'AUTH_FAILED',
                'auth_method': auth_method,
                'email': params['username']
            }), 200

        except (IMAPTimeoutError, IMAPConnectionError, IMAPProtocolError) as e:
            # Network/protocol errors - try cached data first
            error_msg = str(e)
            error_type = type(e).__name__

            cached_fallback = get_cached_response(cache_key)

            if cached_fallback:
                # ALWAYS return 200 with cached data for non-auth errors
                logger.warning(f"[{request_id}] ⚠️  {error_type}, returning stale cache (200 OK)")

                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = f'{error_type} - returning cached data'
                cached_fallback['error'] = {
                    'message': error_msg,
                    'type': error_type.replace('IMAP', '').replace('Error', '').upper(),
                    'occurred_at': datetime.now().isoformat()
                }

                return jsonify(cached_fallback), 200  # 200 OK with error info

            # No cache available - return appropriate error
            logger.error(f"[{request_id}] ✗ {error_type}: {error_msg} (no cache)")

            # Always return 200 for TRMNL compatibility
            status = 200

            return jsonify({
                'success': False,
                'error': error_type.replace('IMAP', '').replace('Error', ''),
                'message': error_msg,
                'code': error_type.replace('IMAP', '').replace('Error', '').upper()
            }), status

        except Exception as e:
            # Unexpected errors - still try cache
            error_msg = str(e)
            cached_fallback = get_cached_response(cache_key)

            if cached_fallback:
                logger.warning(f"[{request_id}] ⚠️  Unexpected error, returning stale cache (200 OK)")

                cached_fallback['success'] = False
                cached_fallback['cached'] = True
                cached_fallback['cache_warning'] = 'Unexpected error - returning cached data'
                cached_fallback['error'] = {
                    'message': error_msg,
                    'type': 'UNEXPECTED_ERROR',
                    'occurred_at': datetime.now().isoformat()
                }

                return jsonify(cached_fallback), 200

            logger.error(f"[{request_id}] ✗ Unexpected error: {error_msg} (no cache)")
            return jsonify({
                'success': False,
                'error': 'Unexpected Error',
                'message': error_msg,
                'code': 'UNEXPECTED_ERROR'
            }), 200

    @app.route('/health')
    def health():
        """Health check endpoint"""
        client_ip = get_client_ip()
        allowed_ips = get_allowed_ips()
        is_whitelisted = client_ip in allowed_ips if ENABLE_IP_WHITELIST else True

        health_data = {
            'status': 'healthy',
            'service': 'imap-email-reader',
            'features': ['password_auth', 'oauth2_auth'],  # OAuth support indicator
            'python': '3.13',
            'flask': 'async',
            'timestamp': datetime.now().isoformat()
        }

        if ENABLE_IP_WHITELIST:
            with TRMNL_IPS_LOCK:
                trmnl_count = len(TRMNL_IPS)
                last_refresh = last_ip_refresh.isoformat() if last_ip_refresh else None

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


# Create app instance
app = create_app()

logger.info("=" * 60)
logger.info("🚀 IMAP Email Reader (Resilient Edition with OAuth2)")
logger.info(f"   Python {sys.version.split()[0]}")
logger.info(f"   Log Level: {LOG_LEVEL}")
logger.info(f"   Auth Methods: Password + OAuth2 (XOAUTH2)")
logger.info(f"   Cache Strategy: Always return 200 with cached data on errors")
logger.info("=" * 60)


# Initialize TRMNL IPs on startup
async def startup_init():
    """Initialize TRMNL IPs on startup"""
    global TRMNL_IPS, last_ip_refresh

    if ENABLE_IP_WHITELIST:
        ips = await fetch_trmnl_ips()
        with TRMNL_IPS_LOCK:
            TRMNL_IPS = ips
            last_ip_refresh = datetime.now()
        start_ip_refresh_worker()
    else:
        logger.warning("⚠️  IP whitelist DISABLED - all IPs allowed!")

    if ENABLE_CACHE:
        logger.info(f"💾 Cache enabled (TTL: {CACHE_TTL_SECONDS}s)")
        client = get_redis_client()
    else:
        logger.info("💾 Cache disabled")

    logger.info("=" * 60)
    logger.info("✓ Ready to accept requests")
    logger.info("=" * 60)


# Run startup initialization
try:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup_init())
    loop.close()
except Exception as e:
    logger.error(f"✗ Startup error: {e}")
    logger.warning("⚠️  Continuing with fallback IPs")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)