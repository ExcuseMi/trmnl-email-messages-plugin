"""
Async IMAP Email Reader - Flask Backend for TRMNL
Optimized version with minimal duplication and maximum performance
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
IMAP_CONNECT_TIMEOUT = int(os.getenv('IMAP_CONNECT_TIMEOUT', '10'))  # Reduced from 60s
IMAP_LOGIN_TIMEOUT = int(os.getenv('IMAP_LOGIN_TIMEOUT', '15'))
IMAP_FETCH_TIMEOUT = int(os.getenv('IMAP_FETCH_TIMEOUT', '30'))
MAX_MESSAGES_LIMIT = int(os.getenv('MAX_MESSAGES_LIMIT', '50'))      # Prevent abuse

# TRMNL API endpoint for IP addresses
TRMNL_IPS_API = 'https://usetrmnl.com/api/ips'

# Configure logging for Docker/production
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Configure root logger with environment variable
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    handlers=[log_handler],
    force=True
)

logger = logging.getLogger(__name__)
logger.info(f"Logging initialized at level: {LOG_LEVEL}")

# Disable Flask's default logger to avoid duplicates
logging.getLogger('werkzeug').setLevel(logging.WARNING)

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
            logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
            redis_client = client
            return redis_client
        except redis.ConnectionError as e:
            if attempt < max_attempts:
                logger.debug(f"Redis connection attempt {attempt}/{max_attempts} failed: {e}")
                time.sleep(0.5)  # Wait before retry
            else:
                logger.warning(f"Redis connection failed after {max_attempts} attempts: {e}")
                logger.warning("Cache will be DISABLED - continuing without cache")
                ENABLE_CACHE = False
                redis_client = None
                return None
        except Exception as e:
            logger.warning(f"Redis connection error: {e}")
            logger.warning("Cache will be DISABLED - continuing without cache")
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
        logger.error(f"Error loading mock data: {e}")
        return None


async def fetch_trmnl_ips():
    """Fetch current TRMNL server IPs from their API"""
    try:
        logger.info(f"Fetching TRMNL IPs from {TRMNL_IPS_API}")

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(TRMNL_IPS_API)
            response.raise_for_status()
            data = response.json()

            # Extract IPv4 and IPv6 addresses
            ipv4_list = data.get('data', {}).get('ipv4', [])
            ipv6_list = data.get('data', {}).get('ipv6', [])

            # Combine into set
            ips = set(ipv4_list + ipv6_list + LOCALHOST_IPS)

            ipv4_count = len(ipv4_list)
            ipv6_count = len(ipv6_list)

            logger.info(f"Fetched {len(ips)} TRMNL IPs ({ipv4_count} IPv4, {ipv6_count} IPv6)")
            logger.debug(f"Whitelisted IPs: {sorted(list(ips))}")
            return ips

    except Exception as e:
        logger.error(f"Failed to fetch TRMNL IPs: {e}")
        logger.warning("IP whitelist will use fallback IPs only")
        return set(LOCALHOST_IPS)


def update_trmnl_ips_sync():
    """Update TRMNL IPs - sync wrapper for background thread"""
    global TRMNL_IPS, last_ip_refresh

    try:
        logger.info("Starting scheduled TRMNL IP refresh")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            ips = loop.run_until_complete(fetch_trmnl_ips())
            with TRMNL_IPS_LOCK:
                TRMNL_IPS = ips
                last_ip_refresh = datetime.now()
            logger.info(f"TRMNL IPs updated successfully at {last_ip_refresh.isoformat()}")
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Error updating TRMNL IPs: {e}")


def ip_refresh_worker():
    """Background worker that refreshes TRMNL IPs periodically"""
    while True:
        try:
            time.sleep(IP_REFRESH_HOURS * 3600)
            update_trmnl_ips_sync()
        except Exception as e:
            logger.error(f"IP refresh worker error: {e}")
            time.sleep(3600)


def start_ip_refresh_worker():
    """Start background thread for IP refresh"""
    if not ENABLE_IP_WHITELIST:
        logger.info("IP whitelist disabled, skipping refresh scheduler")
        return

    worker_thread = threading.Thread(
        target=ip_refresh_worker,
        daemon=True,
        name='IP-Refresh-Worker'
    )
    worker_thread.start()
    logger.info(f"Started IP refresh worker (refresh every {IP_REFRESH_HOURS} hours)")


def generate_cache_key(params):
    """Generate a unique cache key from request parameters"""
    # Create a deterministic string from all relevant parameters
    cache_data = {
        'server': params['server'],
        'port': params['port'],
        'username': params['username'],
        'folder': params['folder'],
        'limit': params['limit'],
        'unread_only': params['unread_only'],
        'flagged_only': params['flagged_only'],
        'gmail_category': params.get('gmail_category'),
        'from_emails': sorted(params.get('from_emails', [])) if params.get('from_emails') else []
    }

    # Create hash from sorted JSON (for consistency)
    cache_str = json.dumps(cache_data, sort_keys=True)
    cache_hash = hashlib.md5(cache_str.encode()).hexdigest()

    # Prefix with namespace for better organization
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
            logger.info(f"Cache HIT (key: {cache_key[-12:]}...)")
            return cached_data
        else:
            logger.debug(f"Cache MISS (key: {cache_key[-12:]}...)")
            return None
    except Exception as e:
        logger.error(f"Cache read error: {e}")
        return None


def cache_response(cache_key, response_data):
    """Store response in Redis with TTL"""
    if not ENABLE_CACHE:
        return

    client = get_redis_client()
    if not client:
        return

    try:
        # Store as JSON with expiration
        client.setex(
            cache_key,
            CACHE_TTL_SECONDS,
            json.dumps(response_data)
        )

        # Get cache stats
        cache_size = client.dbsize()
        logger.debug(f"Cached response (key: {cache_key[-12:]}..., total keys: {cache_size})")
    except Exception as e:
        logger.error(f"Cache write error: {e}")


def get_allowed_ips():
    """Get current list of allowed IPs from TRMNL API"""
    with TRMNL_IPS_LOCK:
        return TRMNL_IPS.copy()


def get_client_ip():
    """Get the real client IP address, accounting for Cloudflare Tunnel"""
    # Cloudflare Tunnel passes real IP in CF-Connecting-IP header
    # Priority: CF-Connecting-IP > X-Forwarded-For > X-Real-IP > remote_addr

    # Debug: Log all relevant headers
    headers_debug = {
        'CF-Connecting-IP': request.headers.get('CF-Connecting-IP'),
        'X-Forwarded-For': request.headers.get('X-Forwarded-For'),
        'X-Real-IP': request.headers.get('X-Real-IP'),
        'Remote-Addr': request.remote_addr
    }
    logger.debug(f"IP detection headers: {headers_debug}")

    # Check CF-Connecting-IP FIRST (Cloudflare Tunnel)
    if request.headers.get('CF-Connecting-IP'):
        ip = request.headers.get('CF-Connecting-IP').strip()
        logger.debug(f"Using CF-Connecting-IP: {ip}")
        return ip

    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        logger.debug(f"Using X-Forwarded-For: {ip}")
        return ip

    if request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP').strip()
        logger.debug(f"Using X-Real-IP: {ip}")
        return ip

    logger.debug(f"Using remote_addr: {request.remote_addr}")
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
            logger.warning(f"Blocked request from unauthorized IP: {client_ip}")
            return jsonify({
                'error': 'Access denied',
                'message': 'Your IP address is not authorized to access this service'
            }), 403

        logger.debug(f"Allowed request from whitelisted IP: {client_ip}")
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
        # No display name, extract email from angle brackets
        email = decoded.split('<')[1].split('>')[0].strip()
        return email

    return decoded.strip()


def parse_message_data(header_data, msg_id, is_read=True, is_flagged=False):
    """Parse header data into message dict"""
    try:
        email_message = email.message_from_bytes(header_data)
    except Exception as e:
        logger.error(f"Failed to parse email message {msg_id}: {e}")
        return None

    # Extract fields
    from_header = email_message.get('From', '')
    sender = extract_sender_name(from_header)
    subject = decode_mime_header(email_message.get('Subject', 'No Subject'))
    date_str = email_message.get('Date', '')

    # Extract sender email using parseaddr (more reliable)
    sender_email = ""
    if from_header:
        decoded_from = decode_mime_header(from_header)
        # parseaddr returns (name, email) tuple
        _, email_addr = parseaddr(decoded_from)
        sender_email = email_addr if email_addr else ""
        logger.debug(f"Message {msg_id}: From header='{from_header}' -> sender='{sender}', email='{sender_email}'")
    else:
        logger.warning(f"Message {msg_id}: No From header found!")

    # Parse timestamp
    try:
        if date_str:
            timestamp = parsedate_to_datetime(date_str)
            timestamp_iso = timestamp.isoformat()
        else:
            timestamp_iso = datetime.now().isoformat()
    except Exception:
        timestamp_iso = datetime.now().isoformat()

    message_dict = {
        'sender': sender,
        'sender_email': sender_email,
        'subject': subject,
        'timestamp': timestamp_iso,
        'msg_id': msg_id,
        'read': is_read,
        'flagged': is_flagged
    }

    logger.debug(f"Created message dict: {message_dict}")

    return message_dict


async def fetch_email_messages(server, port, username, password, folder, limit, unread_only, gmail_category=None, from_emails=None, flagged_only=False):
    """
    Optimized async IMAP fetch with combined batch fetching

    Args:
        gmail_category: Gmail category/tab filter (Primary, Social, Promotions, Updates, Forums)
        from_emails: List of sender email addresses to filter by (OR logic)
        flagged_only: Only fetch flagged/starred emails (IMAP \\Flagged flag)
    """
    client = None
    try:
        start_time = time.time()
        logger.info(f"Fetching emails from {server}:{port} folder={folder} limit={limit} unread_only={unread_only} flagged_only={flagged_only}")

        # Create async IMAP client with production timeouts
        client = aioimaplib.IMAP4_SSL(host=server, port=port, timeout=IMAP_CONNECT_TIMEOUT)

        # Wait for server hello with timeout
        try:
            await asyncio.wait_for(client.wait_hello_from_server(), timeout=IMAP_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout to {server}:{port} (>{IMAP_CONNECT_TIMEOUT}s)')

        # Login with timeout
        try:
            login_response = await asyncio.wait_for(
                client.login(username, password),
                timeout=IMAP_LOGIN_TIMEOUT
            )
            if login_response.result != 'OK':
                raise Exception(f'Login failed: {login_response.lines}')
            logger.debug(f"Successfully logged in to {server}")
        except asyncio.TimeoutError:
            raise Exception(f'Login timeout (>{IMAP_LOGIN_TIMEOUT}s)')

        # Select folder
        select_response = await client.select(folder)
        if select_response.result != 'OK':
            raise Exception(f'Failed to select folder {folder}: {select_response.lines}')

        # Build search criteria
        search_parts = []

        # Handle Gmail categories (special case)
        if gmail_category:
            category_map = {
                'primary': 'CATEGORY PERSONAL',
                'social': 'CATEGORY SOCIAL',
                'promotions': 'CATEGORY PROMOTIONS',
                'updates': 'CATEGORY UPDATES',
                'forums': 'CATEGORY FORUMS'
            }

            category_label = category_map.get(gmail_category.lower())
            if not category_label:
                raise Exception(f'Invalid Gmail category: {gmail_category}. Valid: Primary, Social, Promotions, Updates, Forums')

            # Gmail uses X-GM-RAW for complex queries
            gmail_parts = [f'category:{gmail_category.lower()}']
            if unread_only:
                gmail_parts.append('is:unread')
            if flagged_only:
                gmail_parts.append('is:starred')  # Gmail starred = IMAP flagged

            # Add from_emails to Gmail search
            if from_emails and len(from_emails) > 0:
                logger.info(f"Filtering by senders: {from_emails}")
                # Gmail syntax: from:email1 OR from:email2
                if len(from_emails) == 1:
                    gmail_parts.append(f'from:{from_emails[0]}')
                else:
                    # Build OR query for multiple senders
                    from_query = ' OR '.join([f'from:{email}' for email in from_emails])
                    gmail_parts.append(f'({from_query})')

            search_criteria = f'X-GM-RAW "{" ".join(gmail_parts)}"'
            logger.info(f"Using Gmail search criteria: {search_criteria}")
        else:
            # Standard IMAP search
            if unread_only:
                search_parts.append('UNSEEN')
            if flagged_only:
                search_parts.append('FLAGGED')

            # Filter by sender emails (OR logic)
            if from_emails and len(from_emails) > 0:
                logger.info(f"Filtering by senders: {from_emails}")
                # IMAP OR syntax: OR (FROM "email1") (FROM "email2")
                if len(from_emails) == 1:
                    search_parts.append(f'FROM "{from_emails[0]}"')
                else:
                    # Build nested OR for multiple senders
                    # OR (FROM "a") (FROM "b") for 2 senders
                    # OR (OR (FROM "a") (FROM "b")) (FROM "c") for 3+ senders
                    or_query = f'FROM "{from_emails[0]}"'
                    for email_addr in from_emails[1:]:
                        or_query = f'OR ({or_query}) (FROM "{email_addr}")'
                    search_parts.append(or_query)

            if not search_parts:
                search_parts.append('ALL')

            search_criteria = ' '.join(search_parts)
            logger.info(f"Using IMAP search criteria: {search_criteria}")

        search_response = await client.search(search_criteria)

        if search_response.result != 'OK':
            raise Exception(f'Failed to search messages: {search_response.lines}')

        # Get and validate message IDs
        if not search_response.lines:
            logger.info("No messages found")
            return []

        message_ids_text = search_response.lines[0].decode('utf-8', errors='ignore').strip()
        if not message_ids_text:
            logger.info("No messages found")
            return []

        message_ids = message_ids_text.split()
        if not message_ids:
            logger.info("No messages found")
            return []

        # Reverse for latest first and limit
        message_ids.reverse()
        message_ids = message_ids[:limit]

        logger.info(f"Found {len(message_ids)} messages to fetch")

        # OPTIMIZATION: Single batch fetch for FLAGS + HEADERS
        msg_id_str = ','.join(message_ids)

        fetch_response = await client.fetch(
            msg_id_str,
            '(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])'
        )

        if fetch_response.result != 'OK':
            raise Exception(f'Failed to fetch messages: {fetch_response.lines}')

        # Parse the combined response
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

                # Detect message boundary: "123 FETCH (...)"
                if ' FETCH ' in line_str and 'FLAGS' in line_str:
                    # Save previous message if exists
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

                    # Start new message
                    current_msg_id = line_str.split(' FETCH ', 1)[0].strip()
                    current_flags = {
                        'read': '\\Seen' in line_str,
                        'flagged': '\\Flagged' in line_str
                    }
                    header_lines = []
                    in_headers = False

                # Start of header data (look for From:, Subject:, or Date:)
                elif current_msg_id and not in_headers and (b'From:' in line_bytes or b'Subject:' in line_bytes or b'Date:' in line_bytes):
                    in_headers = True
                    header_lines.append(line_bytes)

                # Continuation of header data
                elif current_msg_id and in_headers:
                    # Stop if we hit closing parenthesis or empty line
                    if line_bytes.strip() == b')' or line_bytes.strip() == b'':
                        in_headers = False
                    else:
                        header_lines.append(line_bytes)

            except Exception as e:
                logger.error(f"Error parsing line: {e}")
                continue

        # Don't forget the last message!
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

        end_time = time.time()
        logger.info(f"Fetched {len(messages)} messages in {end_time - start_time:.2f} seconds")

        return messages

    except aioimaplib.aioimaplib.Abort as e:
        # Protocol state error - connection got confused
        logger.error(f"IMAP protocol error (Abort): {e}")
        raise Exception(f"IMAP protocol error - connection state corrupted. Try refreshing.")
    except aioimaplib.AioImapException as e:
        logger.error(f"IMAP error: {e}")
        raise Exception(f"IMAP error: {str(e)}")
    except asyncio.TimeoutError:
        logger.error("IMAP operation timed out")
        raise Exception("Connection timed out - server may be slow or unresponsive")
    except Exception as e:
        logger.error(f"Error fetching messages: {e}")
        raise Exception(f"Error fetching messages: {str(e)}")
    finally:
        if client:
            try:
                await client.close()
                await client.logout()
            except:
                pass


def get_request_params():
    """Extract and validate request parameters from GET or POST"""
    if request.method == 'POST':
        data = request.json
    else:
        data = request.args

    server = data.get('server')
    username = data.get('username')
    password = data.get('password')

    if not all([server, username, password]):
        return None, {
            'error': 'Missing required parameters',
            'required': ['server', 'username', 'password']
        }, 400

    port = int(data.get('port', 993))
    folder = data.get('folder', 'INBOX')
    limit = int(data.get('limit', 10))

    # Enforce maximum message limit to prevent abuse
    if limit > MAX_MESSAGES_LIMIT:
        return None, {
            'error': f'Message limit too high. Maximum allowed: {MAX_MESSAGES_LIMIT}',
            'requested': limit,
            'maximum': MAX_MESSAGES_LIMIT
        }, 400

    gmail_category = data.get('gmail_category')

    unread_only = data.get('unread_only', False)
    if isinstance(unread_only, str):
        unread_only = unread_only.lower() == 'true'

    flagged_only = data.get('flagged_only', False)
    if isinstance(flagged_only, str):
        flagged_only = flagged_only.lower() == 'true'

    # Parse from_emails - can be comma-separated string or array
    from_emails = data.get('from_emails')
    if from_emails:
        if isinstance(from_emails, str):
            # Split by comma and clean whitespace
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
        """Get latest email messages via IMAP (fully async with caching)"""
        logger.info(f"Received {request.method} request to /messages from {get_client_ip()}")

        params, error, status_code = get_request_params()
        if error:
            logger.warning(f"Invalid request parameters: {error}")
            return jsonify(error), status_code

        logger.info(f"Request params: server={params['server']}, folder={params['folder']}, limit={params['limit']}, unread_only={params['unread_only']}, flagged_only={params['flagged_only']}, gmail_category={params.get('gmail_category')}, from_emails={params.get('from_emails')}")

        # Check for mock data mode
        if params['username'] == 'master@trmnl.com':
            logger.info("Detected master@trmnl.com - returning mock data")
            mock_response = load_mock_data()
            if mock_response:
                return jsonify(mock_response)
            else:
                return jsonify({'error': 'Failed to load mock data'}), 500

        # Check cache first
        cache_key = generate_cache_key(params)
        cached_response = get_cached_response(cache_key)
        if cached_response:
            logger.info("Returning cached response")
            return jsonify(cached_response)

        try:
            messages = await fetch_email_messages(
                params['server'],
                params['port'],
                params['username'],
                params['password'],
                params['folder'],
                params['limit'],
                params['unread_only'],
                params['gmail_category'],
                params['from_emails'],
                params['flagged_only']
            )

            response_data = {
                'success': True,
                'email': params['username'],
                'folder': params['folder'],
                'count': len(messages),
                'unread_only': params['unread_only'],
                'flagged_only': params['flagged_only'],
                'messages': messages,
                'fetched_at': datetime.now().isoformat()
            }

            if params['gmail_category']:
                response_data['gmail_category'] = params['gmail_category']

            if params['from_emails']:
                response_data['from_emails'] = params['from_emails']

            # Cache the response
            cache_response(cache_key, response_data)

            logger.info(f"Successfully fetched {len(messages)} messages")
            return jsonify(response_data)

        except Exception as e:
            error_msg = str(e)
            status_code = 401 if 'authentication' in error_msg.lower() or 'login' in error_msg.lower() else 500
            logger.error(f"Request failed with status {status_code}: {error_msg}")
            return jsonify({'error': error_msg}), status_code

    @app.route('/health')
    def health():
        """Health check endpoint"""
        client_ip = get_client_ip()
        allowed_ips = get_allowed_ips()
        is_whitelisted = client_ip in allowed_ips if ENABLE_IP_WHITELIST else True

        health_data = {
            'status': 'healthy',
            'service': 'imap-email-reader',
            'version': '13.0-optimized-batch-fetch',
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

    @app.route('/test-logging')
    def test_logging():
        """Test endpoint to verify logging is working"""
        logger.debug("🐛 DEBUG: Test debug message")
        logger.info("ℹ️  INFO: Test info message")
        logger.warning("⚠️  WARNING: Test warning message")
        logger.error("❌ ERROR: Test error message")

        return jsonify({
            'status': 'ok',
            'message': 'Check your logs - you should see 4 log messages',
            'config': {
                'pythonunbuffered': os.getenv('PYTHONUNBUFFERED'),
                'log_level': LOG_LEVEL
            }
        })


# Create app instance
app = create_app()

# Print immediately to confirm app is loading
logger.info("=" * 60)
logger.info("IMAP Email Reader - Module Loading")
logger.info(f"Python: {sys.version}")
logger.info(f"PYTHONUNBUFFERED: {os.getenv('PYTHONUNBUFFERED')}")
logger.info(f"LOG_LEVEL: {LOG_LEVEL}")
logger.info("=" * 60)


# Initialize TRMNL IPs on startup
async def startup_init():
    """Initialize TRMNL IPs on startup"""
    global TRMNL_IPS, last_ip_refresh

    logger.info("=" * 60)
    logger.info("Starting IMAP Email Reader")
    logger.info(f"IP Whitelist: {'Enabled' if ENABLE_IP_WHITELIST else 'Disabled'}")
    logger.info(f"Refresh Interval: {IP_REFRESH_HOURS} hours")

    if ENABLE_IP_WHITELIST:
        ips = await fetch_trmnl_ips()
        with TRMNL_IPS_LOCK:
            TRMNL_IPS = ips
            last_ip_refresh = datetime.now()

        start_ip_refresh_worker()
    else:
        logger.warning("IP whitelist is disabled - all IPs will be allowed!")

    # Test Redis connection if cache is enabled
    if ENABLE_CACHE:
        logger.info(f"Cache: ENABLED (TTL: {CACHE_TTL_SECONDS}s)")
        logger.info(f"Testing Redis connection to {REDIS_HOST}:{REDIS_PORT}...")
        client = get_redis_client()
        if client:
            logger.info("✓ Redis connection successful - cache ready")
        else:
            logger.warning("✗ Redis connection failed - cache disabled")
    else:
        logger.info("Cache: DISABLED")

    logger.info("=" * 60)
    logger.info("Startup Complete - Ready to accept requests")
    logger.info("=" * 60)


# Run startup initialization
try:
    logger.info("Running startup initialization...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup_init())
    loop.close()
    logger.info("Startup initialization complete!")
except Exception as e:
    logger.error(f"Startup error: {e}")
    logger.warning("Continuing with fallback IPs (localhost only)")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)