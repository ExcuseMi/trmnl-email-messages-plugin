"""
Async IMAP Email Reader - Flask Backend for TRMNL
Optimized version with minimal duplication and maximum performance
"""

from flask import Flask, request, jsonify
import aioimaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime
import time
import os
from functools import wraps
import asyncio
import httpx
import threading
import logging
import sys


# Configuration
ENABLE_IP_WHITELIST = os.getenv('ENABLE_IP_WHITELIST', 'true').lower() == 'true'
IP_REFRESH_HOURS = int(os.getenv('IP_REFRESH_HOURS', '24'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

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


async def fetch_trmnl_ips():
    """Fetch current TRMNL server IPs from their API"""
    try:
        print(f"[fetch_trmnl_ips] Fetching from {TRMNL_IPS_API}", flush=True)
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

            print(f"[fetch_trmnl_ips] Fetched {len(ips)} IPs ({ipv4_count} IPv4, {ipv6_count} IPv6)", flush=True)
            logger.info(f"Fetched {len(ips)} TRMNL IPs ({ipv4_count} IPv4, {ipv6_count} IPv6)")
            logger.debug(f"Whitelisted IPs: {sorted(list(ips))}")
            return ips

    except Exception as e:
        print(f"[fetch_trmnl_ips] ERROR: {e}", flush=True)
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


def get_allowed_ips():
    """Get current list of allowed IPs from TRMNL API"""
    with TRMNL_IPS_LOCK:
        return TRMNL_IPS.copy()


def get_client_ip():
    """Get the real client IP address, accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP').strip()
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

    if '<' in decoded:
        name = decoded.split('<')[0].strip().replace('"', '').replace("'", "")
        return name if name else decoded

    return decoded.strip()


def extract_header_data(fetch_response):
    """Extract header data from IMAP fetch response"""
    # Method 1: Look for header data in line 1 (most common)
    if len(fetch_response.lines) > 1:
        line1 = fetch_response.lines[1]
        if isinstance(line1, (bytes, bytearray)):
            header_data = bytes(line1) if isinstance(line1, bytearray) else line1
            if header_data.endswith(b'\r\n\r\n'):
                header_data = header_data[:-2]
            if b'Date:' in header_data or b'From:' in header_data:
                return header_data

    # Method 2: Search all lines for header data
    for line in fetch_response.lines:
        if isinstance(line, (bytes, bytearray)):
            line_bytes = bytes(line) if isinstance(line, bytearray) else line
            if b'Date:' in line_bytes or b'From:' in line_bytes:
                if line_bytes.endswith(b'\r\n\r\n'):
                    line_bytes = line_bytes[:-2]
                return line_bytes

    return None


def parse_message_data(header_data, msg_id, is_read=True):
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
        'read': is_read
    }

    # Log the final message dict to verify sender_email is included
    logger.debug(f"Created message dict: {message_dict}")

    return message_dict


async def batch_fetch_flags(client, message_ids):
    """Fetch flags for all messages in one batch request"""
    flags_dict = {}
    try:
        msg_id_str = ','.join(message_ids)
        flags_response = await client.fetch(msg_id_str, '(FLAGS)')

        if flags_response.result == 'OK':
            for line in flags_response.lines:
                if isinstance(line, (bytes, bytearray)):
                    line_bytes = bytes(line) if isinstance(line, bytearray) else line
                    try:
                        line_str = line_bytes.decode('utf-8', errors='ignore')
                        if ' FETCH ' in line_str:
                            parts = line_str.split(' FETCH ', 1)
                            msg_id = parts[0].strip()
                            is_read = '\\Seen' in parts[1]
                            flags_dict[msg_id] = is_read
                    except:
                        pass
    except Exception as e:
        logger.warning(f"Could not fetch flags in batch: {e}")

    return flags_dict


async def fetch_email_messages(server, port, username, password, folder, limit, unread_only, gmail_category=None):
    """
    Optimized async IMAP fetch with batch flag fetching

    Args:
        gmail_category: Gmail category/tab filter (Primary, Social, Promotions, Updates, Forums)
    """
    client = None
    try:
        start_time = time.time()
        logger.info(f"Fetching emails from {server}:{port} folder={folder} limit={limit} unread_only={unread_only}")

        # Create async IMAP client
        client = aioimaplib.IMAP4_SSL(host=server, port=port, timeout=30)
        await client.wait_hello_from_server()

        # Login
        login_response = await client.login(username, password)
        if login_response.result != 'OK':
            raise Exception(f'Login failed: {login_response.lines}')
        logger.debug(f"Successfully logged in to {server}")

        # Select folder
        select_response = await client.select(folder)
        if select_response.result != 'OK':
            raise Exception(f'Failed to select folder {folder}: {select_response.lines}')

        # Search for messages
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

            if unread_only:
                search_criteria = f'X-GM-RAW "category:{gmail_category.lower()} is:unread"'
            else:
                search_criteria = f'X-GM-RAW "category:{gmail_category.lower()}"'

            logger.debug(f"Using search criteria: {search_criteria}")
        else:
            search_criteria = 'UNSEEN' if unread_only else 'ALL'

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

        # OPTIMIZATION: Batch fetch all flags first
        flags_dict = await batch_fetch_flags(client, message_ids)

        messages = []

        # Fetch messages sequentially
        for msg_id in message_ids:
            try:
                fetch_response = await client.fetch(
                    msg_id,
                    '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])'
                )

                if fetch_response.result != 'OK':
                    continue

                header_data = extract_header_data(fetch_response)
                if not header_data:
                    continue

                is_read = flags_dict.get(msg_id, True)

                message = parse_message_data(header_data, msg_id, is_read)
                if message:
                    messages.append(message)

            except Exception as e:
                logger.error(f"Error processing message {msg_id}: {e}")
                continue

        end_time = time.time()
        logger.info(f"Fetched {len(messages)} messages in {end_time - start_time:.2f} seconds")

        return messages

    except aioimaplib.AioImapException as e:
        logger.error(f"IMAP error: {e}")
        raise Exception(f"IMAP error: {str(e)}")
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
    limit = min(int(data.get('limit', 10)), 50)
    gmail_category = data.get('gmail_category')

    unread_only = data.get('unread_only', False)
    if isinstance(unread_only, str):
        unread_only = unread_only.lower() == 'true'

    return {
        'server': server,
        'port': port,
        'username': username,
        'password': password,
        'folder': folder,
        'limit': limit,
        'unread_only': unread_only,
        'gmail_category': gmail_category
    }, None, None


def register_routes(app):
    """Register all Flask routes"""

    @app.route('/messages', methods=['GET', 'POST'])
    @require_whitelisted_ip
    async def get_messages():
        """Get latest email messages via IMAP (fully async)"""
        print(f"[/messages] Received {request.method} request", flush=True)
        logger.info(f"Received {request.method} request to /messages from {get_client_ip()}")

        params, error, status_code = get_request_params()
        if error:
            logger.warning(f"Invalid request parameters: {error}")
            return jsonify(error), status_code

        print(f"[/messages] Params: server={params['server']}, folder={params['folder']}", flush=True)
        logger.info(f"Request params: server={params['server']}, folder={params['folder']}, limit={params['limit']}, unread_only={params['unread_only']}, gmail_category={params.get('gmail_category')}")

        try:
            messages = await fetch_email_messages(
                params['server'],
                params['port'],
                params['username'],
                params['password'],
                params['folder'],
                params['limit'],
                params['unread_only'],
                params['gmail_category']
            )

            response_data = {
                'success': True,
                'folder': params['folder'],
                'count': len(messages),
                'unread_only': params['unread_only'],
                'messages': messages,
                'fetched_at': datetime.now().isoformat()
            }

            if params['gmail_category']:
                response_data['gmail_category'] = params['gmail_category']

            print(f"[/messages] Successfully fetched {len(messages)} messages", flush=True)
            logger.info(f"Successfully fetched {len(messages)} messages")
            return jsonify(response_data)

        except Exception as e:
            error_msg = str(e)
            status_code = 401 if 'authentication' in error_msg.lower() or 'login' in error_msg.lower() else 500
            print(f"[/messages] ERROR: {error_msg}", flush=True)
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
            'version': '12.2-docker-logging',
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

        # Direct stdout/stderr test
        print("DIRECT STDOUT: Print test", flush=True)
        print("DIRECT STDERR: Stderr test", file=sys.stderr, flush=True)

        return jsonify({
            'status': 'ok',
            'message': 'Check your logs - you should see 4 log messages + 2 print statements',
            'config': {
                'pythonunbuffered': os.getenv('PYTHONUNBUFFERED'),
                'log_level': LOG_LEVEL,
                'stdout_line_buffering': sys.stdout.line_buffering,
                'stderr_line_buffering': sys.stderr.line_buffering
            }
        })


# Create app instance
app = create_app()

# Print immediately to confirm app is loading
print("=" * 60, flush=True)
print("IMAP Email Reader - Module Loading", flush=True)
print(f"Python: {sys.version}", flush=True)
print(f"PYTHONUNBUFFERED: {os.getenv('PYTHONUNBUFFERED')}", flush=True)
print(f"LOG_LEVEL: {LOG_LEVEL}", flush=True)
print("=" * 60, flush=True)


# Initialize TRMNL IPs on startup
async def startup_init():
    """Initialize TRMNL IPs on startup"""
    global TRMNL_IPS, last_ip_refresh

    print("=" * 60, flush=True)
    print("Running startup_init()", flush=True)
    print("=" * 60, flush=True)

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

    logger.info("=" * 60)
    logger.info("Startup Complete - Ready to accept requests")
    logger.info("=" * 60)


# Run startup initialization
try:
    print("About to run startup initialization...", flush=True)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup_init())
    loop.close()
    print("Startup initialization complete!", flush=True)
except Exception as e:
    print(f"ERROR in startup: {e}", flush=True)
    logger.error(f"Startup error: {e}")
    logger.warning("Continuing with fallback IPs (localhost only)")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)