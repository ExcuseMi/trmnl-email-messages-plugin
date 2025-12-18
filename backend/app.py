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
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG').upper()  # Changed to DEBUG for debugging

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
                            flags_str = parts[1]

                            # Check for flags
                            is_read = '\\Seen' in flags_str
                            is_flagged = '\\Flagged' in flags_str

                            flags_dict[msg_id] = {
                                'read': is_read,
                                'flagged': is_flagged
                            }
                    except:
                        pass
    except Exception as e:
        logger.warning(f"Could not fetch flags in batch: {e}")

    return flags_dict


async def fetch_email_messages(server, port, username, password, folder, limit, unread_only, gmail_category=None, from_emails=None, flagged_only=False):
    """
    Optimized async IMAP fetch with batch flag fetching

    Args:
        gmail_category: Gmail category/tab filter (Primary, Social, Promotions, Updates, Forums)
        from_emails: List of sender email addresses to filter by (OR logic)
        flagged_only: Only fetch flagged/starred emails (IMAP \Flagged flag)
    """
    client = None
    try:
        start_time = time.time()
        logger.info(f"Fetching emails from {server}:{port} folder={folder} limit={limit} unread_only={unread_only} flagged_only={flagged_only}")

        # Create async IMAP client with longer timeout for large fetches
        client = aioimaplib.IMAP4_SSL(host=server, port=port, timeout=60)
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

        # OPTIMIZATION: Batch fetch all flags first
        flags_dict = await batch_fetch_flags(client, message_ids)

        messages = []

        # Fetch messages sequentially (IMAP protocol limitation - can't parallelize on same connection)
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

                # Get flags from batch fetch
                flags = flags_dict.get(msg_id, {'read': True, 'flagged': False})
                is_read = flags['read']
                is_flagged = flags['flagged']

                message = parse_message_data(header_data, msg_id, is_read, is_flagged)
                if message:
                    messages.append(message)

            except Exception as e:
                logger.error(f"Error processing message {msg_id}: {e}")
                continue

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
    limit = min(int(data.get('limit', 10)), 50)
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
        """Get latest email messages via IMAP (fully async)"""
        print(f"[/messages] Received {request.method} request", flush=True)
        logger.info(f"Received {request.method} request to /messages from {get_client_ip()}")

        params, error, status_code = get_request_params()
        if error:
            logger.warning(f"Invalid request parameters: {error}")
            return jsonify(error), status_code

        print(f"[/messages] Params: server={params['server']}, folder={params['folder']}", flush=True)
        logger.info(f"Request params: server={params['server']}, folder={params['folder']}, limit={params['limit']}, unread_only={params['unread_only']}, flagged_only={params['flagged_only']}, gmail_category={params.get('gmail_category')}, from_emails={params.get('from_emails')}")

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

            # Debug: Log first message to verify sender_email is present
            if messages:
                print(f"[DEBUG] First message keys: {list(messages[0].keys())}", flush=True)
                print(f"[DEBUG] First message sender_email: {messages[0].get('sender_email', 'MISSING!')}", flush=True)
                logger.info(f"First message contains: {messages[0]}")

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