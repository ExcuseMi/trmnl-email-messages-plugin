"""
IMAP Email Reader - Flask Backend for TRMNL
Using imap-tools for robust, fast IMAP access
"""

from flask import Flask, request, jsonify
from imap_tools import MailBox
import email
from email.header import decode_header
from datetime import datetime
import time
import os
from functools import wraps
import asyncio
import httpx
import threading
import logging
import sys
from concurrent.futures import ThreadPoolExecutor


# Configuration
ENABLE_IP_WHITELIST = os.getenv('ENABLE_IP_WHITELIST', 'true').lower() == 'true'
IP_REFRESH_HOURS = int(os.getenv('IP_REFRESH_HOURS', '24'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

# TRMNL API endpoint for IP addresses
TRMNL_IPS_API = 'https://usetrmnl.com/api/ips'

# Configure logging
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    handlers=[log_handler],
    force=True
)

logger = logging.getLogger(__name__)
logger.info(f"Logging initialized at level: {LOG_LEVEL}")

# Disable Flask's default logger
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Ensure logs are flushed immediately
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Thread pool for running synchronous IMAP operations
executor = ThreadPoolExecutor(max_workers=10)

# Global variables for IP whitelist
allowed_ips = set()
last_ip_refresh = None
ip_refresh_lock = threading.Lock()

app = Flask(__name__)


print("=" * 60)
print("IMAP Email Reader - Module Loading")
print(f"Python: {sys.version}")
print(f"PYTHONUNBUFFERED: {os.getenv('PYTHONUNBUFFERED', 'not set')}")
print(f"LOG_LEVEL: {LOG_LEVEL}")
print("=" * 60)


def startup_init():
    """Initialize on startup"""
    global allowed_ips, last_ip_refresh

    print("=" * 60)
    print("Running startup_init()")
    print("=" * 60)

    logger.info("Starting IMAP Email Reader")

    if ENABLE_IP_WHITELIST:
        logger.info("IP Whitelist: Enabled")
        try:
            fetch_trmnl_ips()
            if allowed_ips:
                logger.info(f"Startup: Loaded {len(allowed_ips)} whitelisted IPs")
            else:
                logger.error("Startup: Failed to load any IPs - whitelist won't work!")
        except Exception as e:
            logger.error(f"Startup: Failed to fetch IPs: {e}")
    else:
        logger.info("IP Whitelist: Disabled")

    logger.info("Startup Complete - Ready to accept requests")
    print("Startup initialization complete!")


def fetch_trmnl_ips():
    """Fetch and cache allowed IPs from TRMNL API"""
    global allowed_ips, last_ip_refresh

    print(f"[fetch_trmnl_ips] Fetching from {TRMNL_IPS_API}")
    logger.info(f"Fetching TRMNL IPs from {TRMNL_IPS_API}")

    try:
        response = httpx.get(TRMNL_IPS_API, timeout=10.0)
        response.raise_for_status()

        ip_data = response.json()

        # Handle both formats: {"data": {"ipv4": [], "ipv6": []}} or {"ipv4": [], "ipv6": []}
        if 'data' in ip_data:
            ip_data = ip_data['data']

        new_ips = set()

        ipv4_list = ip_data.get('ipv4', [])
        ipv6_list = ip_data.get('ipv6', [])

        new_ips.update(ipv4_list)
        new_ips.update(ipv6_list)

        if new_ips:
            with ip_refresh_lock:
                allowed_ips = new_ips
                last_ip_refresh = datetime.now()

            print(f"[fetch_trmnl_ips] SUCCESS: Fetched {len(new_ips)} IPs ({len(ipv4_list)} IPv4, {len(ipv6_list)} IPv6)")
            logger.info(f"SUCCESS: Fetched {len(new_ips)} TRMNL IPs ({len(ipv4_list)} IPv4, {len(ipv6_list)} IPv6)")

            # Debug: Show first few IPs
            sample_ips = list(new_ips)[:3]
            print(f"[fetch_trmnl_ips] Sample IPs: {sample_ips}")
            logger.debug(f"Sample IPs: {sample_ips}")
        else:
            print("[fetch_trmnl_ips] ERROR: No IPs returned from API!")
            logger.error("No IPs returned from TRMNL API")

    except Exception as e:
        print(f"[fetch_trmnl_ips] EXCEPTION: {e}")
        logger.error(f"Failed to fetch TRMNL IPs: {e}")
        import traceback
        traceback.print_exc()


def get_client_ip():
    """Get the real client IP address"""
    client_ip = (
        request.headers.get('CF-Connecting-IP') or
        request.headers.get('X-Forwarded-For') or
        request.headers.get('X-Real-IP') or
        request.remote_addr
    )

    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    return client_ip


def require_whitelisted_ip(f):
    """Decorator to enforce IP whitelist"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not ENABLE_IP_WHITELIST:
            return await f(*args, **kwargs)

        client_ip = get_client_ip()

        # Check if we need to refresh IPs
        if last_ip_refresh and (datetime.now() - last_ip_refresh).total_seconds() > (IP_REFRESH_HOURS * 3600):
            threading.Thread(target=fetch_trmnl_ips, daemon=True).start()

        # Debug log
        logger.debug(f"Checking IP: {client_ip}, Whitelist has {len(allowed_ips)} IPs, Match: {client_ip in allowed_ips}")

        if client_ip in allowed_ips:
            logger.debug(f"Allowed request from whitelisted IP: {client_ip}")
            return await f(*args, **kwargs)
        else:
            logger.warning(f"Blocked request from unauthorized IP: {client_ip} (whitelist has {len(allowed_ips)} IPs)")
            return jsonify({'error': 'Unauthorized IP address'}), 403

    return decorated_function


def build_search_criteria(unread_only, flagged_only, from_emails, gmail_category):
    """Build search criteria string"""
    if gmail_category:
        gmail_parts = [f'category:{gmail_category.lower()}']
        if unread_only:
            gmail_parts.append('is:unread')
        if flagged_only:
            gmail_parts.append('is:starred')
        if from_emails:
            if len(from_emails) == 1:
                gmail_parts.append(f'from:{from_emails[0]}')
            else:
                from_query = ' OR '.join([f'from:{e}' for e in from_emails])
                gmail_parts.append(f'({from_query})')
        return f'X-GM-RAW "{" ".join(gmail_parts)}"'

    criteria = []
    if unread_only:
        criteria.append('UNSEEN')
    if flagged_only:
        criteria.append('FLAGGED')
    if from_emails:
        if len(from_emails) == 1:
            criteria.append(f'FROM "{from_emails[0]}"')
        else:
            or_query = f'FROM "{from_emails[0]}"'
            for e in from_emails[1:]:
                or_query = f'OR ({or_query}) (FROM "{e}")'
            criteria.append(or_query)

    return ' '.join(criteria) if criteria else 'ALL'


def fetch_email_messages_sync(server, port, username, password, folder, limit, unread_only, flagged_only, from_emails, gmail_category):
    """Synchronous IMAP fetch using imap-tools"""
    start_time = time.time()
    messages = []

    try:
        logger.info(f"Connecting to {server}:{port} folder={folder}")

        with MailBox(server, port).login(username, password, initial_folder=folder) as mailbox:
            search_str = build_search_criteria(unread_only, flagged_only, from_emails, gmail_category)
            logger.info(f"Search: {search_str}")

            msg_list = list(mailbox.fetch(
                criteria=search_str,
                limit=limit,
                reverse=True,
                mark_seen=False
            ))

            logger.info(f"Found {len(msg_list)} messages")

            for msg in msg_list:
                try:
                    sender_name = msg.from_values.name or msg.from_
                    messages.append({
                        'sender': sender_name,
                        'sender_email': msg.from_,
                        'subject': msg.subject or 'No Subject',
                        'timestamp': msg.date.isoformat() if msg.date else datetime.now().isoformat(),
                        'msg_id': msg.uid,
                        'read': 'SEEN' in msg.flags,
                        'flagged': 'FLAGGED' in msg.flags
                    })
                except Exception as e:
                    logger.error(f"Error parsing message: {e}")

            logger.info(f"Fetched {len(messages)} messages in {time.time() - start_time:.2f}s")
            return messages

    except Exception as e:
        logger.error(f"IMAP error: {e}")
        raise Exception(f"Error: {str(e)}")


async def fetch_email_messages(server, port, username, password, folder, limit, unread_only, flagged_only, from_emails, gmail_category):
    """Async wrapper"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        executor,
        fetch_email_messages_sync,
        server, port, username, password, folder, limit, unread_only, flagged_only, from_emails, gmail_category
    )


def get_request_params():
    """Extract request parameters"""
    data = request.json if request.method == 'POST' else request.args

    server = data.get('server')
    username = data.get('username')
    password = data.get('password')

    if not all([server, username, password]):
        return None, {'error': 'Missing required parameters', 'required': ['server', 'username', 'password']}, 400

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

    from_emails = data.get('from_emails')
    if from_emails:
        if isinstance(from_emails, str):
            from_emails = [e.strip() for e in from_emails.split(',') if e.strip()]
        elif isinstance(from_emails, list):
            from_emails = [e.strip() for e in from_emails if isinstance(e, str) and e.strip()]
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


@app.route('/messages', methods=['GET', 'POST'])
@require_whitelisted_ip
async def get_messages():
    """Fetch emails"""
    logger.info(f"Request from {get_client_ip()}")

    params, error, status = get_request_params()
    if error:
        return jsonify(error), status

    logger.info(f"Params: {params['server']}, folder={params['folder']}, limit={params['limit']}")

    try:
        messages = await fetch_email_messages(
            params['server'], params['port'], params['username'], params['password'],
            params['folder'], params['limit'], params['unread_only'], params['flagged_only'],
            params['from_emails'], params['gmail_category']
        )

        response = {
            'success': True,
            'folder': params['folder'],
            'count': len(messages),
            'messages': messages,
            'fetched_at': datetime.now().isoformat()
        }

        logger.info(f"Success: {len(messages)} messages")
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': str(e)}), 401


@app.route('/')
async def index():
    return jsonify({'status': 'ok', 'service': 'IMAP Email Reader', 'library': 'imap-tools'})


@app.route('/health')
async def health():
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    startup_init()
    app.run(host='0.0.0.0', port=5000)
else:
    startup_init()