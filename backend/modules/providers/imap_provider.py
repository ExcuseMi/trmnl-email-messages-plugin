"""
IMAP Email Provider
Fetches emails using IMAP protocol with password or OAuth2 authentication
"""
import aioimaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime
import asyncio
import ssl
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


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


class IMAPProvider:
    """Generic IMAP email provider"""

    def __init__(
            self,
            connect_timeout: int = 10,
            login_timeout: int = 15,
            fetch_timeout: int = 30
    ):
        self.connect_timeout = connect_timeout
        self.login_timeout = login_timeout
        self.fetch_timeout = fetch_timeout

    async def fetch_messages(
            self,
            server: str,
            port: int,
            username: str,
            password: Optional[str],
            folder: str = 'INBOX',
            limit: int = 10,
            unread_only: bool = False,
            flagged_only: bool = False,
            gmail_category: Optional[str] = None,
            from_emails: Optional[List[str]] = None,
            oauth_token: Optional[str] = None,
            request_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch messages via IMAP

        Args:
            server: IMAP server hostname
            port: IMAP port (usually 993)
            username: Email username
            password: Email password (app password recommended)
            folder: IMAP folder name
            limit: Maximum number of messages
            unread_only: Only fetch unread messages
            flagged_only: Only fetch flagged messages
            gmail_category: Gmail category filter
            from_emails: List of sender emails/domains
            oauth_token: OAuth2 token (for OAuth authentication)
            request_id: Request ID for logging

        Returns:
            List of message dictionaries
        """
        client = None
        req_prefix = f"[{request_id}]" if request_id else ""
        authenticated = False

        try:
            start_time = datetime.now()

            # Create SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            # Create IMAP client
            client = aioimaplib.IMAP4_SSL(
                host=server,
                port=port,
                timeout=self.connect_timeout,
                ssl_context=ssl_context
            )

            # Wait for server hello
            try:
                await asyncio.wait_for(
                    client.wait_hello_from_server(),
                    timeout=self.connect_timeout
                )
            except asyncio.TimeoutError:
                raise IMAPConnectionError(f'Connection timeout to {server}:{port}')

            # Login - OAuth or Password
            try:
                if oauth_token:
                    # OAuth2 authentication
                    await self._oauth_login(client, username, oauth_token, req_prefix)
                else:
                    # Password authentication
                    login_response = await asyncio.wait_for(
                        client.login(username, password),
                        timeout=self.login_timeout
                    )
                    if login_response.result != 'OK':
                        raise IMAPAuthenticationError('Invalid credentials')

                authenticated = True

            except asyncio.TimeoutError:
                raise IMAPTimeoutError(f'Login operation timed out after {self.login_timeout}s')
            except IMAPAuthenticationError:
                raise
            except Exception as e:
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
                raise IMAPTimeoutError('Folder selection timed out')

            # Build search criteria
            search_criteria = self._build_search_criteria(
                unread_only,
                flagged_only,
                gmail_category,
                from_emails
            )

            # Search messages
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

            # Get most recent messages
            message_ids.reverse()
            message_ids = message_ids[:limit]

            # Fetch message details
            msg_id_str = ','.join(message_ids)

            try:
                fetch_response = await asyncio.wait_for(
                    client.fetch(
                        msg_id_str,
                        '(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])'
                    ),
                    timeout=self.fetch_timeout
                )

                if fetch_response.result != 'OK':
                    raise IMAPProtocolError('Fetch failed')
            except asyncio.TimeoutError:
                raise IMAPTimeoutError(f'Fetch operation timed out after {self.fetch_timeout}s')

            # Parse messages
            messages = self._parse_fetch_response(fetch_response)

            elapsed = (datetime.now() - start_time).total_seconds()
            logger.info(f"{req_prefix} ✓ Fetched {len(messages)} messages in {elapsed:.2f}s")

            # Sort by timestamp (newest first)
            messages.sort(
                key=lambda x: datetime.fromisoformat(x['timestamp']),
                reverse=True
            )

            return messages

        except IMAPAuthenticationError:
            logger.error(f"{req_prefix} ✗ Auth failed")
            raise
        except IMAPTimeoutError as e:
            logger.error(f"{req_prefix} ✗ Timeout: {e}")
            raise
        except IMAPConnectionError as e:
            logger.error(f"{req_prefix} ✗ Connection error: {e}")
            raise
        except aioimaplib.aioimaplib.Abort as e:
            logger.error(f"{req_prefix} ✗ IMAP protocol error: {e}")
            if authenticated:
                raise IMAPProtocolError(f"IMAP protocol state error: {str(e)}")
            else:
                raise IMAPAuthenticationError(f"IMAP protocol error during authentication: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"{req_prefix} ✗ Operation timed out")
            raise IMAPTimeoutError("Operation timed out")
        except Exception as e:
            logger.error(f"{req_prefix} ✗ Unexpected error: {e}")
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['authentication', 'credentials', 'password']):
                raise IMAPAuthenticationError(str(e))
            elif 'timeout' in error_str:
                raise IMAPTimeoutError(str(e))
            elif any(keyword in error_str for keyword in ['connection', 'unreachable', 'refused']):
                raise IMAPConnectionError(str(e))
            else:
                raise IMAPProtocolError(f"Error: {str(e)}")

        finally:
            await self._cleanup_connection(client, request_id)

    async def _oauth_login(
            self,
            client: aioimaplib.IMAP4_SSL,
            username: str,
            oauth_token: str,
            req_prefix: str
    ):
        """Perform OAuth2 XOAUTH2 authentication"""
        import base64

        # Generate XOAUTH2 string
        auth_string = f"user={username}\x01auth=Bearer {oauth_token}\x01\x01"
        auth_string_b64 = base64.b64encode(auth_string.encode()).decode()

        # Get tag
        tag = client.protocol.new_tag()
        if isinstance(tag, bytes):
            tag = tag.decode()

        # Send AUTHENTICATE XOAUTH2
        auth_cmd = f'{tag} AUTHENTICATE XOAUTH2\r\n'
        client.protocol.transport.write(auth_cmd.encode())

        # Wait for + continuation
        await asyncio.sleep(0.2)

        # Send base64 auth string
        client.protocol.transport.write(f'{auth_string_b64}\r\n'.encode())

        # Wait for response
        await asyncio.sleep(0.5)

        # Verify with NOOP
        try:
            noop_response = await asyncio.wait_for(client.noop(), timeout=5)

            if noop_response.result == 'OK':
                logger.debug(f"{req_prefix} ✓ OAuth authentication successful")
            else:
                raise IMAPAuthenticationError('OAuth authentication verification failed')
        except Exception as e:
            error_str = str(e).lower()
            if 'authenticationfailed' in error_str or 'invalid credentials' in error_str:
                raise IMAPAuthenticationError(
                    'OAuth token rejected. Token may be expired or missing required scope (https://mail.google.com/). '
                    'Disconnect and reconnect Gmail in TRMNL to get a fresh token.'
                )
            raise IMAPAuthenticationError(f'OAuth verification error: {e}')

    def _build_search_criteria(
            self,
            unread_only: bool,
            flagged_only: bool,
            gmail_category: Optional[str],
            from_emails: Optional[List[str]]
    ) -> str:
        """Build IMAP search criteria"""
        search_parts = []

        if gmail_category:
            # Gmail-specific category search
            gmail_parts = [f'category:{gmail_category.lower()}']
            if unread_only:
                gmail_parts.append('is:unread')
            if flagged_only:
                gmail_parts.append('is:starred')

            if from_emails:
                if len(from_emails) == 1:
                    gmail_parts.append(f'from:{from_emails[0]}')
                else:
                    from_query = ' OR '.join([f'from:{email}' for email in from_emails])
                    gmail_parts.append(f'({from_query})')

            return f'X-GM-RAW "{" ".join(gmail_parts)}"'
        else:
            # Standard IMAP search
            if unread_only:
                search_parts.append('UNSEEN')
            if flagged_only:
                search_parts.append('FLAGGED')

            if from_emails:
                if len(from_emails) == 1:
                    search_parts.append(f'FROM "{from_emails[0]}"')
                else:
                    or_query = f'FROM "{from_emails[0]}"'
                    for email_addr in from_emails[1:]:
                        or_query = f'OR ({or_query}) (FROM "{email_addr}")'
                    search_parts.append(or_query)

            if not search_parts:
                search_parts.append('ALL')

            return ' '.join(search_parts)

    def _parse_fetch_response(
            self,
            fetch_response
    ) -> List[Dict[str, Any]]:
        """Parse IMAP FETCH response"""
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
                    # Save previous message
                    if current_msg_id and header_lines:
                        header_data = b''.join(header_lines)
                        message = self._parse_message_data(
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

                elif current_msg_id and not in_headers and (
                        b'From:' in line_bytes or b'Subject:' in line_bytes or b'Date:' in line_bytes):
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

        # Save last message
        if current_msg_id and header_lines:
            header_data = b''.join(header_lines)
            message = self._parse_message_data(
                header_data,
                current_msg_id,
                current_flags.get('read', True),
                current_flags.get('flagged', False)
            )
            if message:
                messages.append(message)

        return messages

    def _parse_message_data(
            self,
            header_data: bytes,
            msg_id: str,
            is_read: bool,
            is_flagged: bool
    ) -> Optional[Dict[str, Any]]:
        """Parse message headers into dict"""
        try:
            email_message = email.message_from_bytes(header_data)
        except Exception as e:
            logger.error(f"✗ Failed to parse message {msg_id}: {e}")
            return None

        from_header = email_message.get('From', '')
        sender = self._extract_sender_name(from_header)
        subject = self._decode_mime_header(email_message.get('Subject', 'No Subject'))
        date_str = email_message.get('Date', '')

        sender_email = ""
        if from_header:
            decoded_from = self._decode_mime_header(from_header)
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

    def _decode_mime_header(self, header: str) -> str:
        """Decode MIME encoded header"""
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

    def _extract_sender_name(self, from_header: str) -> str:
        """Extract sender name from From header"""
        if not from_header:
            return "Unknown"

        decoded = self._decode_mime_header(from_header)

        if '<' in decoded and '>' in decoded:
            name = decoded.split('<')[0].strip().replace('"', '').replace("'", "")
            if name:
                return name
            email_addr = decoded.split('<')[1].split('>')[0].strip()
            return email_addr

        return decoded.strip()

    async def _cleanup_connection(
            self,
            client,
            request_id: Optional[str] = None
    ):
        """Safely cleanup IMAP connection"""
        if not client:
            return

        req_prefix = f"[{request_id}]" if request_id else ""

        try:
            await asyncio.wait_for(client.close(), timeout=2.0)
        except asyncio.TimeoutError:
            logger.debug(f"{req_prefix} ⚠️  IMAP close timed out")
        except Exception as e:
            logger.debug(f"{req_prefix} ⚠️  IMAP close error: {e}")

        try:
            await asyncio.wait_for(client.logout(), timeout=2.0)
        except asyncio.TimeoutError:
            logger.debug(f"{req_prefix} ⚠️  IMAP logout timed out")
        except Exception as e:
            logger.debug(f"{req_prefix} ⚠️  IMAP logout error: {e}")