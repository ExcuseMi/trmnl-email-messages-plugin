"""
Gmail REST API provider
Fetches emails using Gmail API v1 with OAuth2 authentication
"""
import httpx
import asyncio
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class GmailAPIError(Exception):
    """Gmail API error"""
    pass


class GmailAuthError(Exception):
    """Gmail authentication error"""
    pass


class GmailAPIProvider:
    """Gmail REST API email provider"""

    GMAIL_API_BASE = 'https://gmail.googleapis.com/gmail/v1'
    DEFAULT_TIMEOUT = 30
    MAX_MESSAGES_PER_REQUEST = 50

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    async def fetch_messages(
            self,
            oauth_token: str,
            folder: str = 'INBOX',
            limit: int = 10,
            unread_only: bool = False,
            flagged_only: bool = False,
            gmail_category: Optional[str] = None,
            from_emails: Optional[List[str]] = None,
            request_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch messages from Gmail API

        Args:
            oauth_token: OAuth2 access token
            folder: Label ID (INBOX, SENT, DRAFT, etc.)
            limit: Maximum number of messages
            unread_only: Only fetch unread messages
            flagged_only: Only fetch starred messages
            gmail_category: Gmail category filter (primary, social, promotions, updates, forums)
            from_emails: List of sender emails/domains to filter
            request_id: Request ID for logging

        Returns:
            List of message dictionaries
        """
        req_prefix = f"[{request_id}]" if request_id else ""

        try:
            start_time = datetime.now()

            # Build Gmail search query
            query_parts = []

            if unread_only:
                query_parts.append('is:unread')

            if flagged_only:
                query_parts.append('is:starred')

            if gmail_category:
                query_parts.append(f'category:{gmail_category.lower()}')

            if from_emails:
                # Support domain filtering (@example.com) and email filtering
                from_queries = []
                for email in from_emails:
                    if email.startswith('@'):
                        # Domain filter: @example.com
                        from_queries.append(f'from:{email}')
                    else:
                        # Email or partial match
                        from_queries.append(f'from:{email}')

                if len(from_queries) == 1:
                    query_parts.append(from_queries[0])
                else:
                    query_parts.append(f"({' OR '.join(from_queries)})")

            # Build request parameters
            params = {
                'maxResults': min(limit, self.MAX_MESSAGES_PER_REQUEST),
                'labelIds': [folder]
            }

            if query_parts:
                params['q'] = ' '.join(query_parts)

            headers = {
                'Authorization': f'Bearer {oauth_token}',
                'Accept': 'application/json'
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Step 1: List messages (get IDs)
                list_url = f'{self.GMAIL_API_BASE}/users/me/messages'

                logger.debug(f"{req_prefix} Gmail API request: {params}")

                list_response = await client.get(list_url, headers=headers, params=params)

                if list_response.status_code == 401:
                    raise GmailAuthError('OAuth token expired or invalid')
                elif list_response.status_code == 403:
                    raise GmailAPIError('Insufficient permissions - check OAuth scopes')

                list_response.raise_for_status()
                list_data = list_response.json()

                message_ids = [msg['id'] for msg in list_data.get('messages', [])]

                if not message_ids:
                    logger.info(f"{req_prefix} ✓ No messages found")
                    return []

                # Step 2: Fetch message details (in parallel for speed)
                messages = []

                # Create tasks for parallel fetching
                fetch_tasks = [
                    self._fetch_message_detail(client, headers, msg_id, req_prefix)
                    for msg_id in message_ids
                ]

                # Execute all fetches in parallel
                message_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

                # Process results
                for result in message_results:
                    if isinstance(result, Exception):
                        logger.warning(f"{req_prefix} Failed to fetch message: {result}")
                        continue
                    if result:
                        messages.append(result)

                elapsed = (datetime.now() - start_time).total_seconds()
                logger.info(f"{req_prefix} ✓ Fetched {len(messages)} messages in {elapsed:.2f}s")

                # Sort by timestamp (newest first)
                messages.sort(
                    key=lambda x: datetime.fromisoformat(x['timestamp']),
                    reverse=True
                )

                return messages

        except GmailAuthError:
            raise
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise GmailAuthError('OAuth token expired or invalid')
            elif e.response.status_code == 403:
                raise GmailAPIError('Insufficient permissions')
            else:
                raise GmailAPIError(f'Gmail API error: {e.response.status_code} - {e.response.text}')
        except httpx.TimeoutException:
            raise GmailAPIError('Gmail API request timed out')
        except Exception as e:
            raise GmailAPIError(f'Unexpected error: {str(e)}')

    async def _fetch_message_detail(
            self,
            client: httpx.AsyncClient,
            headers: Dict[str, str],
            msg_id: str,
            req_prefix: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch details for a single message"""
        try:
            msg_url = f'{self.GMAIL_API_BASE}/users/me/messages/{msg_id}'
            msg_params = {
                'format': 'metadata',
                'metadataHeaders': ['From', 'Subject', 'Date']
            }

            msg_response = await client.get(msg_url, headers=headers, params=msg_params)
            msg_response.raise_for_status()
            msg_data = msg_response.json()

            return self._parse_message(msg_data)

        except Exception as e:
            logger.warning(f"{req_prefix} Failed to fetch message {msg_id}: {e}")
            return None

    def _parse_message(self, msg_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Gmail API message into standardized format"""
        try:
            # Extract headers
            headers = {
                h['name']: h['value']
                for h in msg_data.get('payload', {}).get('headers', [])
            }

            # Parse From header
            from_header = headers.get('From', '')
            sender_name, sender_email = self._parse_from_header(from_header)

            # Extract subject
            subject = headers.get('Subject', 'No Subject')

            # Parse date
            date_str = headers.get('Date', '')
            timestamp = self._parse_date(date_str)

            # Extract labels and flags
            label_ids = msg_data.get('labelIds', [])
            is_unread = 'UNREAD' in label_ids
            is_starred = 'STARRED' in label_ids

            return {
                'sender': sender_name,
                'sender_email': sender_email,
                'subject': subject,
                'timestamp': timestamp,
                'msg_id': msg_data['id'],
                'read': not is_unread,
                'flagged': is_starred,
                'labels': label_ids
            }

        except Exception as e:
            logger.error(f"✗ Failed to parse message: {e}")
            return None

    def _parse_from_header(self, from_header: str) -> tuple:
        """Parse From header into name and email"""
        if not from_header:
            return 'Unknown', ''

        # Handle "Name <email@example.com>" format
        if '<' in from_header and '>' in from_header:
            name_part = from_header.split('<')[0].strip()
            email_part = from_header.split('<')[1].split('>')[0].strip()

            # Clean up name
            name = name_part.replace('"', '').replace("'", "").strip()
            if not name:
                name = email_part

            return name, email_part
        else:
            # Just an email address
            email = from_header.strip()
            return email, email

    def _parse_date(self, date_str: str) -> str:
        """Parse email date into ISO format"""
        try:
            if date_str:
                timestamp = parsedate_to_datetime(date_str)
                return timestamp.isoformat()
            else:
                return datetime.now().isoformat()
        except Exception:
            return datetime.now().isoformat()


    async def get_user_email(
            self,
            oauth_token: str,
            request_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Fetch authenticated user's email address

        Args:
            oauth_token: OAuth2 access token
            request_id: Request ID for logging

        Returns:
            User's email address or None
        """
        req_prefix = f"[{request_id}]" if request_id else ""

        try:
            headers = {
                'Authorization': f'Bearer {oauth_token}',
                'Accept': 'application/json'
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                profile_url = f'{self.GMAIL_API_BASE}/users/me/profile'
                response = await client.get(profile_url, headers=headers)

                if response.status_code == 401:
                    raise GmailAuthError('OAuth token expired or invalid')

                response.raise_for_status()
                profile_data = response.json()

                return profile_data.get('emailAddress')

        except Exception as e:
            logger.warning(f"{req_prefix} Failed to fetch user email: {e}")
            return None