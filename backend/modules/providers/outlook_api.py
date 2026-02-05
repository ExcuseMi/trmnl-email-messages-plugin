"""
Outlook/Microsoft Graph API Provider
Fetches emails using Microsoft Graph API with OAuth2 authentication
"""
import httpx
import asyncio
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class OutlookAPIError(Exception):
    """Outlook API error"""
    pass


class OutlookAuthError(Exception):
    """Outlook authentication error"""
    pass


class OutlookAPIProvider:
    """Microsoft Graph API email provider for Outlook/Office365"""

    GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0'
    DEFAULT_TIMEOUT = 30
    MAX_MESSAGES_PER_REQUEST = 50

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

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
                profile_url = f'{self.GRAPH_API_BASE}/me'
                response = await client.get(profile_url, headers=headers)

                if response.status_code == 401:
                    raise OutlookAuthError('OAuth token expired or invalid')

                response.raise_for_status()
                profile_data = response.json()

                # Try multiple fields for email
                email = (
                        profile_data.get('mail') or
                        profile_data.get('userPrincipalName') or
                        profile_data.get('mailboxSettings', {}).get('userPrincipalName')
                )

                return email

        except Exception as e:
            logger.warning(f"{req_prefix} Failed to fetch user email: {e}")
            return None

    async def fetch_messages(
            self,
            oauth_token: str,
            folder: str = 'inbox',
            limit: int = 10,
            unread_only: bool = False,
            flagged_only: bool = False,
            from_emails: Optional[List[str]] = None,
            request_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch messages from Microsoft Graph API

        Args:
            oauth_token: OAuth2 access token
            folder: Folder name (inbox, sentitems, drafts, deleteditems, junkemail)
            limit: Maximum number of messages
            unread_only: Only fetch unread messages
            flagged_only: Only fetch flagged messages
            from_emails: List of sender emails/domains to filter
            request_id: Request ID for logging

        Returns:
            List of message dictionaries
        """
        req_prefix = f"[{request_id}]" if request_id else ""

        try:
            start_time = datetime.now()

            # Build filter query
            filter_parts = []

            if unread_only:
                filter_parts.append('isRead eq false')

            if flagged_only:
                filter_parts.append('flag/flagStatus eq \'flagged\'')

            if from_emails:
                # Build sender filter
                from_filters = []
                for email in from_emails:
                    if email.startswith('@'):
                        # Domain filter
                        domain = email[1:]
                        from_filters.append(f'endswith(from/emailAddress/address,\'{domain}\')')
                    else:
                        # Exact or contains filter
                        from_filters.append(f'from/emailAddress/address eq \'{email}\'')

                if len(from_filters) == 1:
                    filter_parts.append(from_filters[0])
                else:
                    # Combine with OR
                    filter_parts.append(f"({' or '.join(from_filters)})")

            # Build request parameters
            params = {
                '$top': min(limit, self.MAX_MESSAGES_PER_REQUEST),
                '$orderby': 'receivedDateTime desc',
                '$select': 'id,subject,from,receivedDateTime,isRead,flag'
            }

            if filter_parts:
                params['$filter'] = ' and '.join(filter_parts)

            headers = {
                'Authorization': f'Bearer {oauth_token}',
                'Accept': 'application/json',
                'Prefer': 'outlook.body-content-type="text"'  # Get text content
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Normalize folder name
                folder = folder.lower()
                folder_map = {
                    'inbox': 'inbox',
                    'sent': 'sentitems',
                    'drafts': 'drafts',
                    'trash': 'deleteditems',
                    'deleted': 'deleteditems',
                    'junk': 'junkemail',
                    'spam': 'junkemail'
                }

                folder = folder_map.get(folder, folder)

                # Get messages
                messages_url = f'{self.GRAPH_API_BASE}/me/mailFolders/{folder}/messages'

                logger.debug(f"{req_prefix} Outlook API request: {params}")

                response = await client.get(messages_url, headers=headers, params=params)

                if response.status_code == 401:
                    raise OutlookAuthError('OAuth token expired or invalid')
                elif response.status_code == 403:
                    raise OutlookAPIError('Insufficient permissions - check OAuth scopes')
                elif response.status_code == 404:
                    raise OutlookAPIError(f'Folder not found: {folder}')

                response.raise_for_status()
                data = response.json()

                messages_data = data.get('value', [])

                if not messages_data:
                    logger.info(f"{req_prefix} ✓ No messages found")
                    return []

                # Parse messages
                messages = []
                for msg_data in messages_data:
                    message = self._parse_message(msg_data)
                    if message:
                        messages.append(message)

                elapsed = (datetime.now() - start_time).total_seconds()
                logger.info(f"{req_prefix} ✓ Fetched {len(messages)} messages in {elapsed:.2f}s")

                return messages

        except OutlookAuthError:
            raise
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise OutlookAuthError('OAuth token expired or invalid')
            elif e.response.status_code == 403:
                raise OutlookAPIError('Insufficient permissions')
            else:
                raise OutlookAPIError(f'Outlook API error: {e.response.status_code} - {e.response.text}')
        except httpx.TimeoutException:
            raise OutlookAPIError('Outlook API request timed out')
        except Exception as e:
            raise OutlookAPIError(f'Unexpected error: {str(e)}')

    def _parse_message(self, msg_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Microsoft Graph message into standardized format"""
        try:
            # Extract sender
            from_data = msg_data.get('from', {}).get('emailAddress', {})
            sender_name = from_data.get('name', 'Unknown')
            sender_email = from_data.get('address', '')

            # If no name, use email
            if not sender_name or sender_name == 'Unknown':
                sender_name = sender_email

            # Extract subject
            subject = msg_data.get('subject', 'No Subject')

            # Parse received date
            received_str = msg_data.get('receivedDateTime', '')
            try:
                if received_str:
                    # Microsoft Graph uses ISO 8601 format
                    timestamp = datetime.fromisoformat(received_str.replace('Z', '+00:00'))
                    timestamp_iso = timestamp.isoformat()
                else:
                    timestamp_iso = datetime.now().isoformat()
            except Exception:
                timestamp_iso = datetime.now().isoformat()

            # Extract read/flagged status
            is_read = msg_data.get('isRead', True)

            # Flag status
            flag_data = msg_data.get('flag', {})
            flag_status = flag_data.get('flagStatus', 'notFlagged')
            is_flagged = flag_status == 'flagged'

            return {
                'sender': sender_name,
                'sender_email': sender_email,
                'subject': subject,
                'timestamp': timestamp_iso,
                'msg_id': msg_data.get('id', ''),
                'read': is_read,
                'flagged': is_flagged
            }

        except Exception as e:
            logger.error(f"✗ Failed to parse message: {e}")
            return None