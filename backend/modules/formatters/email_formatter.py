"""
Email message formatting utilities
Handles date/time formatting, grouping, and display options
"""
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class EmailFormatter:
    """Format email messages for display"""

    @staticmethod
    def format_messages(
            messages: List[Dict[str, Any]],
            group_by_date: bool = True,
            time_format: str = '24h',
            date_format: str = 'short',
            show_sender_email: bool = False,
            read_subject_regular: bool = True
    ) -> Dict[str, Any]:
        """
        Format messages with display options

        Args:
            messages: List of message dicts
            group_by_date: Group messages by date
            time_format: '24h' or '12h'
            date_format: 'short', 'medium', 'long', 'numeric', 'iso'
            show_sender_email: Show email address instead of name
            read_subject_regular: Display read emails with regular text weight

        Returns:
            Formatted messages structure
        """
        if not messages:
            return {
                'grouped': group_by_date,
                'messages': [],
                'groups': []
            }

        # Format each message
        formatted_messages = []
        for msg in messages:
            formatted_msg = EmailFormatter._format_single_message(
                msg,
                time_format,
                date_format,
                show_sender_email,
                read_subject_regular
            )
            formatted_messages.append(formatted_msg)

        if group_by_date:
            # Group messages by date
            groups = EmailFormatter._group_by_date(formatted_messages)
            return {
                'grouped': True,
                'groups': groups,
                'total_count': len(formatted_messages)
            }
        else:
            # Return flat list
            return {
                'grouped': False,
                'messages': formatted_messages,
                'total_count': len(formatted_messages)
            }

    @staticmethod
    def _format_single_message(
            msg: Dict[str, Any],
            time_format: str,
            date_format: str,
            show_sender_email: bool,
            read_subject_regular: bool
    ) -> Dict[str, Any]:
        """Format a single message"""
        timestamp = datetime.fromisoformat(msg['timestamp'])

        return {
            'id': msg['msg_id'],
            'sender': msg['sender_email'] if show_sender_email else msg['sender'],
            'sender_email': msg['sender_email'],
            'sender_name': msg['sender'],
            'subject': msg['subject'],
            'time': EmailFormatter._format_time(timestamp, time_format),
            'date': EmailFormatter._format_date(timestamp, date_format),
            'timestamp': msg['timestamp'],
            'timestamp_unix': int(timestamp.timestamp()),
            'read': msg['read'],
            'flagged': msg['flagged'],
            'bold': not msg['read'] if read_subject_regular else False,
            'labels': msg.get('labels', [])
        }

    @staticmethod
    def _group_by_date(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group messages by date"""
        groups = defaultdict(list)

        for msg in messages:
            timestamp = datetime.fromisoformat(msg['timestamp'])
            date_key = timestamp.date().isoformat()
            groups[date_key].append(msg)

        # Convert to list format with date labels
        result = []
        for date_key in sorted(groups.keys(), reverse=True):
            date_obj = datetime.fromisoformat(f"{date_key}T00:00:00")

            result.append({
                'date': date_key,
                'date_label': EmailFormatter._format_date_label(date_obj),
                'messages': groups[date_key]
            })

        return result

    @staticmethod
    def _format_time(dt: datetime, format_type: str) -> str:
        """Format time string"""
        if format_type == '12h':
            return dt.strftime('%-I:%M %p')  # 2:30 PM
        else:  # 24h
            return dt.strftime('%H:%M')  # 14:30

    @staticmethod
    def _format_date(dt: datetime, format_type: str) -> str:
        """Format date string"""
        if format_type == 'short':
            return dt.strftime('%b %d')  # Dec 18
        elif format_type == 'medium':
            return dt.strftime('%b %d, %Y')  # Dec 18, 2024
        elif format_type == 'long':
            return dt.strftime('%B %d, %Y')  # December 18, 2024
        elif format_type == 'numeric':
            return dt.strftime('%m/%d/%y')  # 12/18/24
        elif format_type == 'iso':
            return dt.strftime('%Y-%m-%d')  # 2024-12-18
        else:
            return dt.strftime('%b %d')  # Default to short

    @staticmethod
    def _format_date_label(dt: datetime) -> str:
        """Format date label for grouping (Today, Yesterday, etc.)"""
        now = datetime.now()
        today = now.date()
        msg_date = dt.date()

        days_diff = (today - msg_date).days

        if days_diff == 0:
            return 'Today'
        elif days_diff == 1:
            return 'Yesterday'
        elif days_diff < 7:
            return dt.strftime('%A')  # Monday, Tuesday, etc.
        else:
            return dt.strftime('%B %d, %Y')  # December 18, 2024