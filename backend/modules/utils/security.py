"""
Request safety checks: credential-bound cache keys, mail server address checks, client IP
"""
import asyncio
import hashlib
import ipaddress
import socket
from typing import Optional

DNS_TIMEOUT_SECONDS = 5


def credential_hash(password: Optional[str]) -> str:
    """Hash of the password, so a cache entry is only served to the password that filled it"""
    secret = password or ''
    return hashlib.sha256(secret.encode()).hexdigest()


def is_public_address(address: str) -> bool:
    return ipaddress.ip_address(address.split('%')[0]).is_global


async def check_mail_server(server: str, port) -> Optional[str]:
    """Return an error message when the server must not be contacted, else None"""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 'Invalid port'
    if not 1 <= port <= 65535:
        return 'Invalid port'
    if not server or not isinstance(server, str):
        return 'Invalid server'
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(server, port, proto=socket.IPPROTO_TCP),
            timeout=DNS_TIMEOUT_SECONDS)
    except (socket.gaierror, UnicodeError, asyncio.TimeoutError):
        return 'Server not found'
    if not all(is_public_address(info[4][0]) for info in infos):
        return 'Server address not allowed'
    return None


def client_ip(headers, remote_addr: str) -> str:
    """Cloudflare's header is the only one a client cannot set through Cloudflare"""
    cf_ip = headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    return remote_addr
