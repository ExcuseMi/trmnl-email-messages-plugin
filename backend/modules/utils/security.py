"""
Request safety checks: credential-bound cache keys, mail server address checks, client IP
"""
import hashlib
import ipaddress
import socket
from typing import Optional


def credential_hash(password: Optional[str], oauth_token: Optional[str]) -> str:
    """Hash of the credential, so a cache entry is only served to the credential that filled it"""
    secret = oauth_token or password or ''
    return hashlib.sha256(secret.encode()).hexdigest()


def check_mail_server(server: str, port) -> Optional[str]:
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
        infos = socket.getaddrinfo(server, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return 'Server not found'
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split('%')[0])
        if not address.is_global:
            return 'Server address not allowed'
    return None


def client_ip(headers, remote_addr: str) -> str:
    """Cloudflare's header is the only one a client cannot set through Cloudflare"""
    cf_ip = headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    return remote_addr
