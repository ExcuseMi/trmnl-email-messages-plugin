"""
Limit on failed logins: the backend must not be a free password tester against mail servers
"""
import hashlib
from typing import Optional

from modules.utils.store import MemoryStore

ACCOUNT_MAX_FAILURES = 5
ACCOUNT_WINDOW_SECONDS = 15 * 60
GLOBAL_MAX_FAILURES = 100
GLOBAL_WINDOW_SECONDS = 10 * 60
KNOWN_GOOD_SECONDS = 30 * 24 * 3600



class LoginLimiter:
    """
    An account is blocked after ACCOUNT_MAX_FAILURES failed logins in its window, and every
    unknown credential is blocked after GLOBAL_MAX_FAILURES failures across all accounts.
    The last credential that worked always passes, so nobody can lock a user out by guessing.
    """

    def __init__(self, store=None):
        self.store = store or MemoryStore()

    @staticmethod
    def account_key(server: str, username: str) -> str:
        return hashlib.sha256(f"{server.lower()}|{username.lower()}".encode()).hexdigest()

    def blocked(self, account: str, credential: str) -> Optional[str]:
        if self.store.get(f"login:good:{account}") == credential:
            return None
        if int(self.store.get(f"login:fail:{account}") or 0) >= ACCOUNT_MAX_FAILURES:
            return 'Too many failed logins for this account. Try again in 15 minutes.'
        if int(self.store.get('login:fail:all') or 0) >= GLOBAL_MAX_FAILURES:
            return 'Too many failed logins. Try again in a few minutes.'
        return None

    def failed(self, account: str):
        for key, window in ((f"login:fail:{account}", ACCOUNT_WINDOW_SECONDS),
                            ('login:fail:all', GLOBAL_WINDOW_SECONDS)):
            if self.store.incr(key) == 1:
                self.store.expire(key, window)

    def succeeded(self, account: str, credential: str):
        self.store.setex(f"login:good:{account}", KNOWN_GOOD_SECONDS, credential)
        self.store.delete(f"login:fail:{account}")
