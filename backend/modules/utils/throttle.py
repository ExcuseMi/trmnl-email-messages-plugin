"""
One mail fetch per account per window: TRMNL keeps the previous screen in between
"""
from modules.utils.store import MemoryStore

WINDOW_SECONDS = 5 * 60


class Throttle:
    def __init__(self, store=None):
        self.store = store or MemoryStore()

    def acquire(self, account: str, credential: str) -> bool:
        """True when this account may fetch now; the window starts at once, so parallel requests wait too"""
        return bool(self.store.set(f"throttle:{account}:{credential}", '1', nx=True, ex=WINDOW_SECONDS))

    def release(self, account: str, credential: str):
        """A failed fetch may be retried at the next refresh"""
        self.store.delete(f"throttle:{account}:{credential}")
