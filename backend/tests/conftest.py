import os
import sys

os.environ.setdefault('ENABLE_IP_WHITELIST', 'false')
os.environ.setdefault('USE_REDIS', 'false')
os.environ.setdefault('LOG_LEVEL', 'DEBUG')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
