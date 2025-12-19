#!/bin/bash
set -e

# Use environment variable or default to 4
WORKERS=${HYPERCORN_WORKERS:-4}

exec hypercorn app:app \
    --bind 0.0.0.0:5000 \
    --workers $WORKERS \
    --worker-class asyncio \
    --access-logfile - \
    --error-logfile -