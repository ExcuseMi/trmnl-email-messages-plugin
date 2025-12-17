FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Expose port
EXPOSE 5000

# Set Python to unbuffered mode for immediate log output
ENV PYTHONUNBUFFERED=1

# Run with hypercorn (ASGI server for async Flask)
# Single worker for easier debugging
# Don't set --log-level to preserve our logging format
CMD ["hypercorn", "app:app", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--worker-class", "asyncio", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]