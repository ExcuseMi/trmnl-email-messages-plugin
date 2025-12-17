FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Expose port
EXPOSE 5000

# CRITICAL: Set unbuffered output for Docker logs
ENV PYTHONUNBUFFERED=1

# Run with hypercorn
# IMPORTANT: Use "app:app" NOT "app:create_app()"
# The app.py file already creates the app instance at module level
CMD ["hypercorn", "app:app", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--worker-class", "asyncio", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info"]