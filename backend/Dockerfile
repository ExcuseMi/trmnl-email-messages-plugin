FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Expose port
EXPOSE 5000

# Run with hypercorn (ASGI server for async Flask)
CMD ["hypercorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "asyncio", "app:create_app()"]