FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and entrypoint
COPY app.py .
COPY entrypoint.sh .
COPY mock-data.json .
COPY modules/ ./modules/

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Expose port
EXPOSE 5000

# Set Python to unbuffered mode
ENV PYTHONUNBUFFERED=1

# Use entrypoint
ENTRYPOINT ["./entrypoint.sh"]
