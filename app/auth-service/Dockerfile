# VULNERABILITY: Using outdated base image with known CVEs
FROM python:3.9-slim

# VULNERABILITY: Running as root (no USER directive)
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY . .

# VULNERABILITY: Exposing debug port
EXPOSE 5001

# VULNERABILITY: Running with debug mode via environment
ENV FLASK_DEBUG=1
ENV FLASK_ENV=development

CMD ["python", "app/main.py"]
