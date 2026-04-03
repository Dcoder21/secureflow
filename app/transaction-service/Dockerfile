# VULNERABILITY: Using outdated base image with known CVEs
FROM python:3.9-slim

# VULNERABILITY: Running as root
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY . .

EXPOSE 5002

ENV FLASK_DEBUG=1

CMD ["python", "app/main.py"]
