# [VULN-01] Old base image — python:3.8 EOL
FROM python:3.8

# [VULN-02] Runs as root
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# [VULN-03] No HEALTHCHECK
EXPOSE 5001

CMD ["python", "app.py"]
