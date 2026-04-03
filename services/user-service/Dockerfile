# [VULN-01] Old base image — python:3.8 is EOL, multiple high/critical CVEs
FROM python:3.8

# [VULN-02] Running as root — if exploited, attacker has root in the container
WORKDIR /app

COPY requirements.txt .

# [VULN-03] pip install with no hash verification — supply chain risk
RUN pip install -r requirements.txt

COPY . .

# [VULN-04] No HEALTHCHECK
EXPOSE 5000

CMD ["python", "app.py"]
