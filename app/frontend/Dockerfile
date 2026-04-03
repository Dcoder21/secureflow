FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_DEBUG=1

CMD ["python", "app/main.py"]
