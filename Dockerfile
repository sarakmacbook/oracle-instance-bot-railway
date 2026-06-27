FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Use Gunicorn to run the app on Railway's dynamically assigned PORT
CMD gunicorn --bind 0.0.0.0:$PORT app:app
