FROM python:3.12-slim

WORKDIR /app

# Copy application files
COPY . /app

# Default environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=8000
ENV DB_PATH=/app/secrets.db

EXPOSE 8000

CMD ["python3", "app.py"]
