FROM python:3.12-slim

WORKDIR /app

# Ensure non-root appuser and writable data directory for SQLite
RUN groupadd -r appuser && useradd -r -g appuser appuser && \
    mkdir -p /app/data && chown -R appuser:appuser /app

# Copy application files
COPY . /app

# Ensure proper permissions
RUN chown -R appuser:appuser /app

USER appuser

# Cloud Run defaults: injects PORT (default 8080)
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV DB_PATH=/app/data/secrets.db

EXPOSE 8080

CMD ["python3", "app.py"]
